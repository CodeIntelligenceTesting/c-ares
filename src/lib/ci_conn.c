/* MIT License
 *
 * Copyright (c) Massachusetts Institute of Technology
 * Copyright (c) The c-ci project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ci_private.h"

void ci_conn_sock_state_cb_update(ci_conn_t            *conn,
                                    ci_conn_state_flags_t flags)
{
  ci_channel_t *channel = conn->server->channel;

  if ((conn->state_flags & CI_CONN_STATE_CBFLAGS) != flags &&
      channel->sock_state_cb) {
    channel->sock_state_cb(channel->sock_state_cb_data, conn->fd,
                           flags & CI_CONN_STATE_READ ? 1 : 0,
                           flags & CI_CONN_STATE_WRITE ? 1 : 0);
  }

  conn->state_flags &= ~((unsigned int)CI_CONN_STATE_CBFLAGS);
  conn->state_flags |= flags;
}

ci_conn_err_t ci_conn_read(ci_conn_t *conn, void *data, size_t len,
                               size_t *read_bytes)
{
  ci_channel_t *channel = conn->server->channel;
  ci_conn_err_t err;

  if (!(conn->flags & CI_CONN_FLAG_TCP)) {
    struct sockaddr_storage sa_storage;
    ci_socklen_t          salen = sizeof(sa_storage);

    memset(&sa_storage, 0, sizeof(sa_storage));

    err =
      ci_socket_recvfrom(channel, conn->fd, CI_FALSE, data, len, 0,
                           (struct sockaddr *)&sa_storage, &salen, read_bytes);

#ifdef HAVE_RECVFROM
    if (err == CI_CONN_ERR_SUCCESS &&
        !ci_sockaddr_addr_eq((struct sockaddr *)&sa_storage,
                               &conn->server->addr)) {
      err = CI_CONN_ERR_WOULDBLOCK;
    }
#endif
  } else {
    err = ci_socket_recv(channel, conn->fd, CI_TRUE, data, len, read_bytes);
  }

  /* Toggle connected state if needed */
  if (err == CI_CONN_ERR_SUCCESS) {
    conn->state_flags |= CI_CONN_STATE_CONNECTED;
  }

  return err;
}

/* Use like:
 *   struct sockaddr_storage sa_storage;
 *   ci_socklen_t          salen     = sizeof(sa_storage);
 *   struct sockaddr        *sa        = (struct sockaddr *)&sa_storage;
 *   ci_conn_set_sockaddr(conn, sa, &salen);
 */
static ci_status_t ci_conn_set_sockaddr(const ci_conn_t *conn,
                                            struct sockaddr   *sa,
                                            ci_socklen_t    *salen)
{
  const ci_server_t *server = conn->server;
  unsigned short       port =
    conn->flags & CI_CONN_FLAG_TCP ? server->tcp_port : server->udp_port;
  struct sockaddr_in  *sin;
  struct sockaddr_in6 *sin6;

  switch (server->addr.family) {
    case AF_INET:
      sin = (struct sockaddr_in *)(void *)sa;
      if (*salen < (ci_socklen_t)sizeof(*sin)) {
        return CI_EFORMERR;
      }
      *salen = sizeof(*sin);
      memset(sin, 0, sizeof(*sin));
      sin->sin_family = AF_INET;
      sin->sin_port   = htons(port);
      memcpy(&sin->sin_addr, &server->addr.addr.addr4, sizeof(sin->sin_addr));
      return CI_SUCCESS;
    case AF_INET6:
      sin6 = (struct sockaddr_in6 *)(void *)sa;
      if (*salen < (ci_socklen_t)sizeof(*sin6)) {
        return CI_EFORMERR;
      }
      *salen = sizeof(*sin6);
      memset(sin6, 0, sizeof(*sin6));
      sin6->sin6_family = AF_INET6;
      sin6->sin6_port   = htons(port);
      memcpy(&sin6->sin6_addr, &server->addr.addr.addr6,
             sizeof(sin6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
      sin6->sin6_scope_id = server->ll_scope;
#endif
      return CI_SUCCESS;
    default:
      break;
  }

  return CI_EBADFAMILY;
}

static ci_status_t ci_conn_set_self_ip(ci_conn_t *conn, ci_bool_t early)
{
  ci_channel_t         *channel = conn->server->channel;
  struct sockaddr_storage sa_storage;
  int                     rv;
  ci_socklen_t          len = sizeof(sa_storage);

  /* We call this twice on TFO, if we already have the IP we can go ahead and
   * skip processing */
  if (!early && conn->self_ip.family != AF_UNSPEC) {
    return CI_SUCCESS;
  }

  memset(&sa_storage, 0, sizeof(sa_storage));

  if (channel->sock_funcs.agetsockname == NULL) {
    /* Not specified, we can still use cookies cooked with an empty self_ip */
    memset(&conn->self_ip, 0, sizeof(conn->self_ip));
    return CI_SUCCESS;
  }
  rv = channel->sock_funcs.agetsockname(conn->fd,
                                        (struct sockaddr *)(void *)&sa_storage,
                                        &len, channel->sock_func_cb_data);
  if (rv != 0) {
    /* During TCP FastOpen, we can't get the IP this early since connect()
     * may not be called.  That's ok, we'll try again later */
    if (early && conn->flags & CI_CONN_FLAG_TCP &&
        conn->flags & CI_CONN_FLAG_TFO) {
      memset(&conn->self_ip, 0, sizeof(conn->self_ip));
      return CI_SUCCESS;
    }
    return CI_ECONNREFUSED;
  }

  if (!ci_sockaddr_to_ci_addr(&conn->self_ip, NULL,
                                  (struct sockaddr *)(void *)&sa_storage)) {
    return CI_ECONNREFUSED;
  }

  return CI_SUCCESS;
}

ci_conn_err_t ci_conn_write(ci_conn_t *conn, const void *data, size_t len,
                                size_t *written)
{
  ci_channel_t         *channel = conn->server->channel;
  ci_bool_t             is_tfo  = CI_FALSE;
  ci_conn_err_t         err     = CI_CONN_ERR_SUCCESS;
  struct sockaddr_storage sa_storage;
  ci_socklen_t          salen = 0;
  struct sockaddr        *sa    = NULL;

  *written = 0;

  /* Don't try to write if not doing initial TFO and not connected */
  if (conn->flags & CI_CONN_FLAG_TCP &&
      !(conn->state_flags & CI_CONN_STATE_CONNECTED) &&
      !(conn->flags & CI_CONN_FLAG_TFO_INITIAL)) {
    return CI_CONN_ERR_WOULDBLOCK;
  }

  /* On initial write during TFO we need to send an address */
  if (conn->flags & CI_CONN_FLAG_TFO_INITIAL) {
    salen = sizeof(sa_storage);
    sa    = (struct sockaddr *)&sa_storage;

    conn->flags &= ~((unsigned int)CI_CONN_FLAG_TFO_INITIAL);
    is_tfo       = CI_TRUE;

    if (ci_conn_set_sockaddr(conn, sa, &salen) != CI_SUCCESS) {
      return CI_CONN_ERR_FAILURE;
    }
  }

  err = ci_socket_write(channel, conn->fd, data, len, written, sa, salen);
  if (err != CI_CONN_ERR_SUCCESS) {
    goto done;
  }

  if (is_tfo) {
    /* If using TFO, we might not have been able to get an IP earlier, since
     * we hadn't informed the OS of the destination.  When using sendto()
     * now we have so we should be able to fetch it */
    ci_conn_set_self_ip(conn, CI_FALSE);
    goto done;
  }

done:
  if (err == CI_CONN_ERR_SUCCESS && len == *written) {
    /* Wrote all data, make sure we're not listening for write events unless
     * using TFO, in which case we'll need a write event to know when
     * we're connected. */
    ci_conn_sock_state_cb_update(
      conn, CI_CONN_STATE_READ |
              (is_tfo ? CI_CONN_STATE_WRITE : CI_CONN_STATE_NONE));
  } else if (err == CI_CONN_ERR_WOULDBLOCK) {
    /* Need to wait on more buffer space to write */
    ci_conn_sock_state_cb_update(conn, CI_CONN_STATE_READ |
                                           CI_CONN_STATE_WRITE);
  }

  return err;
}

ci_status_t ci_conn_flush(ci_conn_t *conn)
{
  const unsigned char *data;
  size_t               data_len;
  size_t               count;
  ci_conn_err_t      err;
  ci_status_t        status;
  ci_bool_t          tfo = CI_FALSE;

  if (conn == NULL) {
    return CI_EFORMERR;
  }

  if (conn->flags & CI_CONN_FLAG_TFO_INITIAL) {
    tfo = CI_TRUE;
  }

  do {
    if (ci_buf_len(conn->out_buf) == 0) {
      status = CI_SUCCESS;
      goto done;
    }

    if (conn->flags & CI_CONN_FLAG_TCP) {
      data = ci_buf_peek(conn->out_buf, &data_len);
    } else {
      unsigned short msg_len;

      /* Read length, then provide buffer without length */
      ci_buf_tag(conn->out_buf);
      status = ci_buf_fetch_be16(conn->out_buf, &msg_len);
      if (status != CI_SUCCESS) {
        return status;
      }
      ci_buf_tag_rollback(conn->out_buf);

      data = ci_buf_peek(conn->out_buf, &data_len);
      if (data_len < (size_t)(msg_len + 2)) {
        status = CI_EFORMERR;
        goto done;
      }
      data     += 2;
      data_len  = msg_len;
    }

    err = ci_conn_write(conn, data, data_len, &count);
    if (err != CI_CONN_ERR_SUCCESS) {
      if (err != CI_CONN_ERR_WOULDBLOCK) {
        status = CI_ECONNREFUSED;
        goto done;
      }
      status = CI_SUCCESS;
      goto done;
    }

    /* UDP didn't send the length prefix so augment that here */
    if (!(conn->flags & CI_CONN_FLAG_TCP)) {
      count += 2;
    }

    /* Strip data written from the buffer */
    ci_buf_consume(conn->out_buf, count);
    status = CI_SUCCESS;

    /* Loop only for UDP since we have to send per-packet.  We already
     * sent everything we could if using tcp */
  } while (!(conn->flags & CI_CONN_FLAG_TCP));

done:
  if (status == CI_SUCCESS) {
    ci_conn_state_flags_t flags = CI_CONN_STATE_READ;

    /* When using TFO, the we need to enabling waiting on a write event to
     * be notified of when a connection is actually established */
    if (tfo) {
      flags |= CI_CONN_STATE_WRITE;
    }

    /* If using TCP and not all data was written (partial write), that means
     * we need to also wait on a write event */
    if (conn->flags & CI_CONN_FLAG_TCP && ci_buf_len(conn->out_buf)) {
      flags |= CI_CONN_STATE_WRITE;
    }

    ci_conn_sock_state_cb_update(conn, flags);
  }

  return status;
}

static ci_status_t ci_conn_connect(ci_conn_t           *conn,
                                       const struct sockaddr *sa,
                                       ci_socklen_t         salen)
{
  ci_conn_err_t err;

  err = ci_socket_connect(
    conn->server->channel, conn->fd,
    (conn->flags & CI_CONN_FLAG_TFO) ? CI_TRUE : CI_FALSE, sa, salen);

  if (err != CI_CONN_ERR_WOULDBLOCK && err != CI_CONN_ERR_SUCCESS) {
    return CI_ECONNREFUSED;
  }
  return CI_SUCCESS;
}

ci_status_t ci_open_connection(ci_conn_t   **conn_out,
                                   ci_channel_t *channel,
                                   ci_server_t *server, ci_bool_t is_tcp)
{
  ci_status_t           status;
  struct sockaddr_storage sa_storage;
  ci_socklen_t          salen = sizeof(sa_storage);
  struct sockaddr        *sa    = (struct sockaddr *)&sa_storage;
  ci_conn_t            *conn;
  ci_llist_node_t      *node  = NULL;
  int                     stype = is_tcp ? SOCK_STREAM : SOCK_DGRAM;
  ci_conn_state_flags_t state_flags;

  *conn_out = NULL;

  conn = ci_malloc(sizeof(*conn));
  if (conn == NULL) {
    return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  memset(conn, 0, sizeof(*conn));
  conn->fd              = CI_SOCKET_BAD;
  conn->server          = server;
  conn->queries_to_conn = ci_llist_create(NULL);
  conn->flags           = is_tcp ? CI_CONN_FLAG_TCP : CI_CONN_FLAG_NONE;
  conn->out_buf         = ci_buf_create();
  conn->in_buf          = ci_buf_create();

  if (conn->queries_to_conn == NULL || conn->out_buf == NULL ||
      conn->in_buf == NULL) {
    /* LCOV_EXCL_START: OutOfMemory */
    status = CI_ENOMEM;
    goto done;
    /* LCOV_EXCL_STOP */
  }

  /* Try to enable TFO always if using TCP. it will fail later on if its
   * really not supported when we try to enable it on the socket. */
  if (conn->flags & CI_CONN_FLAG_TCP) {
    conn->flags |= CI_CONN_FLAG_TFO;
  }

  /* Convert into the struct sockaddr structure needed by the OS */
  status = ci_conn_set_sockaddr(conn, sa, &salen);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Acquire a socket. */
  if (ci_socket_open(&conn->fd, channel, server->addr.family, stype, 0) !=
      CI_CONN_ERR_SUCCESS) {
    status = CI_ECONNREFUSED;
    goto done;
  }

  /* Configure channel configured options */
  status = ci_socket_configure(
    channel, server->addr.family,
    (conn->flags & CI_CONN_FLAG_TCP) ? CI_TRUE : CI_FALSE, conn->fd);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Enable TFO if possible */
  if (conn->flags & CI_CONN_FLAG_TFO &&
      ci_socket_enable_tfo(channel, conn->fd) != CI_CONN_ERR_SUCCESS) {
    conn->flags &= ~((unsigned int)CI_CONN_FLAG_TFO);
  }

  if (channel->sock_config_cb) {
    int err =
      channel->sock_config_cb(conn->fd, stype, channel->sock_config_cb_data);
    if (err < 0) {
      status = CI_ECONNREFUSED;
      goto done;
    }
  }

  /* Connect */
  status = ci_conn_connect(conn, sa, salen);
  if (status != CI_SUCCESS) {
    goto done;
  }

  if (channel->sock_create_cb) {
    int err =
      channel->sock_create_cb(conn->fd, stype, channel->sock_create_cb_data);
    if (err < 0) {
      status = CI_ECONNREFUSED;
      goto done;
    }
  }

  /* Let the connection know we haven't written our first packet yet for TFO */
  if (conn->flags & CI_CONN_FLAG_TFO) {
    conn->flags |= CI_CONN_FLAG_TFO_INITIAL;
  }

  /* Need to store our own ip for DNS cookie support */
  status = ci_conn_set_self_ip(conn, CI_TRUE);
  if (status != CI_SUCCESS) {
    goto done; /* LCOV_EXCL_LINE: UntestablePath */
  }

  /* TCP connections are thrown to the end as we don't spawn multiple TCP
   * connections. UDP connections are put on front where the newest connection
   * can be quickly pulled */
  if (is_tcp) {
    node = ci_llist_insert_last(server->connections, conn);
  } else {
    node = ci_llist_insert_first(server->connections, conn);
  }
  if (node == NULL) {
    /* LCOV_EXCL_START: OutOfMemory */
    status = CI_ENOMEM;
    goto done;
    /* LCOV_EXCL_STOP */
  }

  /* Register globally to quickly map event on file descriptor to connection
   * node object */
  if (!ci_htable_asvp_insert(channel->connnode_by_socket, conn->fd, node)) {
    /* LCOV_EXCL_START: OutOfMemory */
    status = CI_ENOMEM;
    goto done;
    /* LCOV_EXCL_STOP */
  }

  state_flags = CI_CONN_STATE_READ;

  /* Get notified on connect if using TCP */
  if (conn->flags & CI_CONN_FLAG_TCP) {
    state_flags |= CI_CONN_STATE_WRITE;
  }

  /* Dot no attempt to update sock state callbacks on TFO until *after* the
   * initial write is performed.  Due to the notification event, its possible
   * an erroneous read can come in before the attempt to write the data which
   * might be used to set the ip address */
  if (!(conn->flags & CI_CONN_FLAG_TFO_INITIAL)) {
    ci_conn_sock_state_cb_update(conn, state_flags);
  }

  if (is_tcp) {
    server->tcp_conn = conn;
  }

done:
  if (status != CI_SUCCESS) {
    ci_llist_node_claim(node);
    ci_llist_destroy(conn->queries_to_conn);
    ci_socket_close(channel, conn->fd);
    ci_buf_destroy(conn->out_buf);
    ci_buf_destroy(conn->in_buf);
    ci_free(conn);
  } else {
    *conn_out = conn;
  }
  return status;
}

ci_conn_t *ci_conn_from_fd(const ci_channel_t *channel, ci_socket_t fd)
{
  ci_llist_node_t *node;

  node = ci_htable_asvp_get_direct(channel->connnode_by_socket, fd);
  if (node == NULL) {
    return NULL;
  }

  return ci_llist_node_val(node);
}
