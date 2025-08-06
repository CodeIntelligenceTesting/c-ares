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
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#  include <netinet/tcp.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef NETWARE
#  include <sys/filio.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <limits.h>

static ci_conn_err_t ci_socket_deref_error(int err)
{
  switch (err) {
#if defined(EWOULDBLOCK)
    case EWOULDBLOCK:
      return CI_CONN_ERR_WOULDBLOCK;
#endif
#if defined(EAGAIN) && (!defined(EWOULDBLOCK) || EAGAIN != EWOULDBLOCK)
    case EAGAIN:
      return CI_CONN_ERR_WOULDBLOCK;
#endif
    case EINPROGRESS:
      return CI_CONN_ERR_WOULDBLOCK;
    case ENETDOWN:
      return CI_CONN_ERR_NETDOWN;
    case ENETUNREACH:
      return CI_CONN_ERR_NETUNREACH;
    case ECONNABORTED:
      return CI_CONN_ERR_CONNABORTED;
    case ECONNRESET:
      return CI_CONN_ERR_CONNRESET;
    case ECONNREFUSED:
      return CI_CONN_ERR_CONNREFUSED;
    case ETIMEDOUT:
      return CI_CONN_ERR_CONNTIMEDOUT;
    case EHOSTDOWN:
      return CI_CONN_ERR_HOSTDOWN;
    case EHOSTUNREACH:
      return CI_CONN_ERR_HOSTUNREACH;
    case EINTR:
      return CI_CONN_ERR_INTERRUPT;
    case EAFNOSUPPORT:
      return CI_CONN_ERR_AFNOSUPPORT;
    case EADDRNOTAVAIL:
      return CI_CONN_ERR_BADADDR;
    default:
      break;
  }

  return CI_CONN_ERR_FAILURE;
}

ci_bool_t ci_sockaddr_addr_eq(const struct sockaddr  *sa,
                                  const struct ci_addr *aa)
{
  const void *addr1;
  const void *addr2;

  if (sa->sa_family == aa->family) {
    switch (aa->family) {
      case AF_INET:
        addr1 = &aa->addr.addr4;
        addr2 = &(CI_INADDR_CAST(const struct sockaddr_in *, sa))->sin_addr;
        if (memcmp(addr1, addr2, sizeof(aa->addr.addr4)) == 0) {
          return CI_TRUE; /* match */
        }
        break;
      case AF_INET6:
        addr1 = &aa->addr.addr6;
        addr2 =
          &(CI_INADDR_CAST(const struct sockaddr_in6 *, sa))->sin6_addr;
        if (memcmp(addr1, addr2, sizeof(aa->addr.addr6)) == 0) {
          return CI_TRUE; /* match */
        }
        break;
      default:
        break; /* LCOV_EXCL_LINE */
    }
  }
  return CI_FALSE; /* different */
}

ci_conn_err_t ci_socket_write(ci_channel_t *channel, ci_socket_t fd,
                                  const void *data, size_t len, size_t *written,
                                  const struct sockaddr *sa,
                                  ci_socklen_t         salen)
{
  int             flags = 0;
  ci_ssize_t    rv;
  ci_conn_err_t err = CI_CONN_ERR_SUCCESS;

#ifdef HAVE_MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif

  rv = channel->sock_funcs.asendto(fd, data, len, flags, sa, salen,
                                   channel->sock_func_cb_data);
  if (rv <= 0) {
    err = ci_socket_deref_error(SOCKERRNO);
  } else {
    *written = (size_t)rv;
  }
  return err;
}

ci_conn_err_t ci_socket_recv(ci_channel_t *channel, ci_socket_t s,
                                 ci_bool_t is_tcp, void *data,
                                 size_t data_len, size_t *read_bytes)
{
  ci_ssize_t rv;

  *read_bytes = 0;

  rv = channel->sock_funcs.arecvfrom(s, data, data_len, 0, NULL, 0,
                                     channel->sock_func_cb_data);

  if (rv > 0) {
    *read_bytes = (size_t)rv;
    return CI_CONN_ERR_SUCCESS;
  }

  if (rv == 0) {
    /* UDP allows 0-byte packets and is connectionless, so this is success */
    if (!is_tcp) {
      return CI_CONN_ERR_SUCCESS;
    } else {
      return CI_CONN_ERR_CONNCLOSED;
    }
  }

  /* If we're here, rv<0 */
  return ci_socket_deref_error(SOCKERRNO);
}

ci_conn_err_t ci_socket_recvfrom(ci_channel_t *channel, ci_socket_t s,
                                     ci_bool_t is_tcp, void *data,
                                     size_t data_len, int flags,
                                     struct sockaddr *from,
                                     ci_socklen_t  *from_len,
                                     size_t          *read_bytes)
{
  ci_ssize_t rv;

  rv = channel->sock_funcs.arecvfrom(s, data, data_len, flags, from, from_len,
                                     channel->sock_func_cb_data);

  if (rv > 0) {
    *read_bytes = (size_t)rv;
    return CI_CONN_ERR_SUCCESS;
  }

  if (rv == 0) {
    /* UDP allows 0-byte packets and is connectionless, so this is success */
    if (!is_tcp) {
      return CI_CONN_ERR_SUCCESS;
    } else {
      return CI_CONN_ERR_CONNCLOSED;
    }
  }

  /* If we're here, rv<0 */
  return ci_socket_deref_error(SOCKERRNO);
}

ci_conn_err_t ci_socket_enable_tfo(const ci_channel_t *channel,
                                       ci_socket_t         fd)
{
  ci_bool_t opt = CI_TRUE;

  if (channel->sock_funcs.asetsockopt(fd, CI_SOCKET_OPT_TCP_FASTOPEN,
                                      (void *)&opt, sizeof(opt),
                                      channel->sock_func_cb_data) != 0) {
    return CI_CONN_ERR_NOTIMP;
  }

  return CI_CONN_ERR_SUCCESS;
}

ci_status_t ci_socket_configure(ci_channel_t *channel, int family,
                                    ci_bool_t is_tcp, ci_socket_t fd)
{
  union {
    struct sockaddr     sa;
    struct sockaddr_in  sa4;
    struct sockaddr_in6 sa6;
  } local;

  ci_socklen_t bindlen = 0;
  int            rv;
  unsigned int   bind_flags = 0;

  /* Set the socket's send and receive buffer sizes. */
  if (channel->socket_send_buffer_size > 0) {
    rv = channel->sock_funcs.asetsockopt(
      fd, CI_SOCKET_OPT_SENDBUF_SIZE,
      (void *)&channel->socket_send_buffer_size,
      sizeof(channel->socket_send_buffer_size), channel->sock_func_cb_data);
    if (rv != 0 && SOCKERRNO != ENOSYS) {
      return CI_ECONNREFUSED; /* LCOV_EXCL_LINE: UntestablePath */
    }
  }

  if (channel->socket_receive_buffer_size > 0) {
    rv = channel->sock_funcs.asetsockopt(
      fd, CI_SOCKET_OPT_RECVBUF_SIZE,
      (void *)&channel->socket_receive_buffer_size,
      sizeof(channel->socket_receive_buffer_size), channel->sock_func_cb_data);
    if (rv != 0 && SOCKERRNO != ENOSYS) {
      return CI_ECONNREFUSED; /* LCOV_EXCL_LINE: UntestablePath */
    }
  }

  /* Bind to network interface if configured */
  if (ci_strlen(channel->local_dev_name)) {
    /* Prior versions silently ignored failure, so we need to maintain that
     * compatibility */
    (void)channel->sock_funcs.asetsockopt(
      fd, CI_SOCKET_OPT_BIND_DEVICE, channel->local_dev_name,
      sizeof(channel->local_dev_name), channel->sock_func_cb_data);
  }

  /* Bind to ip address if configured */
  if (family == AF_INET && channel->local_ip4) {
    memset(&local.sa4, 0, sizeof(local.sa4));
    local.sa4.sin_family      = AF_INET;
    local.sa4.sin_addr.s_addr = htonl(channel->local_ip4);
    bindlen                   = sizeof(local.sa4);
  } else if (family == AF_INET6 &&
             memcmp(channel->local_ip6, ci_in6addr_any._S6_un._S6_u8,
                    sizeof(channel->local_ip6)) != 0) {
    /* Only if not link-local and an ip other than "::" is specified */
    memset(&local.sa6, 0, sizeof(local.sa6));
    local.sa6.sin6_family = AF_INET6;
    memcpy(&local.sa6.sin6_addr, channel->local_ip6,
           sizeof(channel->local_ip6));
    bindlen = sizeof(local.sa6);
  }


  if (bindlen && channel->sock_funcs.abind != NULL) {
    bind_flags |= CI_SOCKET_BIND_CLIENT;
    if (is_tcp) {
      bind_flags |= CI_SOCKET_BIND_TCP;
    }
    if (channel->sock_funcs.abind(fd, bind_flags, &local.sa, bindlen,
                                  channel->sock_func_cb_data) != 0) {
      return CI_ECONNREFUSED;
    }
  }

  return CI_SUCCESS;
}

ci_bool_t ci_sockaddr_to_ci_addr(struct ci_addr      *ci_addr,
                                       unsigned short        *port,
                                       const struct sockaddr *sockaddr)
{
  if (sockaddr->sa_family == AF_INET) {
    /* NOTE: memcpy sockaddr_in due to alignment issues found by UBSAN due to
     *       dnsinfo packing on MacOS */
    struct sockaddr_in sockaddr_in;
    memcpy(&sockaddr_in, sockaddr, sizeof(sockaddr_in));

    ci_addr->family = AF_INET;
    memcpy(&ci_addr->addr.addr4, &(sockaddr_in.sin_addr),
           sizeof(ci_addr->addr.addr4));

    if (port) {
      *port = ntohs(sockaddr_in.sin_port);
    }
    return CI_TRUE;
  }

  if (sockaddr->sa_family == AF_INET6) {
    /* NOTE: memcpy sockaddr_in6 due to alignment issues found by UBSAN due to
     *       dnsinfo packing on MacOS */
    struct sockaddr_in6 sockaddr_in6;
    memcpy(&sockaddr_in6, sockaddr, sizeof(sockaddr_in6));

    ci_addr->family = AF_INET6;
    memcpy(&ci_addr->addr.addr6, &(sockaddr_in6.sin6_addr),
           sizeof(ci_addr->addr.addr6));
    if (port) {
      *port = ntohs(sockaddr_in6.sin6_port);
    }
    return CI_TRUE;
  }

  return CI_FALSE;
}

ci_conn_err_t ci_socket_open(ci_socket_t *sock, ci_channel_t *channel,
                                 int af, int type, int protocol)
{
  ci_socket_t s;

  *sock = CI_SOCKET_BAD;

  s =
    channel->sock_funcs.asocket(af, type, protocol, channel->sock_func_cb_data);

  if (s == CI_SOCKET_BAD) {
    return ci_socket_deref_error(SOCKERRNO);
  }

  *sock = s;

  return CI_CONN_ERR_SUCCESS;
}

ci_conn_err_t ci_socket_connect(ci_channel_t *channel,
                                    ci_socket_t sockfd, ci_bool_t is_tfo,
                                    const struct sockaddr *addr,
                                    ci_socklen_t         addrlen)
{
  ci_conn_err_t err   = CI_CONN_ERR_SUCCESS;
  unsigned int    flags = 0;

  if (is_tfo) {
    flags |= CI_SOCKET_CONN_TCP_FASTOPEN;
  }

  do {
    int rv;

    rv = channel->sock_funcs.aconnect(sockfd, addr, addrlen, flags,
                                      channel->sock_func_cb_data);

    if (rv < 0) {
      err = ci_socket_deref_error(SOCKERRNO);
    } else {
      err = CI_CONN_ERR_SUCCESS;
    }
  } while (err == CI_CONN_ERR_INTERRUPT);

  return err;
}

void ci_socket_close(ci_channel_t *channel, ci_socket_t s)
{
  if (channel == NULL || s == CI_SOCKET_BAD) {
    return;
  }

  channel->sock_funcs.aclose(s, channel->sock_func_cb_data);
}

void ci_set_socket_callback(ci_channel_t           *channel,
                              ci_sock_create_callback cb, void *data)
{
  if (channel == NULL) {
    return;
  }
  channel->sock_create_cb      = cb;
  channel->sock_create_cb_data = data;
}

void ci_set_socket_configure_callback(ci_channel_t           *channel,
                                        ci_sock_config_callback cb,
                                        void                     *data)
{
  if (channel == NULL || channel->optmask & CI_OPT_EVENT_THREAD) {
    return;
  }
  channel->sock_config_cb      = cb;
  channel->sock_config_cb_data = data;
}

void ci_set_pending_write_cb(ci_channel_t       *channel,
                               ci_pending_write_cb callback, void *user_data)
{
  if (channel == NULL || channel->optmask & CI_OPT_EVENT_THREAD) {
    return;
  }
  channel->notify_pending_write_cb      = callback;
  channel->notify_pending_write_cb_data = user_data;
}
