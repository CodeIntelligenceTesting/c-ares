/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2010 Daniel Stenberg
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

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef NETWARE
#  include <sys/filio.h>
#endif
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <limits.h>


static void          timeadd(ci_timeval_t *now, size_t millisecs);
static ci_status_t process_write(ci_channel_t *channel,
                                   ci_socket_t   write_fd);
static ci_status_t process_read(ci_channel_t       *channel,
                                  ci_socket_t         read_fd,
                                  const ci_timeval_t *now);
static ci_status_t process_timeouts(ci_channel_t       *channel,
                                      const ci_timeval_t *now);
static ci_status_t process_answer(ci_channel_t      *channel,
                                    const unsigned char *abuf, size_t alen,
                                    ci_conn_t          *conn,
                                    const ci_timeval_t *now);
static void handle_conn_error(ci_conn_t *conn, ci_bool_t critical_failure,
                              ci_status_t failure_status);
static ci_bool_t same_questions(const ci_query_t      *query,
                                  const ci_dns_record_t *arec);
static void        end_query(ci_channel_t *channel, ci_server_t *server,
                             ci_query_t *query, ci_status_t status,
                             const ci_dns_record_t *dnsrec);

static void        ci_query_remove_from_conn(ci_query_t *query)
{
  /* If its not part of a connection, it can't be tracked for timeouts either */
  ci_slist_node_destroy(query->node_queries_by_timeout);
  ci_llist_node_destroy(query->node_queries_to_conn);
  query->node_queries_by_timeout = NULL;
  query->node_queries_to_conn    = NULL;
  query->conn                    = NULL;
}

/* Invoke the server state callback after a success or failure */
static void invoke_server_state_cb(const ci_server_t *server,
                                   ci_bool_t success, int flags)
{
  const ci_channel_t *channel = server->channel;
  ci_buf_t           *buf;
  ci_status_t         status;
  char                 *server_string;

  if (channel->server_state_cb == NULL) {
    return;
  }

  buf = ci_buf_create();
  if (buf == NULL) {
    return; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  status = ci_get_server_addr(server, buf);
  if (status != CI_SUCCESS) {
    ci_buf_destroy(buf); /* LCOV_EXCL_LINE: OutOfMemory */
    return;                /* LCOV_EXCL_LINE: OutOfMemory */
  }

  server_string = ci_buf_finish_str(buf, NULL);
  buf           = NULL;
  if (server_string == NULL) {
    return; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  channel->server_state_cb(server_string, success, flags,
                           channel->server_state_cb_data);
  ci_free(server_string);
}

static void server_increment_failures(ci_server_t *server,
                                      ci_bool_t    used_tcp)
{
  ci_slist_node_t    *node;
  const ci_channel_t *channel = server->channel;
  ci_timeval_t        next_retry_time;

  node = ci_slist_node_find(channel->servers, server);
  if (node == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  server->consec_failures++;
  ci_slist_node_reinsert(node);

  ci_tvnow(&next_retry_time);
  timeadd(&next_retry_time, channel->server_retry_delay);
  server->next_retry_time = next_retry_time;

  invoke_server_state_cb(server, CI_FALSE,
                         used_tcp == CI_TRUE ? CI_SERV_STATE_TCP
                                               : CI_SERV_STATE_UDP);
}

static void server_set_good(ci_server_t *server, ci_bool_t used_tcp)
{
  ci_slist_node_t    *node;
  const ci_channel_t *channel = server->channel;

  node = ci_slist_node_find(channel->servers, server);
  if (node == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (server->consec_failures > 0) {
    server->consec_failures = 0;
    ci_slist_node_reinsert(node);
  }

  server->next_retry_time.sec  = 0;
  server->next_retry_time.usec = 0;

  invoke_server_state_cb(server, CI_TRUE,
                         used_tcp == CI_TRUE ? CI_SERV_STATE_TCP
                                               : CI_SERV_STATE_UDP);
}

/* return true if now is exactly check time or later */
ci_bool_t ci_timedout(const ci_timeval_t *now,
                          const ci_timeval_t *check)
{
  ci_int64_t secs = (now->sec - check->sec);

  if (secs > 0) {
    return CI_TRUE; /* yes, timed out */
  }
  if (secs < 0) {
    return CI_FALSE; /* nope, not timed out */
  }

  /* if the full seconds were identical, check the sub second parts */
  return ((ci_int64_t)now->usec - (ci_int64_t)check->usec) >= 0
           ? CI_TRUE
           : CI_FALSE;
}

/* add the specific number of milliseconds to the time in the first argument */
static void timeadd(ci_timeval_t *now, size_t millisecs)
{
  now->sec  += (ci_int64_t)millisecs / 1000;
  now->usec += (unsigned int)((millisecs % 1000) * 1000);

  if (now->usec >= 1000000) {
    now->sec  += now->usec / 1000000;
    now->usec %= 1000000;
  }
}

static ci_status_t ci_process_fds_nolock(ci_channel_t         *channel,
                                             const ci_fd_events_t *events,
                                             size_t nevents, unsigned int flags)
{
  ci_timeval_t now;
  size_t         i;
  ci_status_t  status = CI_SUCCESS;

  if (channel == NULL || (events == NULL && nevents != 0)) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ci_tvnow(&now);

  /* Process write events */
  for (i = 0; i < nevents; i++) {
    if (events[i].fd == CI_SOCKET_BAD ||
        !(events[i].events & CI_FD_EVENT_WRITE)) {
      continue;
    }
    status = process_write(channel, events[i].fd);
    /* We only care about ENOMEM, anything else is handled via connection
     * retries, etc */
    if (status == CI_ENOMEM) {
      goto done;
    }
  }

  /* Process read events */
  for (i = 0; i < nevents; i++) {
    if (events[i].fd == CI_SOCKET_BAD ||
        !(events[i].events & CI_FD_EVENT_READ)) {
      continue;
    }
    status = process_read(channel, events[i].fd, &now);
    if (status == CI_ENOMEM) {
      goto done;
    }
  }

  if (!(flags & CI_PROCESS_FLAG_SKIP_NON_FD)) {
    ci_check_cleanup_conns(channel);
    status = process_timeouts(channel, &now);
    if (status == CI_ENOMEM) {
      goto done;
    }
  }

done:
  if (status == CI_ENOMEM) {
    return CI_ENOMEM;
  }
  return CI_SUCCESS;
}

ci_status_t ci_process_fds(ci_channel_t         *channel,
                               const ci_fd_events_t *events, size_t nevents,
                               unsigned int flags)
{
  ci_status_t status;

  if (channel == NULL) {
    return CI_EFORMERR;
  }

  ci_channel_lock(channel);
  status = ci_process_fds_nolock(channel, events, nevents, flags);
  ci_channel_unlock(channel);
  return status;
}

void ci_process_fd(ci_channel_t *channel, ci_socket_t read_fd,
                     ci_socket_t write_fd)
{
  ci_fd_events_t events[2];
  size_t           nevents = 0;

  memset(events, 0, sizeof(events));

  if (read_fd != CI_SOCKET_BAD) {
    nevents++;
    events[nevents - 1].fd      = read_fd;
    events[nevents - 1].events |= CI_FD_EVENT_READ;
  }

  if (write_fd != CI_SOCKET_BAD) {
    if (write_fd != read_fd) {
      nevents++;
    }
    events[nevents - 1].fd      = write_fd;
    events[nevents - 1].events |= CI_FD_EVENT_WRITE;
  }

  ci_process_fds(channel, events, nevents, CI_PROCESS_FLAG_NONE);
}

static ci_socket_t *channel_socket_list(const ci_channel_t *channel,
                                          size_t               *num)
{
  ci_slist_node_t *snode;
  ci_array_t      *arr = ci_array_create(sizeof(ci_socket_t), NULL);

  *num = 0;

  if (arr == NULL) {
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  for (snode = ci_slist_node_first(channel->servers); snode != NULL;
       snode = ci_slist_node_next(snode)) {
    ci_server_t     *server = ci_slist_node_val(snode);
    ci_llist_node_t *node;

    for (node = ci_llist_node_first(server->connections); node != NULL;
         node = ci_llist_node_next(node)) {
      const ci_conn_t *conn = ci_llist_node_val(node);
      ci_socket_t     *sptr;
      ci_status_t      status;

      if (conn->fd == CI_SOCKET_BAD) {
        continue;
      }

      status = ci_array_insert_last((void **)&sptr, arr);
      if (status != CI_SUCCESS) {
        ci_array_destroy(arr); /* LCOV_EXCL_LINE: OutOfMemory */
        return NULL;             /* LCOV_EXCL_LINE: OutOfMemory */
      }
      *sptr = conn->fd;
    }
  }

  return ci_array_finish(arr, num);
}

/* Something interesting happened on the wire, or there was a timeout.
 * See what's up and respond accordingly.
 */
void ci_process(ci_channel_t *channel, fd_set *read_fds, fd_set *write_fds)
{
  size_t            i;
  size_t            num_sockets;
  ci_socket_t    *socketlist;
  ci_fd_events_t *events  = NULL;
  size_t            nevents = 0;

  if (channel == NULL) {
    return;
  }

  ci_channel_lock(channel);

  /* There is no good way to iterate across an fd_set, instead we must pull a
   * list of all known fds, and iterate across that checking against the fd_set.
   */
  socketlist = channel_socket_list(channel, &num_sockets);

  /* Lets create an events array, maximum number is the number of sockets in
   * the list, so we'll use that and just track entries with nevents */
  if (num_sockets) {
    events = ci_malloc_zero(sizeof(*events) * num_sockets);
    if (events == NULL) {
      goto done;
    }
  }

  for (i = 0; i < num_sockets; i++) {
    ci_bool_t had_read = CI_FALSE;
    if (read_fds && FD_ISSET(socketlist[i], read_fds)) {
      nevents++;
      events[nevents - 1].fd      = socketlist[i];
      events[nevents - 1].events |= CI_FD_EVENT_READ;
      had_read                    = CI_TRUE;
    }
    if (write_fds && FD_ISSET(socketlist[i], write_fds)) {
      if (!had_read) {
        nevents++;
      }
      events[nevents - 1].fd      = socketlist[i];
      events[nevents - 1].events |= CI_FD_EVENT_WRITE;
    }
  }

done:
  ci_process_fds_nolock(channel, events, nevents, CI_PROCESS_FLAG_NONE);
  ci_free(events);
  ci_free(socketlist);
  ci_channel_unlock(channel);
}

static ci_status_t process_write(ci_channel_t *channel,
                                   ci_socket_t   write_fd)
{
  ci_conn_t  *conn = ci_conn_from_fd(channel, write_fd);
  ci_status_t status;

  if (conn == NULL) {
    return CI_SUCCESS;
  }

  /* Mark as connected if we got here and TFO Initial not set */
  if (!(conn->flags & CI_CONN_FLAG_TFO_INITIAL)) {
    conn->state_flags |= CI_CONN_STATE_CONNECTED;
  }

  status = ci_conn_flush(conn);
  if (status != CI_SUCCESS) {
    handle_conn_error(conn, CI_TRUE, status);
  }
  return status;
}

void ci_process_pending_write(ci_channel_t *channel)
{
  ci_slist_node_t *node;

  if (channel == NULL) {
    return;
  }

  ci_channel_lock(channel);
  if (!channel->notify_pending_write) {
    ci_channel_unlock(channel);
    return;
  }

  /* Set as untriggerd before calling into ci_conn_flush(), this is
   * because its possible ci_conn_flush() might cause additional data to
   * be enqueued if there is some form of exception so it will need to recurse.
   */
  channel->notify_pending_write = CI_FALSE;

  for (node = ci_slist_node_first(channel->servers); node != NULL;
       node = ci_slist_node_next(node)) {
    ci_server_t *server = ci_slist_node_val(node);
    ci_conn_t   *conn   = server->tcp_conn;
    ci_status_t  status;

    if (conn == NULL) {
      continue;
    }

    /* Enqueue any pending data if there is any */
    status = ci_conn_flush(conn);
    if (status != CI_SUCCESS) {
      handle_conn_error(conn, CI_TRUE, status);
    }
  }

  ci_channel_unlock(channel);
}

static ci_status_t read_conn_packets(ci_conn_t *conn)
{
  ci_bool_t           read_again;
  ci_conn_err_t       err;
  const ci_channel_t *channel = conn->server->channel;

  do {
    size_t         count;
    size_t         len = 65535;
    unsigned char *ptr;
    size_t         start_len = ci_buf_len(conn->in_buf);

    /* If UDP, lets write out a placeholder for the length indicator */
    if (!(conn->flags & CI_CONN_FLAG_TCP) &&
        ci_buf_append_be16(conn->in_buf, 0) != CI_SUCCESS) {
      handle_conn_error(conn, CI_FALSE /* not critical to connection */,
                        CI_SUCCESS);
      return CI_ENOMEM;
    }

    /* Get a buffer of sufficient size */
    ptr = ci_buf_append_start(conn->in_buf, &len);

    if (ptr == NULL) {
      handle_conn_error(conn, CI_FALSE /* not critical to connection */,
                        CI_SUCCESS);
      return CI_ENOMEM;
    }

    /* Read from socket */
    err = ci_conn_read(conn, ptr, len, &count);

    if (err != CI_CONN_ERR_SUCCESS) {
      ci_buf_append_finish(conn->in_buf, 0);
      if (!(conn->flags & CI_CONN_FLAG_TCP)) {
        ci_buf_set_length(conn->in_buf, start_len);
      }
      break;
    }

    /* Record amount of data read */
    ci_buf_append_finish(conn->in_buf, count);

    /* Only loop if sockets support non-blocking operation, and are using UDP
     * or are using TCP and read the maximum buffer size */
    read_again = CI_FALSE;
    if (channel->sock_funcs.flags & CI_SOCKFUNC_FLAG_NONBLOCKING &&
        (!(conn->flags & CI_CONN_FLAG_TCP) || count == len)) {
      read_again = CI_TRUE;
    }

    /* If UDP, overwrite length */
    if (!(conn->flags & CI_CONN_FLAG_TCP)) {
      len = ci_buf_len(conn->in_buf);
      ci_buf_set_length(conn->in_buf, start_len);
      ci_buf_append_be16(conn->in_buf, (unsigned short)count);
      ci_buf_set_length(conn->in_buf, len);
    }
    /* Try to read again only if *we* set up the socket, otherwise it may be
     * a blocking socket and would cause recvfrom to hang. */
  } while (read_again);

  if (err != CI_CONN_ERR_SUCCESS && err != CI_CONN_ERR_WOULDBLOCK) {
    handle_conn_error(conn, CI_TRUE, CI_ECONNREFUSED);
    return CI_ECONNREFUSED;
  }

  return CI_SUCCESS;
}

static ci_status_t read_answers(ci_conn_t *conn, const ci_timeval_t *now)
{
  ci_status_t   status;
  ci_channel_t *channel = conn->server->channel;

  /* Process all queued answers */
  while (1) {
    unsigned short       dns_len  = 0;
    const unsigned char *data     = NULL;
    size_t               data_len = 0;

    /* Tag so we can roll back */
    ci_buf_tag(conn->in_buf);

    /* Read length indicator */
    status = ci_buf_fetch_be16(conn->in_buf, &dns_len);
    if (status != CI_SUCCESS) {
      ci_buf_tag_rollback(conn->in_buf);
      break;
    }

    /* Not enough data for a full response yet */
    status = ci_buf_consume(conn->in_buf, dns_len);
    if (status != CI_SUCCESS) {
      ci_buf_tag_rollback(conn->in_buf);
      break;
    }

    /* Can't fail except for misuse */
    data = ci_buf_tag_fetch(conn->in_buf, &data_len);
    if (data == NULL || data_len < 2) {
      ci_buf_tag_clear(conn->in_buf);
      break;
    }

    /* Strip off 2 bytes length */
    data     += 2;
    data_len -= 2;

    /* We finished reading this answer; process it */
    status = process_answer(channel, data, data_len, conn, now);
    if (status != CI_SUCCESS) {
      handle_conn_error(conn, CI_TRUE, status);
      return status;
    }

    /* Since we processed the answer, clear the tag so space can be reclaimed */
    ci_buf_tag_clear(conn->in_buf);
  }
  return status;
}

static ci_status_t process_read(ci_channel_t       *channel,
                                  ci_socket_t         read_fd,
                                  const ci_timeval_t *now)
{
  ci_conn_t  *conn = ci_conn_from_fd(channel, read_fd);
  ci_status_t status;

  if (conn == NULL) {
    return CI_SUCCESS;
  }

  /* TODO: There might be a potential issue here where there was a read that
   *       read some data, then looped and read again and got a disconnect.
   *       Right now, that would cause a resend instead of processing the data
   *       we have.  This is fairly unlikely to occur due to only looping if
   *       a full buffer of 65535 bytes was read. */
  status = read_conn_packets(conn);

  if (status != CI_SUCCESS) {
    return status;
  }

  return read_answers(conn, now);
}

/* If any queries have timed out, note the timeout and move them on. */
static ci_status_t process_timeouts(ci_channel_t       *channel,
                                      const ci_timeval_t *now)
{
  ci_slist_node_t *node;
  ci_status_t      status = CI_SUCCESS;

  /* Just keep popping off the first as this list will re-sort as things come
   * and go.  We don't want to try to rely on 'next' as some operation might
   * cause a cleanup of that pointer and would become invalid */
  while ((node = ci_slist_node_first(channel->queries_by_timeout)) != NULL) {
    ci_query_t *query = ci_slist_node_val(node);
    ci_conn_t  *conn;

    /* Since this is sorted, as soon as we hit a query that isn't timed out,
     * break */
    if (!ci_timedout(now, &query->timeout)) {
      break;
    }

    query->timeouts++;

    conn = query->conn;
    server_increment_failures(conn->server, query->using_tcp);
    status = ci_requeue_query(query, now, CI_ETIMEOUT, CI_TRUE, NULL);
    if (status == CI_ENOMEM) {
      goto done;
    }
  }
done:
  if (status == CI_ENOMEM) {
    return CI_ENOMEM;
  }
  return CI_SUCCESS;
}

static ci_status_t rewrite_without_edns(ci_query_t *query)
{
  ci_status_t status = CI_SUCCESS;
  size_t        i;
  ci_bool_t   found_opt_rr = CI_FALSE;

  /* Find and remove the OPT RR record */
  for (i = 0; i < ci_dns_record_rr_cnt(query->query, CI_SECTION_ADDITIONAL);
       i++) {
    const ci_dns_rr_t *rr;
    rr = ci_dns_record_rr_get(query->query, CI_SECTION_ADDITIONAL, i);
    if (ci_dns_rr_get_type(rr) == CI_REC_TYPE_OPT) {
      ci_dns_record_rr_del(query->query, CI_SECTION_ADDITIONAL, i);
      found_opt_rr = CI_TRUE;
      break;
    }
  }

  if (!found_opt_rr) {
    status = CI_EFORMERR;
    goto done;
  }

done:
  return status;
}

/* Handle an answer from a server. This must NEVER cleanup the
 * server connection! Return something other than CI_SUCCESS to cause
 * the connection to be terminated after this call. */
static ci_status_t process_answer(ci_channel_t      *channel,
                                    const unsigned char *abuf, size_t alen,
                                    ci_conn_t          *conn,
                                    const ci_timeval_t *now)
{
  ci_query_t      *query;
  /* Cache these as once ci_send_query() gets called, it may end up
   * invalidating the connection all-together */
  ci_server_t     *server  = conn->server;
  ci_dns_record_t *rdnsrec = NULL;
  ci_status_t      status;
  ci_bool_t        is_cached = CI_FALSE;

  /* UDP can have 0-byte messages, drop them to the ground */
  if (alen == 0) {
    return CI_SUCCESS;
  }

  /* Parse the response */
  status = ci_dns_parse(abuf, alen, 0, &rdnsrec);
  if (status != CI_SUCCESS) {
    /* Malformations are never accepted */
    status = CI_EBADRESP;
    goto cleanup;
  }

  /* Find the query corresponding to this packet. The queries are
   * hashed/bucketed by query id, so this lookup should be quick.
   */
  query = ci_htable_szvp_get_direct(channel->queries_by_qid,
                                      ci_dns_record_get_id(rdnsrec));
  if (!query) {
    /* We may have stopped listening for this query, that's ok */
    status = CI_SUCCESS;
    goto cleanup;
  }

  /* Both the query id and the questions must be the same. We will drop any
   * replies that aren't for the same query as this is considered invalid. */
  if (!same_questions(query, rdnsrec)) {
    /* Possible qid conflict due to delayed response, that's ok */
    status = CI_SUCCESS;
    goto cleanup;
  }

  /* Validate DNS cookie in response. This function may need to requeue the
   * query. */
  if (ci_cookie_validate(query, rdnsrec, conn, now) != CI_SUCCESS) {
    /* Drop response and return */
    status = CI_SUCCESS;
    goto cleanup;
  }

  /* At this point we know we've received an answer for this query, so we should
   * remove it from the connection's queue so we can possibly invalidate the
   * connection. Delay cleaning up the connection though as we may enqueue
   * something new.  */
  ci_llist_node_destroy(query->node_queries_to_conn);
  query->node_queries_to_conn = NULL;

  /* If we use EDNS and server answers with FORMERR without an OPT RR, the
   * protocol extension is not understood by the responder. We must retry the
   * query without EDNS enabled. */
  if (ci_dns_record_get_rcode(rdnsrec) == CI_RCODE_FORMERR &&
      ci_dns_get_opt_rr_const(query->query) != NULL &&
      ci_dns_get_opt_rr_const(rdnsrec) == NULL) {
    status = rewrite_without_edns(query);
    if (status != CI_SUCCESS) {
      end_query(channel, server, query, status, NULL);
      goto cleanup;
    }

    /* Send to same server */
    ci_send_query(server, query, now);
    status = CI_SUCCESS;
    goto cleanup;
  }

  /* If we got a truncated UDP packet and are not ignoring truncation,
   * don't accept the packet, and switch the query to TCP if we hadn't
   * done so already.
   */
  if (ci_dns_record_get_flags(rdnsrec) & CI_FLAG_TC &&
      !(conn->flags & CI_CONN_FLAG_TCP) &&
      !(channel->flags & CI_FLAG_IGNTC)) {
    query->using_tcp = CI_TRUE;
    ci_send_query(NULL, query, now);
    status = CI_SUCCESS; /* Switched to TCP is ok */
    goto cleanup;
  }

  /* If we aren't passing through all error packets, discard packets
   * with SERVFAIL, NOTIMP, or REFUSED response codes.
   */
  if (!(channel->flags & CI_FLAG_NOCHECKRESP)) {
    ci_dns_rcode_t rcode = ci_dns_record_get_rcode(rdnsrec);
    if (rcode == CI_RCODE_SERVFAIL || rcode == CI_RCODE_NOTIMP ||
        rcode == CI_RCODE_REFUSED) {
      switch (rcode) {
        case CI_RCODE_SERVFAIL:
          status = CI_ESERVFAIL;
          break;
        case CI_RCODE_NOTIMP:
          status = CI_ENOTIMP;
          break;
        case CI_RCODE_REFUSED:
          status = CI_EREFUSED;
          break;
        default:
          break;
      }

      server_increment_failures(server, query->using_tcp);
      ci_requeue_query(query, now, status, CI_TRUE, rdnsrec);

      /* Should any of these cause a connection termination?
       * Maybe SERVER_FAILURE? */
      status = CI_SUCCESS;
      goto cleanup;
    }
  }

  /* If cache insertion was successful, it took ownership.  We ignore
   * other cache insertion failures. */
  if (ci_qcache_insert(channel, now, query, rdnsrec) == CI_SUCCESS) {
    is_cached = CI_TRUE;
  }

  server_set_good(server, query->using_tcp);
  end_query(channel, server, query, CI_SUCCESS, rdnsrec);

  status = CI_SUCCESS;

cleanup:
  /* Don't cleanup the cached pointer to the dns response */
  if (!is_cached) {
    ci_dns_record_destroy(rdnsrec);
  }

  return status;
}

static void handle_conn_error(ci_conn_t *conn, ci_bool_t critical_failure,
                              ci_status_t failure_status)
{
  ci_server_t *server = conn->server;

  /* Increment failures first before requeue so it is unlikely to requeue
   * to the same server */
  if (critical_failure) {
    server_increment_failures(
      server, (conn->flags & CI_CONN_FLAG_TCP) ? CI_TRUE : CI_FALSE);
  }

  /* This will requeue any connections automatically */
  ci_close_connection(conn, failure_status);
}

ci_status_t ci_requeue_query(ci_query_t *query, const ci_timeval_t *now,
                                 ci_status_t            status,
                                 ci_bool_t              inc_try_count,
                                 const ci_dns_record_t *dnsrec)
{
  ci_channel_t *channel   = query->channel;
  size_t          max_tries = ci_slist_len(channel->servers) * channel->tries;

  ci_query_remove_from_conn(query);

  if (status != CI_SUCCESS) {
    query->error_status = status;
  }

  if (inc_try_count) {
    query->try_count++;
  }

  if (query->try_count < max_tries && !query->no_retries) {
    return ci_send_query(NULL, query, now);
  }

  /* If we are here, all attempts to perform query failed. */
  if (query->error_status == CI_SUCCESS) {
    query->error_status = CI_ETIMEOUT;
  }

  end_query(channel, NULL, query, query->error_status, dnsrec);
  return CI_ETIMEOUT;
}

/*! Count the number of servers that share the same highest priority (lowest
 *  consecutive failures).  Since they are sorted in priority order, we just
 *  stop when the consecutive failure count changes. Used for random selection
 *  of good servers. */
static size_t count_highest_prio_servers(const ci_channel_t *channel)
{
  ci_slist_node_t *node;
  size_t             cnt                  = 0;
  size_t             last_consec_failures = SIZE_MAX;

  for (node = ci_slist_node_first(channel->servers); node != NULL;
       node = ci_slist_node_next(node)) {
    const ci_server_t *server = ci_slist_node_val(node);

    if (last_consec_failures != SIZE_MAX &&
        last_consec_failures < server->consec_failures) {
      break;
    }

    last_consec_failures = server->consec_failures;
    cnt++;
  }

  return cnt;
}

/* Pick a random *best* server from the list, we first get a random number in
 * the range of the number of *best* servers, then scan until we find that
 * server in the list */
static ci_server_t *ci_random_server(ci_channel_t *channel)
{
  unsigned char      c;
  size_t             cnt;
  size_t             idx;
  ci_slist_node_t *node;
  size_t             num_servers = count_highest_prio_servers(channel);

  /* Silence coverity, not possible */
  if (num_servers == 0) {
    return NULL;
  }

  ci_rand_bytes(channel->rand_state, &c, 1);

  cnt = c;
  idx = cnt % num_servers;

  cnt = 0;
  for (node = ci_slist_node_first(channel->servers); node != NULL;
       node = ci_slist_node_next(node)) {
    if (cnt == idx) {
      return ci_slist_node_val(node);
    }

    cnt++;
  }

  return NULL;
}

static void server_probe_cb(void *arg, ci_status_t status, size_t timeouts,
                            const ci_dns_record_t *dnsrec)
{
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)dnsrec;
  /* Nothing to do, the logic internally will handle success/fail of this */
}

/* Determine if we should probe a downed server */
static void ci_probe_failed_server(ci_channel_t      *channel,
                                     const ci_server_t *server,
                                     const ci_query_t  *query)
{
  const ci_server_t *last_server = ci_slist_last_val(channel->servers);
  unsigned short       r;
  ci_timeval_t       now;
  ci_slist_node_t   *node;
  ci_server_t       *probe_server = NULL;

  /* If no servers have failures, or we're not configured with a server retry
   * chance, then nothing to probe */
  if ((last_server != NULL && last_server->consec_failures == 0) ||
      channel->server_retry_chance == 0) {
    return;
  }

  /* Generate a random value to decide whether to retry a failed server. The
   * probability to use is 1/channel->server_retry_chance, rounded up to a
   * precision of 1/2^B where B is the number of bits in the random value.
   * We use an unsigned short for the random value for increased precision.
   */
  ci_rand_bytes(channel->rand_state, (unsigned char *)&r, sizeof(r));
  if (r % channel->server_retry_chance != 0) {
    return;
  }

  /* Select the first server with failures to retry that has passed the retry
   * timeout and doesn't already have a pending probe */
  ci_tvnow(&now);
  for (node = ci_slist_node_first(channel->servers); node != NULL;
       node = ci_slist_node_next(node)) {
    ci_server_t *node_val = ci_slist_node_val(node);
    if (node_val != NULL && node_val->consec_failures > 0 &&
        !node_val->probe_pending &&
        ci_timedout(&now, &node_val->next_retry_time)) {
      probe_server = node_val;
      break;
    }
  }

  /* Either nothing to probe or the query was enqueud to the same server
   * we were going to probe. Do nothing. */
  if (probe_server == NULL || server == probe_server) {
    return;
  }

  /* Enqueue an identical query onto the specified server without honoring
   * the cache or allowing retries.  We want to make sure it only attempts to
   * use the server in question */
  probe_server->probe_pending = CI_TRUE;
  ci_send_nolock(channel, probe_server,
                   CI_SEND_FLAG_NOCACHE | CI_SEND_FLAG_NORETRY,
                   query->query, server_probe_cb, NULL, NULL);
}

static size_t ci_calc_query_timeout(const ci_query_t   *query,
                                      const ci_server_t  *server,
                                      const ci_timeval_t *now)
{
  const ci_channel_t *channel  = query->channel;
  size_t                timeout  = ci_metrics_server_timeout(server, now);
  size_t                timeplus = timeout;
  size_t                rounds;
  size_t                num_servers = ci_slist_len(channel->servers);

  if (num_servers == 0) {
    return 0; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* For each trip through the entire server list, we want to double the
   * retry from the last retry */
  rounds = (query->try_count / num_servers);
  if (rounds > 0) {
    timeplus <<= rounds;
  }

  if (channel->maxtimeout && timeplus > channel->maxtimeout) {
    timeplus = channel->maxtimeout;
  }

  /* Add some jitter to the retry timeout.
   *
   * Jitter is needed in situation when resolve requests are performed
   * simultaneously from multiple hosts and DNS server throttle these requests.
   * Adding randomness allows to avoid synchronisation of retries.
   *
   * Value of timeplus adjusted randomly to the range [0.5 * timeplus,
   * timeplus].
   */
  if (rounds > 0) {
    unsigned short r;
    float          delta_multiplier;

    ci_rand_bytes(channel->rand_state, (unsigned char *)&r, sizeof(r));
    delta_multiplier  = ((float)r / USHRT_MAX) * 0.5f;
    timeplus         -= (size_t)((float)timeplus * delta_multiplier);
  }

  /* We want explicitly guarantee that timeplus is greater or equal to timeout
   * specified in channel options. */
  if (timeplus < timeout) {
    timeplus = timeout;
  }

  return timeplus;
}

static ci_conn_t *ci_fetch_connection(const ci_channel_t *channel,
                                          ci_server_t        *server,
                                          const ci_query_t   *query)
{
  ci_llist_node_t *node;
  ci_conn_t       *conn;

  if (query->using_tcp) {
    return server->tcp_conn;
  }

  /* Fetch existing UDP connection */
  node = ci_llist_node_first(server->connections);
  if (node == NULL) {
    return NULL;
  }

  conn = ci_llist_node_val(node);
  /* Not UDP, skip */
  if (conn->flags & CI_CONN_FLAG_TCP) {
    return NULL;
  }

  /* Used too many times */
  if (channel->udp_max_queries > 0 &&
      conn->total_queries >= channel->udp_max_queries) {
    return NULL;
  }

  return conn;
}

static ci_status_t ci_conn_query_write(ci_conn_t          *conn,
                                           ci_query_t         *query,
                                           const ci_timeval_t *now)
{
  ci_server_t  *server  = conn->server;
  ci_channel_t *channel = server->channel;
  ci_status_t   status;

  status = ci_cookie_apply(query->query, conn, now);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* We write using the TCP format even for UDP, we just strip the length
   * before putting on the wire */
  status = ci_dns_write_buf_tcp(query->query, conn->out_buf);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Not pending a TFO write and not connected, so we can't even try to
   * write until we get a signal */
  if (conn->flags & CI_CONN_FLAG_TCP &&
      !(conn->state_flags & CI_CONN_STATE_CONNECTED) &&
      !(conn->flags & CI_CONN_FLAG_TFO_INITIAL)) {
    return CI_SUCCESS;
  }

  /* Delay actual write if possible (TCP only, and only if callback
   * configured) */
  if (channel->notify_pending_write_cb && !channel->notify_pending_write &&
      conn->flags & CI_CONN_FLAG_TCP) {
    channel->notify_pending_write = CI_TRUE;
    channel->notify_pending_write_cb(channel->notify_pending_write_cb_data);
    return CI_SUCCESS;
  }

  /* Unfortunately we need to write right away and can't aggregate multiple
   * queries into a single write. */
  return ci_conn_flush(conn);
}

ci_status_t ci_send_query(ci_server_t *requested_server,
                              ci_query_t *query, const ci_timeval_t *now)
{
  ci_channel_t *channel = query->channel;
  ci_server_t  *server;
  ci_conn_t    *conn;
  size_t          timeplus;
  ci_status_t   status;
  ci_bool_t     probe_downed_server = CI_TRUE;


  /* Choose the server to send the query to */
  if (requested_server != NULL) {
    server = requested_server;
  } else {
    /* If rotate is turned on, do a random selection */
    if (channel->rotate) {
      server = ci_random_server(channel);
    } else {
      /* First server in list */
      server = ci_slist_first_val(channel->servers);
    }
  }

  if (server == NULL) {
    end_query(channel, server, query, CI_ENOSERVER /* ? */, NULL);
    return CI_ENOSERVER;
  }

  /* If a query is directed to a specific query, or the server chosen has
   * failures, or the query is being retried, don't probe for downed servers */
  if (requested_server != NULL || server->consec_failures > 0 ||
      query->try_count != 0) {
    probe_downed_server = CI_FALSE;
  }

  conn = ci_fetch_connection(channel, server, query);
  if (conn == NULL) {
    status = ci_open_connection(&conn, channel, server, query->using_tcp);
    switch (status) {
      /* Good result, continue on */
      case CI_SUCCESS:
        break;

      /* These conditions are retryable as they are server-specific
       * error codes */
      case CI_ECONNREFUSED:
      case CI_EBADFAMILY:
        server_increment_failures(server, query->using_tcp);
        return ci_requeue_query(query, now, status, CI_TRUE, NULL);

      /* Anything else is not retryable, likely ENOMEM */
      default:
        end_query(channel, server, query, status, NULL);
        return status;
    }
  }

  /* Write the query */
  status = ci_conn_query_write(conn, query, now);
  switch (status) {
    /* Good result, continue on */
    case CI_SUCCESS:
      break;

    case CI_ENOMEM:
      /* Not retryable */
      end_query(channel, server, query, status, NULL);
      return status;

    /* These conditions are retryable as they are server-specific
     * error codes */
    case CI_ECONNREFUSED:
    case CI_EBADFAMILY:
      handle_conn_error(conn, CI_TRUE, status);
      status = ci_requeue_query(query, now, status, CI_TRUE, NULL);
      if (status == CI_ETIMEOUT) {
        status = CI_ECONNREFUSED;
      }
      return status;

    default:
      server_increment_failures(server, query->using_tcp);
      status = ci_requeue_query(query, now, status, CI_TRUE, NULL);
      return status;
  }

  timeplus = ci_calc_query_timeout(query, server, now);
  /* Keep track of queries bucketed by timeout, so we can process
   * timeout events quickly.
   */
  ci_slist_node_destroy(query->node_queries_by_timeout);
  query->ts      = *now;
  query->timeout = *now;
  timeadd(&query->timeout, timeplus);
  query->node_queries_by_timeout =
    ci_slist_insert(channel->queries_by_timeout, query);
  if (!query->node_queries_by_timeout) {
    /* LCOV_EXCL_START: OutOfMemory */
    end_query(channel, server, query, CI_ENOMEM, NULL);
    return CI_ENOMEM;
    /* LCOV_EXCL_STOP */
  }

  /* Keep track of queries bucketed by connection, so we can process errors
   * quickly. */
  ci_llist_node_destroy(query->node_queries_to_conn);
  query->node_queries_to_conn =
    ci_llist_insert_last(conn->queries_to_conn, query);

  if (query->node_queries_to_conn == NULL) {
    /* LCOV_EXCL_START: OutOfMemory */
    end_query(channel, server, query, CI_ENOMEM, NULL);
    return CI_ENOMEM;
    /* LCOV_EXCL_STOP */
  }

  query->conn = conn;
  conn->total_queries++;

  /* We just successfully enqueud a query, see if we should probe downed
   * servers. */
  if (probe_downed_server) {
    ci_probe_failed_server(channel, server, query);
  }

  return CI_SUCCESS;
}

static ci_bool_t same_questions(const ci_query_t      *query,
                                  const ci_dns_record_t *arec)
{
  size_t                   i;
  ci_bool_t              rv      = CI_FALSE;
  const ci_dns_record_t *qrec    = query->query;
  const ci_channel_t    *channel = query->channel;


  if (ci_dns_record_query_cnt(qrec) != ci_dns_record_query_cnt(arec)) {
    goto done;
  }

  for (i = 0; i < ci_dns_record_query_cnt(qrec); i++) {
    const char         *qname = NULL;
    const char         *aname = NULL;
    ci_dns_rec_type_t qtype;
    ci_dns_rec_type_t atype;
    ci_dns_class_t    qclass;
    ci_dns_class_t    aclass;

    if (ci_dns_record_query_get(qrec, i, &qname, &qtype, &qclass) !=
          CI_SUCCESS ||
        qname == NULL) {
      goto done;
    }

    if (ci_dns_record_query_get(arec, i, &aname, &atype, &aclass) !=
          CI_SUCCESS ||
        aname == NULL) {
      goto done;
    }

    if (qtype != atype || qclass != aclass) {
      goto done;
    }

    if (channel->flags & CI_FLAG_DNS0x20 && !query->using_tcp) {
      /* NOTE: for DNS 0x20, part of the protection is to use a case-sensitive
       *       comparison of the DNS query name.  This expects the upstream DNS
       *       server to preserve the case of the name in the response packet.
       *       https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00
       */
      if (!ci_streq(qname, aname)) {
        goto done;
      }
    } else {
      /* without DNS0x20 use case-insensitive matching */
      if (!ci_strcaseeq(qname, aname)) {
        goto done;
      }
    }
  }

  rv = CI_TRUE;

done:
  return rv;
}

static void ci_detach_query(ci_query_t *query)
{
  /* Remove the query from all the lists in which it is linked */
  ci_query_remove_from_conn(query);
  ci_htable_szvp_remove(query->channel->queries_by_qid, query->qid);
  ci_llist_node_destroy(query->node_all_queries);
  query->node_all_queries = NULL;
}

static void end_query(ci_channel_t *channel, ci_server_t *server,
                      ci_query_t *query, ci_status_t status,
                      const ci_dns_record_t *dnsrec)
{
  /* If we were probing for the server to come back online, lets mark it as
   * no longer being probed */
  if (server != NULL) {
    server->probe_pending = CI_FALSE;
  }

  ci_metrics_record(query, server, status, dnsrec);

  /* Invoke the callback. */
  query->callback(query->arg, status, query->timeouts, dnsrec);
  ci_free_query(query);

  /* Check and notify if no other queries are enqueued on the channel.  This
   * must come after the callback and freeing the query for 2 reasons.
   *  1) The callback itself may enqueue a new query
   *  2) Technically the current query isn't detached until it is free()'d.
   */
  ci_queue_notify_empty(channel);
}

void ci_free_query(ci_query_t *query)
{
  ci_detach_query(query);
  /* Zero out some important stuff, to help catch bugs */
  query->callback = NULL;
  query->arg      = NULL;
  /* Deallocate the memory associated with the query */
  ci_dns_record_destroy(query->query);

  ci_free(query);
}
