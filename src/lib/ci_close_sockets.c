/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
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
#include <assert.h>

static void ci_requeue_queries(ci_conn_t  *conn,
                                 ci_status_t requeue_status)
{
  ci_query_t  *query;
  ci_timeval_t now;

  ci_tvnow(&now);

  while ((query = ci_llist_first_val(conn->queries_to_conn)) != NULL) {
    ci_requeue_query(query, &now, requeue_status, CI_TRUE, NULL);
  }
}

void ci_close_connection(ci_conn_t *conn, ci_status_t requeue_status)
{
  ci_server_t  *server  = conn->server;
  ci_channel_t *channel = server->channel;

  /* Unlink */
  ci_llist_node_claim(
    ci_htable_asvp_get_direct(channel->connnode_by_socket, conn->fd));
  ci_htable_asvp_remove(channel->connnode_by_socket, conn->fd);

  if (conn->flags & CI_CONN_FLAG_TCP) {
    server->tcp_conn = NULL;
  }

  ci_buf_destroy(conn->in_buf);
  ci_buf_destroy(conn->out_buf);

  /* Requeue queries to other connections */
  ci_requeue_queries(conn, requeue_status);

  ci_llist_destroy(conn->queries_to_conn);

  ci_conn_sock_state_cb_update(conn, CI_CONN_STATE_NONE);

  ci_socket_close(channel, conn->fd);

  ci_free(conn);
}

void ci_close_sockets(ci_server_t *server)
{
  ci_llist_node_t *node;

  while ((node = ci_llist_node_first(server->connections)) != NULL) {
    ci_conn_t *conn = ci_llist_node_val(node);
    ci_close_connection(conn, CI_SUCCESS);
  }
}

void ci_check_cleanup_conns(const ci_channel_t *channel)
{
  ci_slist_node_t *snode;

  if (channel == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* Iterate across each server */
  for (snode = ci_slist_node_first(channel->servers); snode != NULL;
       snode = ci_slist_node_next(snode)) {
    ci_server_t     *server = ci_slist_node_val(snode);
    ci_llist_node_t *cnode;

    /* Iterate across each connection */
    cnode = ci_llist_node_first(server->connections);
    while (cnode != NULL) {
      ci_llist_node_t *next       = ci_llist_node_next(cnode);
      ci_conn_t       *conn       = ci_llist_node_val(cnode);
      ci_bool_t        do_cleanup = CI_FALSE;
      cnode                         = next;

      /* Has connections, not eligible */
      if (ci_llist_len(conn->queries_to_conn)) {
        continue;
      }

      /* If we are configured not to stay open, close it out */
      if (!(channel->flags & CI_FLAG_STAYOPEN)) {
        do_cleanup = CI_TRUE;
      }

      /* If the associated server has failures, close it out. Resetting the
       * connection (and specifically the source port number) can help resolve
       * situations where packets are being dropped.
       */
      if (conn->server->consec_failures > 0) {
        do_cleanup = CI_TRUE;
      }

      /* If the udp connection hit its max queries, always close it */
      if (!(conn->flags & CI_CONN_FLAG_TCP) && channel->udp_max_queries > 0 &&
          conn->total_queries >= channel->udp_max_queries) {
        do_cleanup = CI_TRUE;
      }

      if (!do_cleanup) {
        continue;
      }

      /* Clean it up */
      ci_close_connection(conn, CI_SUCCESS);
    }
  }
}
