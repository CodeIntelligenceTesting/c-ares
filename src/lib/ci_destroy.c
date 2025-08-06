/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2004 Daniel Stenberg
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
#include "event/ci_event.h"
#include <assert.h>

void ci_destroy(ci_channel_t *channel)
{
  size_t             i;
  ci_llist_node_t *node = NULL;

  if (channel == NULL) {
    return;
  }

  /* Mark as being shutdown */
  ci_channel_lock(channel);
  channel->sys_up = CI_FALSE;
  ci_channel_unlock(channel);

  /* Disable configuration change monitoring.  We can't hold a lock because
   * some cleanup routines, such as on Windows, are synchronous operations.
   * What we've observed is a system config change event was triggered right
   * at shutdown time and it tries to take the channel lock and the destruction
   * waits for that event to complete before it continues so we get a channel
   * lock deadlock at shutdown if we hold a lock during this process. */
  if (channel->optmask & CI_OPT_EVENT_THREAD) {
    ci_event_thread_t *e = channel->sock_state_cb_data;
    if (e && e->configchg) {
      ci_event_configchg_destroy(e->configchg);
      e->configchg = NULL;
    }
  }

  /* Wait for reinit thread to exit if there was one pending, can't be
   * holding a lock as the thread may take locks. */
  if (channel->reinit_thread != NULL) {
    void *rv;
    ci_thread_join(channel->reinit_thread, &rv);
    channel->reinit_thread = NULL;
  }

  /* Lock because callbacks will be triggered, and any system-generated
   * callbacks need to hold a channel lock. */
  ci_channel_lock(channel);

  /* Destroy all queries */
  node = ci_llist_node_first(channel->all_queries);
  while (node != NULL) {
    ci_llist_node_t *next  = ci_llist_node_next(node);
    ci_query_t      *query = ci_llist_node_claim(node);

    query->node_all_queries = NULL;
    query->callback(query->arg, CI_EDESTRUCTION, 0, NULL);
    ci_free_query(query);

    node = next;
  }

  ci_queue_notify_empty(channel);

#ifndef NDEBUG
  /* Freeing the query should remove it from all the lists in which it sits,
   * so all query lists should be empty now.
   */
  assert(ci_llist_len(channel->all_queries) == 0);
  assert(ci_htable_szvp_num_keys(channel->queries_by_qid) == 0);
  assert(ci_slist_len(channel->queries_by_timeout) == 0);
#endif

  ci_destroy_servers_state(channel);

#ifndef NDEBUG
  assert(ci_htable_asvp_num_keys(channel->connnode_by_socket) == 0);
#endif

  /* No more callbacks will be triggered after this point, unlock */
  ci_channel_unlock(channel);

  /* Shut down the event thread */
  if (channel->optmask & CI_OPT_EVENT_THREAD) {
    ci_event_thread_destroy(channel);
  }

  if (channel->domains) {
    for (i = 0; i < channel->ndomains; i++) {
      ci_free(channel->domains[i]);
    }
    ci_free(channel->domains);
  }

  ci_llist_destroy(channel->all_queries);
  ci_slist_destroy(channel->queries_by_timeout);
  ci_htable_szvp_destroy(channel->queries_by_qid);
  ci_htable_asvp_destroy(channel->connnode_by_socket);

  ci_free(channel->sortlist);
  ci_free(channel->lookups);
  ci_free(channel->resolvconf_path);
  ci_free(channel->hosts_path);
  ci_destroy_rand_state(channel->rand_state);

  ci_hosts_file_destroy(channel->hf);

  ci_qcache_destroy(channel->qcache);

  ci_channel_threading_destroy(channel);

  ci_free(channel);
}

void ci_destroy_server(ci_server_t *server)
{
  if (server == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ci_close_sockets(server);
  ci_llist_destroy(server->connections);
  ci_free(server);
}

void ci_destroy_servers_state(ci_channel_t *channel)
{
  ci_slist_node_t *node;

  while ((node = ci_slist_node_first(channel->servers)) != NULL) {
    ci_server_t *server = ci_slist_node_claim(node);
    ci_destroy_server(server);
  }

  ci_slist_destroy(channel->servers);
  channel->servers = NULL;
}
