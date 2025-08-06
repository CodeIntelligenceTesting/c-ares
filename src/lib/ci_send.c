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

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#include "ci_nameser.h"

static unsigned short generate_unique_qid(ci_channel_t *channel)
{
  unsigned short id;

  do {
    id = ci_generate_new_id(channel->rand_state);
  } while (ci_htable_szvp_get(channel->queries_by_qid, id, NULL));

  return id;
}

/* https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00 */
static ci_status_t ci_apply_dns0x20(ci_channel_t    *channel,
                                        ci_dns_record_t *dnsrec)
{
  ci_status_t status = CI_SUCCESS;
  const char   *name   = NULL;
  char          dns0x20name[256];
  unsigned char randdata[256 / 8];
  size_t        len;
  size_t        remaining_bits;
  size_t        total_bits;
  size_t        i;

  status = ci_dns_record_query_get(dnsrec, 0, &name, NULL, NULL);
  if (status != CI_SUCCESS) {
    goto done;
  }

  len = ci_strlen(name);
  if (len == 0) {
    return CI_SUCCESS;
  }

  if (len >= sizeof(dns0x20name)) {
    status = CI_EBADNAME;
    goto done;
  }

  memset(dns0x20name, 0, sizeof(dns0x20name));

  /* Fetch the minimum amount of random data we'd need for the string, which
   * is 1 bit per byte */
  total_bits     = ((len + 7) / 8) * 8;
  remaining_bits = total_bits;
  ci_rand_bytes(channel->rand_state, randdata, total_bits / 8);

  /* Randomly apply 0x20 to name */
  for (i = 0; i < len; i++) {
    size_t bit;

    /* Only apply 0x20 to alpha characters */
    if (!ci_isalpha(name[i])) {
      dns0x20name[i] = name[i];
      continue;
    }

    /* coin flip */
    bit = total_bits - remaining_bits;
    if (randdata[bit / 8] & (1 << (bit % 8))) {
      dns0x20name[i] = name[i] | 0x20;                          /* Set 0x20 */
    } else {
      dns0x20name[i] = (char)(((unsigned char)name[i]) & 0xDF); /* Unset 0x20 */
    }
    remaining_bits--;
  }

  status = ci_dns_record_query_set_name(dnsrec, 0, dns0x20name);

done:
  return status;
}

ci_status_t ci_send_nolock(ci_channel_t *channel, ci_server_t *server,
                               ci_send_flags_t        flags,
                               const ci_dns_record_t *dnsrec,
                               ci_callback_dnsrec callback, void *arg,
                               unsigned short *qid)
{
  ci_query_t            *query;
  ci_timeval_t           now;
  ci_status_t            status;
  unsigned short           id          = generate_unique_qid(channel);
  const ci_dns_record_t *dnsrec_resp = NULL;

  ci_tvnow(&now);

  if (ci_slist_len(channel->servers) == 0) {
    callback(arg, CI_ENOSERVER, 0, NULL);
    return CI_ENOSERVER;
  }

  if (!(flags & CI_SEND_FLAG_NOCACHE)) {
    /* Check query cache */
    status = ci_qcache_fetch(channel, &now, dnsrec, &dnsrec_resp);
    if (status != CI_ENOTFOUND) {
      /* CI_SUCCESS means we retrieved the cache, anything else is a critical
       * failure, all result in termination */
      callback(arg, status, 0, dnsrec_resp);
      return status;
    }
  }

  /* Allocate space for query and allocated fields. */
  query = ci_malloc(sizeof(ci_query_t));
  if (!query) {
    callback(arg, CI_ENOMEM, 0, NULL); /* LCOV_EXCL_LINE: OutOfMemory */
    return CI_ENOMEM;                  /* LCOV_EXCL_LINE: OutOfMemory */
  }
  memset(query, 0, sizeof(*query));

  query->channel      = channel;
  query->qid          = id;
  query->timeout.sec  = 0;
  query->timeout.usec = 0;
  query->using_tcp =
    (channel->flags & CI_FLAG_USEVC) ? CI_TRUE : CI_FALSE;

  /* Duplicate Query */
  status = ci_dns_record_duplicate_ex(&query->query, dnsrec);
  if (status != CI_SUCCESS) {
    ci_free(query);
    callback(arg, status, 0, NULL);
    return status;
  }

  ci_dns_record_set_id(query->query, id);

  if (channel->flags & CI_FLAG_DNS0x20 && !query->using_tcp) {
    status = ci_apply_dns0x20(channel, query->query);
    if (status != CI_SUCCESS) {
      /* LCOV_EXCL_START: OutOfMemory */
      callback(arg, status, 0, NULL);
      ci_free_query(query);
      return status;
      /* LCOV_EXCL_STOP */
    }
  }

  /* Fill in query arguments. */
  query->callback = callback;
  query->arg      = arg;

  /* Initialize query status. */
  query->try_count = 0;

  if (flags & CI_SEND_FLAG_NORETRY) {
    query->no_retries = CI_TRUE;
  }

  query->error_status = CI_SUCCESS;
  query->timeouts     = 0;

  /* Initialize our list nodes. */
  query->node_queries_by_timeout = NULL;
  query->node_queries_to_conn    = NULL;

  /* Chain the query into the list of all queries. */
  query->node_all_queries = ci_llist_insert_last(channel->all_queries, query);
  if (query->node_all_queries == NULL) {
    /* LCOV_EXCL_START: OutOfMemory */
    callback(arg, CI_ENOMEM, 0, NULL);
    ci_free_query(query);
    return CI_ENOMEM;
    /* LCOV_EXCL_STOP */
  }

  /* Keep track of queries bucketed by qid, so we can process DNS
   * responses quickly.
   */
  if (!ci_htable_szvp_insert(channel->queries_by_qid, query->qid, query)) {
    /* LCOV_EXCL_START: OutOfMemory */
    callback(arg, CI_ENOMEM, 0, NULL);
    ci_free_query(query);
    return CI_ENOMEM;
    /* LCOV_EXCL_STOP */
  }

  /* Perform the first query action. */

  status = ci_send_query(server, query, &now);
  if (status == CI_SUCCESS && qid) {
    *qid = id;
  }
  return status;
}

ci_status_t ci_send_dnsrec(ci_channel_t          *channel,
                               const ci_dns_record_t *dnsrec,
                               ci_callback_dnsrec callback, void *arg,
                               unsigned short *qid)
{
  ci_status_t status;

  if (channel == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ci_channel_lock(channel);

  status = ci_send_nolock(channel, NULL, 0, dnsrec, callback, arg, qid);

  ci_channel_unlock(channel);

  return status;
}

void ci_send(ci_channel_t *channel, const unsigned char *qbuf, int qlen,
               ci_callback callback, void *arg)
{
  ci_dns_record_t *dnsrec = NULL;
  ci_status_t      status;
  void              *carg = NULL;

  if (channel == NULL) {
    return;
  }

  /* Verify that the query is at least long enough to hold the header. */
  if (qlen < HFIXEDSZ || qlen >= (1 << 16)) {
    callback(arg, CI_EBADQUERY, 0, NULL, 0);
    return;
  }

  status = ci_dns_parse(qbuf, (size_t)qlen, 0, &dnsrec);
  if (status != CI_SUCCESS) {
    callback(arg, (int)status, 0, NULL, 0);
    return;
  }

  carg = ci_dnsrec_convert_arg(callback, arg);
  if (carg == NULL) {
    /* LCOV_EXCL_START: OutOfMemory */
    status = CI_ENOMEM;
    ci_dns_record_destroy(dnsrec);
    callback(arg, (int)status, 0, NULL, 0);
    return;
    /* LCOV_EXCL_STOP */
  }

  ci_send_dnsrec(channel, dnsrec, ci_dnsrec_convert_cb, carg, NULL);

  ci_dns_record_destroy(dnsrec);
}

size_t ci_queue_active_queries(const ci_channel_t *channel)
{
  size_t len;

  if (channel == NULL) {
    return 0;
  }

  ci_channel_lock(channel);

  len = ci_llist_len(channel->all_queries);

  ci_channel_unlock(channel);

  return len;
}
