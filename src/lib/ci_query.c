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

typedef struct {
  ci_callback_dnsrec callback;
  void                *arg;
} ci_query_dnsrec_arg_t;

static void ci_query_dnsrec_cb(void *arg, ci_status_t status,
                                 size_t                   timeouts,
                                 const ci_dns_record_t *dnsrec)
{
  ci_query_dnsrec_arg_t *qquery = arg;

  if (status != CI_SUCCESS) {
    qquery->callback(qquery->arg, status, timeouts, dnsrec);
  } else {
    size_t           ancount;
    ci_dns_rcode_t rcode;
    /* Pull the response code and answer count from the packet and convert any
     * errors.
     */
    rcode   = ci_dns_record_get_rcode(dnsrec);
    ancount = ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER);
    status  = ci_dns_query_reply_tostatus(rcode, ancount);
    qquery->callback(qquery->arg, status, timeouts, dnsrec);
  }
  ci_free(qquery);
}

ci_status_t ci_query_nolock(ci_channel_t *channel, const char *name,
                                ci_dns_class_t     dnsclass,
                                ci_dns_rec_type_t  type,
                                ci_callback_dnsrec callback, void *arg,
                                unsigned short *qid)
{
  ci_status_t            status;
  ci_dns_record_t       *dnsrec = NULL;
  ci_dns_flags_t         flags  = 0;
  ci_query_dnsrec_arg_t *qquery = NULL;

  if (channel == NULL || name == NULL || callback == NULL) {
    /* LCOV_EXCL_START: DefensiveCoding */
    status = CI_EFORMERR;
    if (callback != NULL) {
      callback(arg, status, 0, NULL);
    }
    return status;
    /* LCOV_EXCL_STOP */
  }

  if (!(channel->flags & CI_FLAG_NORECURSE)) {
    flags |= CI_FLAG_RD;
  }

  status = ci_dns_record_create_query(
    &dnsrec, name, dnsclass, type, 0, flags,
    (size_t)(channel->flags & CI_FLAG_EDNS) ? channel->ednspsz : 0);
  if (status != CI_SUCCESS) {
    callback(arg, status, 0, NULL); /* LCOV_EXCL_LINE: OutOfMemory */
    return status;                  /* LCOV_EXCL_LINE: OutOfMemory */
  }

  qquery = ci_malloc(sizeof(*qquery));
  if (qquery == NULL) {
    /* LCOV_EXCL_START: OutOfMemory */
    status = CI_ENOMEM;
    callback(arg, status, 0, NULL);
    ci_dns_record_destroy(dnsrec);
    return status;
    /* LCOV_EXCL_STOP */
  }

  qquery->callback = callback;
  qquery->arg      = arg;

  /* Send it off.  qcallback will be called when we get an answer. */
  status = ci_send_nolock(channel, NULL, 0, dnsrec, ci_query_dnsrec_cb,
                            qquery, qid);

  ci_dns_record_destroy(dnsrec);
  return status;
}

ci_status_t ci_query_dnsrec(ci_channel_t *channel, const char *name,
                                ci_dns_class_t     dnsclass,
                                ci_dns_rec_type_t  type,
                                ci_callback_dnsrec callback, void *arg,
                                unsigned short *qid)
{
  ci_status_t status;

  if (channel == NULL) {
    return CI_EFORMERR;
  }

  ci_channel_lock(channel);
  status = ci_query_nolock(channel, name, dnsclass, type, callback, arg, qid);
  ci_channel_unlock(channel);
  return status;
}

void ci_query(ci_channel_t *channel, const char *name, int dnsclass,
                int type, ci_callback callback, void *arg)
{
  void *carg = NULL;

  if (channel == NULL) {
    return;
  }

  carg = ci_dnsrec_convert_arg(callback, arg);
  if (carg == NULL) {
    callback(arg, CI_ENOMEM, 0, NULL, 0); /* LCOV_EXCL_LINE: OutOfMemory */
    return;                                 /* LCOV_EXCL_LINE: OutOfMemory */
  }

  ci_query_dnsrec(channel, name, (ci_dns_class_t)dnsclass,
                    (ci_dns_rec_type_t)type, ci_dnsrec_convert_cb, carg,
                    NULL);
}
