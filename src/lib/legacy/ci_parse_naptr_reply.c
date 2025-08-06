/* MIT License
 *
 * Copyright (c) 2023 Brad House
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
#include "ci_data.h"

int ci_parse_naptr_reply(const unsigned char *abuf, int alen_int,
                           struct ci_naptr_reply **naptr_out)
{
  ci_status_t            status;
  size_t                   alen;
  struct ci_naptr_reply *naptr_head = NULL;
  struct ci_naptr_reply *naptr_last = NULL;
  struct ci_naptr_reply *naptr_curr;
  ci_dns_record_t       *dnsrec = NULL;
  size_t                   i;

  *naptr_out = NULL;

  if (alen_int < 0) {
    return CI_EBADRESP;
  }

  alen = (size_t)alen_int;

  status = ci_dns_parse(abuf, alen, 0, &dnsrec);
  if (status != CI_SUCCESS) {
    goto done;
  }

  if (ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER) == 0) {
    status = CI_ENODATA;
    goto done;
  }

  for (i = 0; i < ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER); i++) {
    const ci_dns_rr_t *rr =
      ci_dns_record_rr_get(dnsrec, CI_SECTION_ANSWER, i);

    if (rr == NULL) {
      /* Shouldn't be possible */
      status = CI_EBADRESP; /* LCOV_EXCL_LINE: DefensiveCoding */
      goto done;              /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    if (ci_dns_rr_get_class(rr) != CI_CLASS_IN ||
        ci_dns_rr_get_type(rr) != CI_REC_TYPE_NAPTR) {
      continue;
    }

    /* Allocate storage for this NAPTR answer appending it to the list */
    naptr_curr = ci_malloc_data(CI_DATATYPE_NAPTR_REPLY);
    if (naptr_curr == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* Link in the record */
    if (naptr_last) {
      naptr_last->next = naptr_curr;
    } else {
      naptr_head = naptr_curr;
    }
    naptr_last = naptr_curr;

    naptr_curr->order      = ci_dns_rr_get_u16(rr, CI_RR_NAPTR_ORDER);
    naptr_curr->preference = ci_dns_rr_get_u16(rr, CI_RR_NAPTR_PREFERENCE);

    /* XXX: Why is this unsigned char * ? */
    naptr_curr->flags = (unsigned char *)ci_strdup(
      ci_dns_rr_get_str(rr, CI_RR_NAPTR_FLAGS));
    if (naptr_curr->flags == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
    /* XXX: Why is this unsigned char * ? */
    naptr_curr->service = (unsigned char *)ci_strdup(
      ci_dns_rr_get_str(rr, CI_RR_NAPTR_SERVICES));
    if (naptr_curr->service == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
    /* XXX: Why is this unsigned char * ? */
    naptr_curr->regexp = (unsigned char *)ci_strdup(
      ci_dns_rr_get_str(rr, CI_RR_NAPTR_REGEXP));
    if (naptr_curr->regexp == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
    naptr_curr->replacement =
      ci_strdup(ci_dns_rr_get_str(rr, CI_RR_NAPTR_REPLACEMENT));
    if (naptr_curr->replacement == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

done:
  /* clean up on error */
  if (status != CI_SUCCESS) {
    if (naptr_head) {
      ci_free_data(naptr_head);
    }
  } else {
    /* everything looks fine, return the data */
    *naptr_out = naptr_head;
  }
  ci_dns_record_destroy(dnsrec);
  return (int)status;
}
