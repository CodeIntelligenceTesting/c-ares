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

int ci_parse_soa_reply(const unsigned char *abuf, int alen_int,
                         struct ci_soa_reply **soa_out)
{
  ci_status_t          status;
  size_t                 alen;
  struct ci_soa_reply *soa    = NULL;
  ci_dns_record_t     *dnsrec = NULL;
  size_t                 i;

  *soa_out = NULL;

  if (alen_int < 0) {
    return CI_EBADRESP;
  }

  alen = (size_t)alen_int;

  status = ci_dns_parse(abuf, alen, 0, &dnsrec);
  if (status != CI_SUCCESS) {
    goto done;
  }

  if (ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER) == 0) {
    status = CI_EBADRESP; /* ENODATA might make more sense */
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
        ci_dns_rr_get_type(rr) != CI_REC_TYPE_SOA) {
      continue;
    }

    /* allocate result struct */
    soa = ci_malloc_data(CI_DATATYPE_SOA_REPLY);
    if (soa == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    soa->serial  = ci_dns_rr_get_u32(rr, CI_RR_SOA_SERIAL);
    soa->refresh = ci_dns_rr_get_u32(rr, CI_RR_SOA_REFRESH);
    soa->retry   = ci_dns_rr_get_u32(rr, CI_RR_SOA_RETRY);
    soa->expire  = ci_dns_rr_get_u32(rr, CI_RR_SOA_EXPIRE);
    soa->minttl  = ci_dns_rr_get_u32(rr, CI_RR_SOA_MINIMUM);
    soa->nsname  = ci_strdup(ci_dns_rr_get_str(rr, CI_RR_SOA_MNAME));
    if (soa->nsname == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
    soa->hostmaster = ci_strdup(ci_dns_rr_get_str(rr, CI_RR_SOA_RNAME));
    if (soa->hostmaster == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
    break;
  }

  if (soa == NULL) {
    status = CI_EBADRESP;
  }

done:
  /* clean up on error */
  if (status != CI_SUCCESS) {
    ci_free_data(soa);
    /* Compatibility */
    if (status == CI_EBADNAME) {
      status = CI_EBADRESP;
    }
  } else {
    /* everything looks fine, return the data */
    *soa_out = soa;
  }
  ci_dns_record_destroy(dnsrec);
  return (int)status;
}
