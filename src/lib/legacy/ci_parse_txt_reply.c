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

static int ci_parse_txt_reply_int(const unsigned char *abuf, size_t alen,
                                    ci_bool_t ex, void **txt_out)
{
  ci_status_t        status;
  struct ci_txt_ext *txt_head = NULL;
  struct ci_txt_ext *txt_last = NULL;
  struct ci_txt_ext *txt_curr;
  ci_dns_record_t   *dnsrec = NULL;
  size_t               i;

  *txt_out = NULL;

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
    size_t j;
    size_t cnt;


    if (rr == NULL) {
      /* Shouldn't be possible */
      status = CI_EBADRESP; /* LCOV_EXCL_LINE: DefensiveCoding */
      goto done;              /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    /* XXX: Why Chaos? */
    if ((ci_dns_rr_get_class(rr) != CI_CLASS_IN &&
         ci_dns_rr_get_class(rr) != CI_CLASS_CHAOS) ||
        ci_dns_rr_get_type(rr) != CI_REC_TYPE_TXT) {
      continue;
    }

    cnt = ci_dns_rr_get_abin_cnt(rr, CI_RR_TXT_DATA);

    for (j = 0; j < cnt; j++) {
      const unsigned char *ptr;
      size_t               ptr_len;

      /* Allocate storage for this TXT answer appending it to the list */
      txt_curr =
        ci_malloc_data(ex ? CI_DATATYPE_TXT_EXT : CI_DATATYPE_TXT_REPLY);
      if (txt_curr == NULL) {
        status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }

      /* Link in the record */
      if (txt_last) {
        txt_last->next = txt_curr;
      } else {
        txt_head = txt_curr;
      }
      txt_last = txt_curr;

      /* Tag start on first for each TXT record */
      if (ex && j == 0) {
        txt_curr->record_start = 1;
      }

      ptr = ci_dns_rr_get_abin(rr, CI_RR_TXT_DATA, j, &ptr_len);

      txt_curr->txt = ci_malloc(ptr_len + 1);
      if (txt_curr->txt == NULL) {
        status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
      memcpy(txt_curr->txt, ptr, ptr_len);
      txt_curr->txt[ptr_len] = 0;
      txt_curr->length       = ptr_len;
    }
  }

done:
  /* clean up on error */
  if (status != CI_SUCCESS) {
    if (txt_head) {
      ci_free_data(txt_head);
    }
  } else {
    /* everything looks fine, return the data */
    *txt_out = txt_head;
  }
  ci_dns_record_destroy(dnsrec);
  return (int)status;
}

int ci_parse_txt_reply(const unsigned char *abuf, int alen,
                         struct ci_txt_reply **txt_out)
{
  if (alen < 0) {
    return CI_EBADRESP;
  }
  return ci_parse_txt_reply_int(abuf, (size_t)alen, CI_FALSE,
                                  (void **)txt_out);
}

int ci_parse_txt_reply_ext(const unsigned char *abuf, int alen,
                             struct ci_txt_ext **txt_out)
{
  if (alen < 0) {
    return CI_EBADRESP;
  }
  return ci_parse_txt_reply_int(abuf, (size_t)alen, CI_TRUE,
                                  (void **)txt_out);
}
