/* MIT License
 *
 * Copyright (c) 2024 Brad House
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
#include "ci_dns_private.h"

typedef struct {
  unsigned char *data;
  size_t         len;
} multistring_data_t;

struct ci_dns_multistring {
  /*! whether or not cached concatenated string is valid */
  ci_bool_t    cache_invalidated;
  /*! combined/concatenated string cache */
  unsigned char *cache_str;
  /*! length of combined/concatenated string */
  size_t         cache_str_len;
  /*! Data making up strings */
  ci_array_t  *strs; /*!< multistring_data_t type */
};

static void ci_dns_multistring_free_cb(void *arg)
{
  multistring_data_t *data = arg;
  if (data == NULL) {
    return;
  }
  ci_free(data->data);
}

ci_dns_multistring_t *ci_dns_multistring_create(void)
{
  ci_dns_multistring_t *strs = ci_malloc_zero(sizeof(*strs));
  if (strs == NULL) {
    return NULL;
  }

  strs->strs =
    ci_array_create(sizeof(multistring_data_t), ci_dns_multistring_free_cb);
  if (strs->strs == NULL) {
    ci_free(strs);
    return NULL;
  }

  return strs;
}

void ci_dns_multistring_clear(ci_dns_multistring_t *strs)
{
  if (strs == NULL) {
    return;
  }

  while (ci_array_len(strs->strs)) {
    ci_array_remove_last(strs->strs);
  }
}

void ci_dns_multistring_destroy(ci_dns_multistring_t *strs)
{
  if (strs == NULL) {
    return;
  }
  ci_dns_multistring_clear(strs);
  ci_array_destroy(strs->strs);
  ci_free(strs->cache_str);
  ci_free(strs);
}

ci_status_t ci_dns_multistring_swap_own(ci_dns_multistring_t *strs,
                                            size_t idx, unsigned char *str,
                                            size_t len)
{
  multistring_data_t *data;

  if (strs == NULL || str == NULL || len == 0) {
    return CI_EFORMERR;
  }

  strs->cache_invalidated = CI_TRUE;

  data = ci_array_at(strs->strs, idx);
  if (data == NULL) {
    return CI_EFORMERR;
  }

  ci_free(data->data);
  data->data = str;
  data->len  = len;
  return CI_SUCCESS;
}

ci_status_t ci_dns_multistring_del(ci_dns_multistring_t *strs, size_t idx)
{
  if (strs == NULL) {
    return CI_EFORMERR;
  }

  strs->cache_invalidated = CI_TRUE;

  return ci_array_remove_at(strs->strs, idx);
}

ci_status_t ci_dns_multistring_add_own(ci_dns_multistring_t *strs,
                                           unsigned char *str, size_t len)
{
  multistring_data_t *data;
  ci_status_t       status;

  if (strs == NULL) {
    return CI_EFORMERR;
  }

  strs->cache_invalidated = CI_TRUE;

  /* NOTE: its ok to have an empty string added */
  if (str == NULL && len != 0) {
    return CI_EFORMERR;
  }

  status = ci_array_insert_last((void **)&data, strs->strs);
  if (status != CI_SUCCESS) {
    return status;
  }

  data->data = str;
  data->len  = len;

  return CI_SUCCESS;
}

size_t ci_dns_multistring_cnt(const ci_dns_multistring_t *strs)
{
  if (strs == NULL) {
    return 0;
  }
  return ci_array_len(strs->strs);
}

const unsigned char *
  ci_dns_multistring_get(const ci_dns_multistring_t *strs, size_t idx,
                           size_t *len)
{
  const multistring_data_t *data;

  if (strs == NULL || len == NULL) {
    return NULL;
  }

  data = ci_array_at_const(strs->strs, idx);
  if (data == NULL) {
    return NULL;
  }

  *len = data->len;
  return data->data;
}

const unsigned char *ci_dns_multistring_combined(ci_dns_multistring_t *strs,
                                                   size_t                 *len)
{
  ci_buf_t *buf = NULL;
  size_t      i;

  if (strs == NULL || len == NULL) {
    return NULL;
  }

  *len = 0;

  /* Return cache if possible */
  if (!strs->cache_invalidated) {
    *len = strs->cache_str_len;
    return strs->cache_str;
  }

  /* Clear cache */
  ci_free(strs->cache_str);
  strs->cache_str     = NULL;
  strs->cache_str_len = 0;

  buf = ci_buf_create();

  for (i = 0; i < ci_array_len(strs->strs); i++) {
    const multistring_data_t *data = ci_array_at_const(strs->strs, i);
    if (data == NULL ||
        ci_buf_append(buf, data->data, data->len) != CI_SUCCESS) {
      ci_buf_destroy(buf);
      return NULL;
    }
  }

  strs->cache_str =
    (unsigned char *)ci_buf_finish_str(buf, &strs->cache_str_len);
  if (strs->cache_str != NULL) {
    strs->cache_invalidated = CI_FALSE;
  }
  *len = strs->cache_str_len;
  return strs->cache_str;
}

ci_status_t ci_dns_multistring_parse_buf(ci_buf_t *buf,
                                             size_t      remaining_len,
                                             ci_dns_multistring_t **strs,
                                             ci_bool_t validate_printable)
{
  unsigned char len;
  ci_status_t status   = CI_EBADRESP;
  size_t        orig_len = ci_buf_len(buf);

  if (buf == NULL) {
    return CI_EFORMERR;
  }

  if (remaining_len == 0) {
    return CI_EBADRESP;
  }

  if (strs != NULL) {
    *strs = ci_dns_multistring_create();
    if (*strs == NULL) {
      return CI_ENOMEM;
    }
  }

  while (orig_len - ci_buf_len(buf) < remaining_len) {
    status = ci_buf_fetch_bytes(buf, &len, 1);
    if (status != CI_SUCCESS) {
      break; /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    if (len) {
      /* When used by the _str() parser, it really needs to be validated to
       * be a valid printable ascii string.  Do that here */
      if (validate_printable && ci_buf_len(buf) >= len) {
        size_t      mylen;
        const char *data = (const char *)ci_buf_peek(buf, &mylen);
        if (!ci_str_isprint(data, len)) {
          status = CI_EBADSTR;
          break;
        }
      }

      if (strs != NULL) {
        unsigned char *data = NULL;
        status = ci_buf_fetch_bytes_dup(buf, len, CI_TRUE, &data);
        if (status != CI_SUCCESS) {
          break;
        }
        status = ci_dns_multistring_add_own(*strs, data, len);
        if (status != CI_SUCCESS) {
          ci_free(data);
          break;
        }
      } else {
        status = ci_buf_consume(buf, len);
        if (status != CI_SUCCESS) {
          break;
        }
      }
    }
  }

  if (status != CI_SUCCESS && strs != NULL) {
    ci_dns_multistring_destroy(*strs);
    *strs = NULL;
  }

  return status;
}
