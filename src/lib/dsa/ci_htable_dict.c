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
#include "ci_htable.h"
#include "ci_htable_dict.h"

struct ci_htable_dict {
  ci_htable_t *hash;
};

typedef struct {
  char               *key;
  char               *val;
  ci_htable_dict_t *parent;
} ci_htable_dict_bucket_t;

void ci_htable_dict_destroy(ci_htable_dict_t *htable)
{
  if (htable == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ci_htable_destroy(htable->hash);
  ci_free(htable);
}

static unsigned int hash_func(const void *key, unsigned int seed)
{
  return ci_htable_hash_FNV1a_casecmp(key, ci_strlen(key), seed);
}

static const void *bucket_key(const void *bucket)
{
  const ci_htable_dict_bucket_t *arg = bucket;
  return arg->key;
}

static void bucket_free(void *bucket)
{
  ci_htable_dict_bucket_t *arg = bucket;

  ci_free(arg->key);
  ci_free(arg->val);

  ci_free(arg);
}

static ci_bool_t key_eq(const void *key1, const void *key2)
{
  return ci_strcaseeq(key1, key2);
}

ci_htable_dict_t *ci_htable_dict_create(void)
{
  ci_htable_dict_t *htable = ci_malloc(sizeof(*htable));
  if (htable == NULL) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  htable->hash = ci_htable_create(hash_func, bucket_key, bucket_free, key_eq);
  if (htable->hash == NULL) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  return htable;

/* LCOV_EXCL_START: OutOfMemory */
fail:
  if (htable) {
    ci_htable_destroy(htable->hash);
    ci_free(htable);
  }
  return NULL;
  /* LCOV_EXCL_STOP */
}

ci_bool_t ci_htable_dict_insert(ci_htable_dict_t *htable, const char *key,
                                    const char *val)
{
  ci_htable_dict_bucket_t *bucket = NULL;

  if (htable == NULL || ci_strlen(key) == 0) {
    goto fail;
  }

  bucket = ci_malloc_zero(sizeof(*bucket));
  if (bucket == NULL) {
    goto fail;
  }

  bucket->parent = htable;
  bucket->key    = ci_strdup(key);
  if (bucket->key == NULL) {
    goto fail;
  }

  if (val != NULL) {
    bucket->val = ci_strdup(val);
    if (bucket->val == NULL) {
      goto fail;
    }
  }

  if (!ci_htable_insert(htable->hash, bucket)) {
    goto fail;
  }

  return CI_TRUE;

fail:
  if (bucket) {
    ci_free(bucket->val);
    ci_free(bucket);
  }
  return CI_FALSE;
}

ci_bool_t ci_htable_dict_get(const ci_htable_dict_t *htable,
                                 const char *key, const char **val)
{
  const ci_htable_dict_bucket_t *bucket = NULL;

  if (val) {
    *val = NULL;
  }

  if (htable == NULL) {
    return CI_FALSE;
  }

  bucket = ci_htable_get(htable->hash, key);
  if (bucket == NULL) {
    return CI_FALSE;
  }

  if (val) {
    *val = bucket->val;
  }
  return CI_TRUE;
}

const char *ci_htable_dict_get_direct(const ci_htable_dict_t *htable,
                                        const char               *key)
{
  const char *val = NULL;
  ci_htable_dict_get(htable, key, &val);
  return val;
}

ci_bool_t ci_htable_dict_remove(ci_htable_dict_t *htable, const char *key)
{
  if (htable == NULL) {
    return CI_FALSE;
  }

  return ci_htable_remove(htable->hash, key);
}

size_t ci_htable_dict_num_keys(const ci_htable_dict_t *htable)
{
  if (htable == NULL) {
    return 0;
  }
  return ci_htable_num_keys(htable->hash);
}

char **ci_htable_dict_keys(const ci_htable_dict_t *htable, size_t *num)
{
  const void **buckets = NULL;
  size_t       cnt     = 0;
  char       **out     = NULL;
  size_t       i;

  if (htable == NULL || num == NULL) {
    return NULL; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *num = 0;

  buckets = ci_htable_all_buckets(htable->hash, &cnt);
  if (buckets == NULL || cnt == 0) {
    return NULL;
  }

  out = ci_malloc_zero(sizeof(*out) * cnt);
  if (out == NULL) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  for (i = 0; i < cnt; i++) {
    out[i] = ci_strdup(((const ci_htable_dict_bucket_t *)buckets[i])->key);
    if (out[i] == NULL) {
      goto fail;
    }
  }

  ci_free(buckets);
  *num = cnt;
  return out;

fail:
  *num = 0;
  ci_free_array(out, cnt, ci_free);
  return NULL;
}
