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
#include "ci_htable.h"
#include "ci_htable_szvp.h"

struct ci_htable_szvp {
  ci_htable_szvp_val_free_t free_val;
  ci_htable_t              *hash;
};

typedef struct {
  size_t              key;
  void               *val;
  ci_htable_szvp_t *parent;
} ci_htable_szvp_bucket_t;

void ci_htable_szvp_destroy(ci_htable_szvp_t *htable)
{
  if (htable == NULL) {
    return;
  }

  ci_htable_destroy(htable->hash);
  ci_free(htable);
}

static unsigned int hash_func(const void *key, unsigned int seed)
{
  const size_t *arg = key;
  return ci_htable_hash_FNV1a((const unsigned char *)arg, sizeof(*arg), seed);
}

static const void *bucket_key(const void *bucket)
{
  const ci_htable_szvp_bucket_t *arg = bucket;
  return &arg->key;
}

static void bucket_free(void *bucket)
{
  ci_htable_szvp_bucket_t *arg = bucket;

  if (arg->parent->free_val) {
    arg->parent->free_val(arg->val);
  }

  ci_free(arg);
}

static ci_bool_t key_eq(const void *key1, const void *key2)
{
  const size_t *k1 = key1;
  const size_t *k2 = key2;

  if (*k1 == *k2) {
    return CI_TRUE;
  }

  return CI_FALSE;
}

ci_htable_szvp_t *
  ci_htable_szvp_create(ci_htable_szvp_val_free_t val_free)
{
  ci_htable_szvp_t *htable = ci_malloc(sizeof(*htable));
  if (htable == NULL) {
    goto fail;
  }

  htable->hash = ci_htable_create(hash_func, bucket_key, bucket_free, key_eq);
  if (htable->hash == NULL) {
    goto fail;
  }

  htable->free_val = val_free;

  return htable;

fail:
  if (htable) {
    ci_htable_destroy(htable->hash);
    ci_free(htable);
  }
  return NULL;
}

ci_bool_t ci_htable_szvp_insert(ci_htable_szvp_t *htable, size_t key,
                                    void *val)
{
  ci_htable_szvp_bucket_t *bucket = NULL;

  if (htable == NULL) {
    goto fail;
  }

  bucket = ci_malloc(sizeof(*bucket));
  if (bucket == NULL) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  bucket->parent = htable;
  bucket->key    = key;
  bucket->val    = val;

  if (!ci_htable_insert(htable->hash, bucket)) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  return CI_TRUE;

fail:
  if (bucket) {
    ci_free(bucket); /* LCOV_EXCL_LINE: OutOfMemory */
  }
  return CI_FALSE;
}

ci_bool_t ci_htable_szvp_get(const ci_htable_szvp_t *htable, size_t key,
                                 void **val)
{
  ci_htable_szvp_bucket_t *bucket = NULL;

  if (val) {
    *val = NULL;
  }

  if (htable == NULL) {
    return CI_FALSE;
  }

  bucket = ci_htable_get(htable->hash, &key);
  if (bucket == NULL) {
    return CI_FALSE;
  }

  if (val) {
    *val = bucket->val;
  }
  return CI_TRUE;
}

void *ci_htable_szvp_get_direct(const ci_htable_szvp_t *htable, size_t key)
{
  void *val = NULL;
  ci_htable_szvp_get(htable, key, &val);
  return val;
}

ci_bool_t ci_htable_szvp_remove(ci_htable_szvp_t *htable, size_t key)
{
  if (htable == NULL) {
    return CI_FALSE;
  }

  return ci_htable_remove(htable->hash, &key);
}

size_t ci_htable_szvp_num_keys(const ci_htable_szvp_t *htable)
{
  if (htable == NULL) {
    return 0;
  }
  return ci_htable_num_keys(htable->hash);
}
