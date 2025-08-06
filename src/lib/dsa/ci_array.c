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
#include "ci_array.h"

#define CI__ARRAY_MIN 4

struct ci_array {
  ci_array_destructor_t destruct;
  void                   *arr;
  size_t                  member_size;
  size_t                  cnt;
  size_t                  offset;
  size_t                  alloc_cnt;
};

ci_array_t *ci_array_create(size_t                  member_size,
                                ci_array_destructor_t destruct)
{
  ci_array_t *arr;

  if (member_size == 0) {
    return NULL;
  }

  arr = ci_malloc_zero(sizeof(*arr));
  if (arr == NULL) {
    return NULL;
  }

  arr->member_size = member_size;
  arr->destruct    = destruct;
  return arr;
}

size_t ci_array_len(const ci_array_t *arr)
{
  if (arr == NULL) {
    return 0;
  }
  return arr->cnt;
}

void *ci_array_at(ci_array_t *arr, size_t idx)
{
  if (arr == NULL || idx >= arr->cnt) {
    return NULL;
  }
  return (unsigned char *)arr->arr + ((idx + arr->offset) * arr->member_size);
}

const void *ci_array_at_const(const ci_array_t *arr, size_t idx)
{
  if (arr == NULL || idx >= arr->cnt) {
    return NULL;
  }
  return (unsigned char *)arr->arr + ((idx + arr->offset) * arr->member_size);
}

ci_status_t ci_array_sort(ci_array_t *arr, ci_array_cmp_t cmp)
{
  if (arr == NULL || cmp == NULL) {
    return CI_EFORMERR;
  }

  /* Nothing to sort */
  if (arr->cnt < 2) {
    return CI_SUCCESS;
  }

  qsort((unsigned char *)arr->arr + (arr->offset * arr->member_size), arr->cnt,
        arr->member_size, cmp);
  return CI_SUCCESS;
}

void ci_array_destroy(ci_array_t *arr)
{
  size_t i;

  if (arr == NULL) {
    return;
  }

  if (arr->destruct != NULL) {
    for (i = 0; i < arr->cnt; i++) {
      arr->destruct(ci_array_at(arr, i));
    }
  }

  ci_free(arr->arr);
  ci_free(arr);
}

/* NOTE: this function operates on actual indexes, NOT indexes using the
 *       arr->offset */
static ci_status_t ci_array_move(ci_array_t *arr, size_t dest_idx,
                                     size_t src_idx)
{
  void       *dest_ptr;
  const void *src_ptr;
  size_t      nmembers;

  if (arr == NULL || dest_idx >= arr->alloc_cnt || src_idx >= arr->alloc_cnt) {
    return CI_EFORMERR;
  }

  /* Nothing to do */
  if (dest_idx == src_idx) {
    return CI_SUCCESS;
  }

  dest_ptr = (unsigned char *)arr->arr + (dest_idx * arr->member_size);
  src_ptr  = (unsigned char *)arr->arr + (src_idx * arr->member_size);

  /* Check to make sure shifting to the right won't overflow our allocation
   * boundary */
  if (dest_idx > src_idx && arr->cnt + (dest_idx - src_idx) > arr->alloc_cnt) {
    return CI_EFORMERR;
  }

  nmembers = arr->cnt - (src_idx - arr->offset);
  memmove(dest_ptr, src_ptr, nmembers * arr->member_size);

  return CI_SUCCESS;
}

void *ci_array_finish(ci_array_t *arr, size_t *num_members)
{
  void *ptr;

  if (arr == NULL || num_members == NULL) {
    return NULL;
  }

  /* Make sure we move data to beginning of allocation */
  if (arr->offset != 0) {
    if (ci_array_move(arr, 0, arr->offset) != CI_SUCCESS) {
      return NULL;
    }
    arr->offset = 0;
  }

  ptr          = arr->arr;
  *num_members = arr->cnt;
  ci_free(arr);
  return ptr;
}

ci_status_t ci_array_set_size(ci_array_t *arr, size_t size)
{
  void *temp;

  if (arr == NULL || size == 0 || size < arr->cnt) {
    return CI_EFORMERR;
  }

  /* Always operate on powers of 2 */
  size = ci_round_up_pow2(size);

  if (size < CI__ARRAY_MIN) {
    size = CI__ARRAY_MIN;
  }

  /* If our allocation size is already large enough, skip */
  if (size <= arr->alloc_cnt) {
    return CI_SUCCESS;
  }

  temp = ci_realloc_zero(arr->arr, arr->alloc_cnt * arr->member_size,
                           size * arr->member_size);
  if (temp == NULL) {
    return CI_ENOMEM;
  }
  arr->alloc_cnt = size;
  arr->arr       = temp;
  return CI_SUCCESS;
}

ci_status_t ci_array_insert_at(void **elem_ptr, ci_array_t *arr,
                                   size_t idx)
{
  void         *ptr;
  ci_status_t status;

  if (arr == NULL) {
    return CI_EFORMERR;
  }

  /* Not >= since we are allowed to append to the end */
  if (idx > arr->cnt) {
    return CI_EFORMERR;
  }

  /* Allocate more if needed */
  status = ci_array_set_size(arr, arr->cnt + 1);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Shift if we have memory but not enough room at the end */
  if (arr->cnt + 1 + arr->offset > arr->alloc_cnt) {
    status = ci_array_move(arr, 0, arr->offset);
    if (status != CI_SUCCESS) {
      return status;
    }
    arr->offset = 0;
  }

  /* If we're inserting anywhere other than the end, we need to move some
   * elements out of the way */
  if (idx != arr->cnt) {
    status = ci_array_move(arr, idx + arr->offset + 1, idx + arr->offset);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  /* Ok, we're guaranteed to have a gap where we need it, lets zero it out,
   * and return it */
  ptr = (unsigned char *)arr->arr + ((idx + arr->offset) * arr->member_size);
  memset(ptr, 0, arr->member_size);
  arr->cnt++;

  if (elem_ptr) {
    *elem_ptr = ptr;
  }

  return CI_SUCCESS;
}

ci_status_t ci_array_insert_last(void **elem_ptr, ci_array_t *arr)
{
  return ci_array_insert_at(elem_ptr, arr, ci_array_len(arr));
}

ci_status_t ci_array_insert_first(void **elem_ptr, ci_array_t *arr)
{
  return ci_array_insert_at(elem_ptr, arr, 0);
}

ci_status_t ci_array_insertdata_at(ci_array_t *arr, size_t idx,
                                       const void *data_ptr)
{
  ci_status_t status;
  void         *ptr = NULL;

  status = ci_array_insert_at(&ptr, arr, idx);
  if (status != CI_SUCCESS) {
    return status;
  }
  memcpy(ptr, data_ptr, arr->member_size);
  return CI_SUCCESS;
}

ci_status_t ci_array_insertdata_last(ci_array_t *arr,
                                         const void   *data_ptr)
{
  ci_status_t status;
  void         *ptr = NULL;

  status = ci_array_insert_last(&ptr, arr);
  if (status != CI_SUCCESS) {
    return status;
  }
  memcpy(ptr, data_ptr, arr->member_size);
  return CI_SUCCESS;
}

ci_status_t ci_array_insertdata_first(ci_array_t *arr,
                                          const void   *data_ptr)
{
  ci_status_t status;
  void         *ptr = NULL;

  status = ci_array_insert_last(&ptr, arr);
  if (status != CI_SUCCESS) {
    return status;
  }
  memcpy(ptr, data_ptr, arr->member_size);
  return CI_SUCCESS;
}

void *ci_array_first(ci_array_t *arr)
{
  return ci_array_at(arr, 0);
}

void *ci_array_last(ci_array_t *arr)
{
  size_t cnt = ci_array_len(arr);
  if (cnt == 0) {
    return NULL;
  }
  return ci_array_at(arr, cnt - 1);
}

const void *ci_array_first_const(const ci_array_t *arr)
{
  return ci_array_at_const(arr, 0);
}

const void *ci_array_last_const(const ci_array_t *arr)
{
  size_t cnt = ci_array_len(arr);
  if (cnt == 0) {
    return NULL;
  }
  return ci_array_at_const(arr, cnt - 1);
}

ci_status_t ci_array_claim_at(void *dest, size_t dest_size,
                                  ci_array_t *arr, size_t idx)
{
  ci_status_t status;

  if (arr == NULL || idx >= arr->cnt) {
    return CI_EFORMERR;
  }

  if (dest != NULL && dest_size < arr->member_size) {
    return CI_EFORMERR;
  }

  if (dest) {
    memcpy(dest, ci_array_at(arr, idx), arr->member_size);
  }

  if (idx == 0) {
    /* Optimization, if first element, just increment offset, makes removing a
     * lot from the start quick */
    arr->offset++;
  } else if (idx != arr->cnt - 1) {
    /* Must shift entire array if removing an element from the middle. Does
     * nothing if removing last element other than decrement count. */
    status = ci_array_move(arr, idx + arr->offset, idx + arr->offset + 1);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  arr->cnt--;
  return CI_SUCCESS;
}

ci_status_t ci_array_remove_at(ci_array_t *arr, size_t idx)
{
  void *ptr = ci_array_at(arr, idx);
  if (arr == NULL || ptr == NULL) {
    return CI_EFORMERR;
  }

  if (arr->destruct != NULL) {
    arr->destruct(ptr);
  }

  return ci_array_claim_at(NULL, 0, arr, idx);
}

ci_status_t ci_array_remove_first(ci_array_t *arr)
{
  return ci_array_remove_at(arr, 0);
}

ci_status_t ci_array_remove_last(ci_array_t *arr)
{
  size_t cnt = ci_array_len(arr);
  if (cnt == 0) {
    return CI_EFORMERR;
  }
  return ci_array_remove_at(arr, cnt - 1);
}
