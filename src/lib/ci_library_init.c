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

/* library-private global and unique instance vars */

#if defined(ANDROID) || defined(__ANDROID__)
#  include "ci_android.h"
#endif

/* library-private global vars with source visibility restricted to this file */

static unsigned int ci_initialized;
static int          ci_init_flags;

/* library-private global vars with visibility across the whole library */

/* Some systems may return either NULL or a valid pointer on malloc(0).  c-ci
 * should never call malloc(0) so lets return NULL so we're more likely to find
 * an issue if it were to occur. */

static void        *default_malloc(size_t size)
{
  if (size == 0) {
    return NULL;
  }
  return malloc(size);
}

static void *default_realloc(void *p, size_t size)
{
  return realloc(p, size);
}

static void default_free(void *p)
{
  free(p);
}

static void *(*__ci_malloc)(size_t size)             = default_malloc;
static void *(*__ci_realloc)(void *ptr, size_t size) = default_realloc;
static void (*__ci_free)(void *ptr)                  = default_free;

void *ci_malloc(size_t size)
{
  return __ci_malloc(size);
}

void *ci_realloc(void *ptr, size_t size)
{
  return __ci_realloc(ptr, size);
}

void ci_free(void *ptr)
{
  __ci_free(ptr);
}

void *ci_malloc_zero(size_t size)
{
  void *ptr = ci_malloc(size);
  if (ptr != NULL) {
    memset(ptr, 0, size);
  }

  return ptr;
}

void *ci_realloc_zero(void *ptr, size_t orig_size, size_t new_size)
{
  void *p = ci_realloc(ptr, new_size);
  if (p == NULL) {
    return NULL;
  }

  if (new_size > orig_size) {
    memset((unsigned char *)p + orig_size, 0, new_size - orig_size);
  }

  return p;
}

int ci_library_init(int flags)
{
  if (ci_initialized) {
    ci_initialized++;
    return CI_SUCCESS;
  }
  ci_initialized++;

  /* NOTE: CI_LIB_INIT_WIN32 flag no longer used */

  ci_init_flags = flags;

  return CI_SUCCESS;
}

int ci_library_init_mem(int flags, void *(*amalloc)(size_t size),
                          void (*afree)(void *ptr),
                          void *(*arealloc)(void *ptr, size_t size))
{
  if (amalloc) {
    __ci_malloc = amalloc;
  }
  if (arealloc) {
    __ci_realloc = arealloc;
  }
  if (afree) {
    __ci_free = afree;
  }
  return ci_library_init(flags);
}

void ci_library_cleanup(void)
{
  if (!ci_initialized) {
    return;
  }
  ci_initialized--;
  if (ci_initialized) {
    return;
  }

  /* NOTE: CI_LIB_INIT_WIN32 flag no longer used */

#if defined(ANDROID) || defined(__ANDROID__)
  ci_library_cleanup_android();
#endif

  ci_init_flags = CI_LIB_INIT_NONE;
  __ci_malloc   = default_malloc;
  __ci_realloc  = default_realloc;
  __ci_free     = default_free;
}

int ci_library_initialized(void)
{
#ifdef USE_WINSOCK
  if (!ci_initialized) {
    return CI_ENOTINITIALIZED;
  }
#endif
  return CI_SUCCESS;
}
