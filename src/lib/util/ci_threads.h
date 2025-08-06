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
#ifndef __CI__THREADS_H
#define __CI__THREADS_H

struct ci_thread_mutex;
typedef struct ci_thread_mutex ci_thread_mutex_t;

ci_thread_mutex_t             *ci_thread_mutex_create(void);
void ci_thread_mutex_destroy(ci_thread_mutex_t *mut);
void ci_thread_mutex_lock(ci_thread_mutex_t *mut);
void ci_thread_mutex_unlock(ci_thread_mutex_t *mut);


struct ci_thread_cond;
typedef struct ci_thread_cond ci_thread_cond_t;

ci_thread_cond_t             *ci_thread_cond_create(void);
void          ci_thread_cond_destroy(ci_thread_cond_t *cond);
void          ci_thread_cond_signal(ci_thread_cond_t *cond);
void          ci_thread_cond_broadcast(ci_thread_cond_t *cond);
ci_status_t ci_thread_cond_wait(ci_thread_cond_t  *cond,
                                    ci_thread_mutex_t *mut);
ci_status_t ci_thread_cond_timedwait(ci_thread_cond_t  *cond,
                                         ci_thread_mutex_t *mut,
                                         unsigned long        timeout_ms);


struct ci_thread;
typedef struct ci_thread ci_thread_t;

typedef void *(*ci_thread_func_t)(void *arg);
ci_status_t ci_thread_create(ci_thread_t    **thread,
                                 ci_thread_func_t func, void *arg);
ci_status_t ci_thread_join(ci_thread_t *thread, void **rv);

#endif
