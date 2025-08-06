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

#ifdef CI_THREADS
#  ifdef _WIN32

struct ci_thread_mutex {
  CRITICAL_SECTION mutex;
};

ci_thread_mutex_t *ci_thread_mutex_create(void)
{
  ci_thread_mutex_t *mut = ci_malloc_zero(sizeof(*mut));
  if (mut == NULL) {
    return NULL;
  }

  InitializeCriticalSection(&mut->mutex);
  return mut;
}

void ci_thread_mutex_destroy(ci_thread_mutex_t *mut)
{
  if (mut == NULL) {
    return;
  }
  DeleteCriticalSection(&mut->mutex);
  ci_free(mut);
}

void ci_thread_mutex_lock(ci_thread_mutex_t *mut)
{
  if (mut == NULL) {
    return;
  }
  EnterCriticalSection(&mut->mutex);
}

void ci_thread_mutex_unlock(ci_thread_mutex_t *mut)
{
  if (mut == NULL) {
    return;
  }
  LeaveCriticalSection(&mut->mutex);
}

struct ci_thread_cond {
  CONDITION_VARIABLE cond;
};

ci_thread_cond_t *ci_thread_cond_create(void)
{
  ci_thread_cond_t *cond = ci_malloc_zero(sizeof(*cond));
  if (cond == NULL) {
    return NULL;
  }
  InitializeConditionVariable(&cond->cond);
  return cond;
}

void ci_thread_cond_destroy(ci_thread_cond_t *cond)
{
  if (cond == NULL) {
    return;
  }
  ci_free(cond);
}

void ci_thread_cond_signal(ci_thread_cond_t *cond)
{
  if (cond == NULL) {
    return;
  }
  WakeConditionVariable(&cond->cond);
}

void ci_thread_cond_broadcast(ci_thread_cond_t *cond)
{
  if (cond == NULL) {
    return;
  }
  WakeAllConditionVariable(&cond->cond);
}

ci_status_t ci_thread_cond_wait(ci_thread_cond_t  *cond,
                                    ci_thread_mutex_t *mut)
{
  if (cond == NULL || mut == NULL) {
    return CI_EFORMERR;
  }

  SleepConditionVariableCS(&cond->cond, &mut->mutex, INFINITE);
  return CI_SUCCESS;
}

ci_status_t ci_thread_cond_timedwait(ci_thread_cond_t  *cond,
                                         ci_thread_mutex_t *mut,
                                         unsigned long        timeout_ms)
{
  if (cond == NULL || mut == NULL) {
    return CI_EFORMERR;
  }

  if (!SleepConditionVariableCS(&cond->cond, &mut->mutex, timeout_ms)) {
    return CI_ETIMEOUT;
  }

  return CI_SUCCESS;
}

struct ci_thread {
  HANDLE thread;
  DWORD  id;

  void *(*func)(void *arg);
  void *arg;
  void *rv;
};

/* Wrap for pthread compatibility */
static DWORD WINAPI ci_thread_func(LPVOID lpParameter)
{
  ci_thread_t *thread = lpParameter;

  thread->rv = thread->func(thread->arg);
  return 0;
}

ci_status_t ci_thread_create(ci_thread_t    **thread,
                                 ci_thread_func_t func, void *arg)
{
  ci_thread_t *thr = NULL;

  if (func == NULL || thread == NULL) {
    return CI_EFORMERR;
  }

  thr = ci_malloc_zero(sizeof(*thr));
  if (thr == NULL) {
    return CI_ENOMEM;
  }

  thr->func   = func;
  thr->arg    = arg;
  thr->thread = CreateThread(NULL, 0, ci_thread_func, thr, 0, &thr->id);
  if (thr->thread == NULL) {
    ci_free(thr);
    return CI_ESERVFAIL;
  }

  *thread = thr;
  return CI_SUCCESS;
}

ci_status_t ci_thread_join(ci_thread_t *thread, void **rv)
{
  ci_status_t status = CI_SUCCESS;

  if (thread == NULL) {
    return CI_EFORMERR;
  }

  if (WaitForSingleObject(thread->thread, INFINITE) != WAIT_OBJECT_0) {
    status = CI_ENOTFOUND;
  } else {
    CloseHandle(thread->thread);
  }

  if (status == CI_SUCCESS && rv != NULL) {
    *rv = thread->rv;
  }
  ci_free(thread);

  return status;
}

#  else /* !WIN32 == PTHREAD */
#    include <pthread.h>

/* for clock_gettime() */
#    ifdef HAVE_TIME_H
#      include <time.h>
#    endif

/* for gettimeofday() */
#    ifdef HAVE_SYS_TIME_H
#      include <sys/time.h>
#    endif

struct ci_thread_mutex {
  pthread_mutex_t mutex;
};

ci_thread_mutex_t *ci_thread_mutex_create(void)
{
  pthread_mutexattr_t  attr;
  ci_thread_mutex_t *mut = ci_malloc_zero(sizeof(*mut));
  if (mut == NULL) {
    return NULL;
  }

  if (pthread_mutexattr_init(&attr) != 0) {
    ci_free(mut); /* LCOV_EXCL_LINE: UntestablePath */
    return NULL;    /* LCOV_EXCL_LINE: UntestablePath */
  }

  if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
    goto fail; /* LCOV_EXCL_LINE: UntestablePath */
  }

  if (pthread_mutex_init(&mut->mutex, &attr) != 0) {
    goto fail; /* LCOV_EXCL_LINE: UntestablePath */
  }

  pthread_mutexattr_destroy(&attr);
  return mut;

/* LCOV_EXCL_START: UntestablePath */
fail:
  pthread_mutexattr_destroy(&attr);
  ci_free(mut);
  return NULL;
  /* LCOV_EXCL_STOP */
}

void ci_thread_mutex_destroy(ci_thread_mutex_t *mut)
{
  if (mut == NULL) {
    return;
  }
  pthread_mutex_destroy(&mut->mutex);
  ci_free(mut);
}

void ci_thread_mutex_lock(ci_thread_mutex_t *mut)
{
  if (mut == NULL) {
    return;
  }
  pthread_mutex_lock(&mut->mutex);
}

void ci_thread_mutex_unlock(ci_thread_mutex_t *mut)
{
  if (mut == NULL) {
    return;
  }
  pthread_mutex_unlock(&mut->mutex);
}

struct ci_thread_cond {
  pthread_cond_t cond;
};

ci_thread_cond_t *ci_thread_cond_create(void)
{
  ci_thread_cond_t *cond = ci_malloc_zero(sizeof(*cond));
  if (cond == NULL) {
    return NULL;
  }
  pthread_cond_init(&cond->cond, NULL);
  return cond;
}

void ci_thread_cond_destroy(ci_thread_cond_t *cond)
{
  if (cond == NULL) {
    return;
  }
  pthread_cond_destroy(&cond->cond);
  ci_free(cond);
}

void ci_thread_cond_signal(ci_thread_cond_t *cond)
{
  if (cond == NULL) {
    return;
  }
  pthread_cond_signal(&cond->cond);
}

void ci_thread_cond_broadcast(ci_thread_cond_t *cond)
{
  if (cond == NULL) {
    return;
  }
  pthread_cond_broadcast(&cond->cond);
}

ci_status_t ci_thread_cond_wait(ci_thread_cond_t  *cond,
                                    ci_thread_mutex_t *mut)
{
  if (cond == NULL || mut == NULL) {
    return CI_EFORMERR;
  }

  pthread_cond_wait(&cond->cond, &mut->mutex);
  return CI_SUCCESS;
}

static void ci_timespec_timeout(struct timespec *ts, unsigned long add_ms)
{
#    if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_REALTIME)
  clock_gettime(CLOCK_REALTIME, ts);
#    elif defined(HAVE_GETTIMEOFDAY)
  struct timeval tv;
  gettimeofday(&tv, NULL);
  ts->tv_sec  = tv.tv_sec;
  ts->tv_nsec = tv.tv_usec * 1000;
#    else
#      error cannot determine current system time
#    endif

  ts->tv_sec  += (time_t)(add_ms / 1000);
  ts->tv_nsec += (long)((add_ms % 1000) * 1000000);

  /* Normalize if needed */
  if (ts->tv_nsec >= 1000000000) {
    ts->tv_sec  += ts->tv_nsec / 1000000000;
    ts->tv_nsec %= 1000000000;
  }
}

ci_status_t ci_thread_cond_timedwait(ci_thread_cond_t  *cond,
                                         ci_thread_mutex_t *mut,
                                         unsigned long        timeout_ms)
{
  struct timespec ts;

  if (cond == NULL || mut == NULL) {
    return CI_EFORMERR;
  }

  ci_timespec_timeout(&ts, timeout_ms);

  if (pthread_cond_timedwait(&cond->cond, &mut->mutex, &ts) != 0) {
    return CI_ETIMEOUT;
  }

  return CI_SUCCESS;
}

struct ci_thread {
  pthread_t thread;
};

ci_status_t ci_thread_create(ci_thread_t    **thread,
                                 ci_thread_func_t func, void *arg)
{
  ci_thread_t *thr = NULL;

  if (func == NULL || thread == NULL) {
    return CI_EFORMERR;
  }

  thr = ci_malloc_zero(sizeof(*thr));
  if (thr == NULL) {
    return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  if (pthread_create(&thr->thread, NULL, func, arg) != 0) {
    ci_free(thr);        /* LCOV_EXCL_LINE: UntestablePath */
    return CI_ESERVFAIL; /* LCOV_EXCL_LINE: UntestablePath */
  }

  *thread = thr;
  return CI_SUCCESS;
}

ci_status_t ci_thread_join(ci_thread_t *thread, void **rv)
{
  void         *ret    = NULL;
  ci_status_t status = CI_SUCCESS;

  if (thread == NULL) {
    return CI_EFORMERR;
  }

  if (pthread_join(thread->thread, &ret) != 0) {
    status = CI_ENOTFOUND;
  }
  ci_free(thread);

  if (status == CI_SUCCESS && rv != NULL) {
    *rv = ret;
  }
  return status;
}

#  endif

ci_bool_t ci_threadsafety(void)
{
  return CI_TRUE;
}

#else /* !CI_THREADS */

/* NoOp */
ci_thread_mutex_t *ci_thread_mutex_create(void)
{
  return NULL;
}

void ci_thread_mutex_destroy(ci_thread_mutex_t *mut)
{
  (void)mut;
}

void ci_thread_mutex_lock(ci_thread_mutex_t *mut)
{
  (void)mut;
}

void ci_thread_mutex_unlock(ci_thread_mutex_t *mut)
{
  (void)mut;
}

ci_thread_cond_t *ci_thread_cond_create(void)
{
  return NULL;
}

void ci_thread_cond_destroy(ci_thread_cond_t *cond)
{
  (void)cond;
}

void ci_thread_cond_signal(ci_thread_cond_t *cond)
{
  (void)cond;
}

void ci_thread_cond_broadcast(ci_thread_cond_t *cond)
{
  (void)cond;
}

ci_status_t ci_thread_cond_wait(ci_thread_cond_t  *cond,
                                    ci_thread_mutex_t *mut)
{
  (void)cond;
  (void)mut;
  return CI_ENOTIMP;
}

ci_status_t ci_thread_cond_timedwait(ci_thread_cond_t  *cond,
                                         ci_thread_mutex_t *mut,
                                         unsigned long        timeout_ms)
{
  (void)cond;
  (void)mut;
  (void)timeout_ms;
  return CI_ENOTIMP;
}

ci_status_t ci_thread_create(ci_thread_t    **thread,
                                 ci_thread_func_t func, void *arg)
{
  (void)thread;
  (void)func;
  (void)arg;
  return CI_ENOTIMP;
}

ci_status_t ci_thread_join(ci_thread_t *thread, void **rv)
{
  (void)thread;
  (void)rv;
  return CI_ENOTIMP;
}

ci_bool_t ci_threadsafety(void)
{
  return CI_FALSE;
}
#endif


ci_status_t ci_channel_threading_init(ci_channel_t *channel)
{
  ci_status_t status = CI_SUCCESS;

  /* Threading is optional! */
  if (!ci_threadsafety()) {
    return CI_SUCCESS;
  }

  channel->lock = ci_thread_mutex_create();
  if (channel->lock == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  channel->cond_empty = ci_thread_cond_create();
  if (channel->cond_empty == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

done:
  if (status != CI_SUCCESS) {
    ci_channel_threading_destroy(channel);
  }
  return status;
}

void ci_channel_threading_destroy(ci_channel_t *channel)
{
  ci_thread_mutex_destroy(channel->lock);
  channel->lock = NULL;
  ci_thread_cond_destroy(channel->cond_empty);
  channel->cond_empty = NULL;
}

void ci_channel_lock(const ci_channel_t *channel)
{
  ci_thread_mutex_lock(channel->lock);
}

void ci_channel_unlock(const ci_channel_t *channel)
{
  ci_thread_mutex_unlock(channel->lock);
}

/* Must not be holding a channel lock already, public function only */
ci_status_t ci_queue_wait_empty(ci_channel_t *channel, int timeout_ms)
{
  ci_status_t  status = CI_SUCCESS;
  ci_timeval_t tout;

  if (!ci_threadsafety()) {
    return CI_ENOTIMP;
  }

  if (channel == NULL) {
    return CI_EFORMERR;
  }

  if (timeout_ms >= 0) {
    ci_tvnow(&tout);
    tout.sec  += (ci_int64_t)(timeout_ms / 1000);
    tout.usec += (unsigned int)(timeout_ms % 1000) * 1000;
  }

  ci_thread_mutex_lock(channel->lock);
  while (ci_llist_len(channel->all_queries)) {
    if (timeout_ms < 0) {
      ci_thread_cond_wait(channel->cond_empty, channel->lock);
    } else {
      ci_timeval_t tv_remaining;
      ci_timeval_t tv_now;
      unsigned long  tms;

      ci_tvnow(&tv_now);
      ci_timeval_remaining(&tv_remaining, &tv_now, &tout);
      tms =
        (unsigned long)((tv_remaining.sec * 1000) + (tv_remaining.usec / 1000));
      if (tms == 0) {
        status = CI_ETIMEOUT;
      } else {
        status =
          ci_thread_cond_timedwait(channel->cond_empty, channel->lock, tms);
      }

      /* If there was a timeout, don't loop.  Otherwise, make sure this wasn't
       * a spurious wakeup by looping and checking the condition. */
      if (status == CI_ETIMEOUT) {
        break;
      }
    }
  }
  ci_thread_mutex_unlock(channel->lock);
  return status;
}

void ci_queue_notify_empty(ci_channel_t *channel)
{
  if (channel == NULL) {
    return;
  }

  /* We are guaranteed to be holding a channel lock already */
  if (ci_llist_len(channel->all_queries)) {
    return;
  }

  /* Notify all waiters of the conditional */
  ci_thread_cond_broadcast(channel->cond_empty);
}
