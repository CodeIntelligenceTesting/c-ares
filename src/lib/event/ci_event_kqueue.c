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
#include "ci_event.h"

#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_EVENT_H
#  include <sys/event.h>
#endif
#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif

#ifdef HAVE_KQUEUE

typedef struct {
  int            kqueue_fd;
  struct kevent *changelist;
  size_t         nchanges;
  size_t         nchanges_alloc;
} ci_evsys_kqueue_t;

static void ci_evsys_kqueue_destroy(ci_event_thread_t *e)
{
  ci_evsys_kqueue_t *kq = NULL;

  if (e == NULL) {
    return;
  }

  kq = e->ev_sys_data;
  if (kq == NULL) {
    return;
  }

  if (kq->kqueue_fd != -1) {
    close(kq->kqueue_fd);
  }

  ci_free(kq->changelist);
  ci_free(kq);
  e->ev_sys_data = NULL;
}

static ci_bool_t ci_evsys_kqueue_init(ci_event_thread_t *e)
{
  ci_evsys_kqueue_t *kq = NULL;

  kq = ci_malloc_zero(sizeof(*kq));
  if (kq == NULL) {
    return CI_FALSE;
  }

  e->ev_sys_data = kq;

  kq->kqueue_fd = kqueue();
  if (kq->kqueue_fd == -1) {
    ci_evsys_kqueue_destroy(e);
    return CI_FALSE;
  }

#  ifdef FD_CLOEXEC
  fcntl(kq->kqueue_fd, F_SETFD, FD_CLOEXEC);
#  endif

  kq->nchanges_alloc = 8;
  kq->changelist =
    ci_malloc_zero(kq->nchanges_alloc * sizeof(*kq->changelist));
  if (kq->changelist == NULL) {
    ci_evsys_kqueue_destroy(e);
    return CI_FALSE;
  }

  e->ev_signal = ci_pipeevent_create(e);
  if (e->ev_signal == NULL) {
    ci_evsys_kqueue_destroy(e);
    return CI_FALSE;
  }

  return CI_TRUE;
}

static void ci_evsys_kqueue_enqueue(ci_evsys_kqueue_t *kq, int fd,
                                      int16_t filter, uint16_t flags)
{
  size_t idx;

  if (kq == NULL) {
    return;
  }

  idx = kq->nchanges;

  kq->nchanges++;

  if (kq->nchanges > kq->nchanges_alloc) {
    kq->nchanges_alloc <<= 1;
    kq->changelist       = ci_realloc_zero(
      kq->changelist, (kq->nchanges_alloc >> 1) * sizeof(*kq->changelist),
      kq->nchanges_alloc * sizeof(*kq->changelist));
  }

  EV_SET(&kq->changelist[idx], fd, filter, flags, 0, 0, 0);
}

static void ci_evsys_kqueue_event_process(ci_event_t      *event,
                                            ci_event_flags_t old_flags,
                                            ci_event_flags_t new_flags)
{
  ci_event_thread_t *e = event->e;
  ci_evsys_kqueue_t *kq;

  if (e == NULL) {
    return;
  }

  kq = e->ev_sys_data;
  if (kq == NULL) {
    return;
  }

  if (new_flags & CI_EVENT_FLAG_READ && !(old_flags & CI_EVENT_FLAG_READ)) {
    ci_evsys_kqueue_enqueue(kq, event->fd, EVFILT_READ, EV_ADD | EV_ENABLE);
  }

  if (!(new_flags & CI_EVENT_FLAG_READ) && old_flags & CI_EVENT_FLAG_READ) {
    ci_evsys_kqueue_enqueue(kq, event->fd, EVFILT_READ, EV_DELETE);
  }

  if (new_flags & CI_EVENT_FLAG_WRITE &&
      !(old_flags & CI_EVENT_FLAG_WRITE)) {
    ci_evsys_kqueue_enqueue(kq, event->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE);
  }

  if (!(new_flags & CI_EVENT_FLAG_WRITE) &&
      old_flags & CI_EVENT_FLAG_WRITE) {
    ci_evsys_kqueue_enqueue(kq, event->fd, EVFILT_WRITE, EV_DELETE);
  }
}

static ci_bool_t ci_evsys_kqueue_event_add(ci_event_t *event)
{
  ci_evsys_kqueue_event_process(event, 0, event->flags);
  return CI_TRUE;
}

static void ci_evsys_kqueue_event_del(ci_event_t *event)
{
  ci_evsys_kqueue_event_process(event, event->flags, 0);
}

static void ci_evsys_kqueue_event_mod(ci_event_t      *event,
                                        ci_event_flags_t new_flags)
{
  ci_evsys_kqueue_event_process(event, event->flags, new_flags);
}

static size_t ci_evsys_kqueue_wait(ci_event_thread_t *e,
                                     unsigned long        timeout_ms)
{
  struct kevent        events[8];
  size_t               nevents = sizeof(events) / sizeof(*events);
  ci_evsys_kqueue_t *kq      = e->ev_sys_data;
  int                  rv;
  size_t               i;
  struct timespec      ts;
  struct timespec     *timeout = NULL;
  size_t               cnt     = 0;

  if (timeout_ms != 0) {
    ts.tv_sec  = (time_t)timeout_ms / 1000;
    ts.tv_nsec = (timeout_ms % 1000) * 1000 * 1000;
    timeout    = &ts;
  }

  memset(events, 0, sizeof(events));

  rv = kevent(kq->kqueue_fd, kq->changelist, (int)kq->nchanges, events,
              (int)nevents, timeout);
  if (rv < 0) {
    return 0;
  }

  /* Changelist was consumed */
  kq->nchanges = 0;
  nevents      = (size_t)rv;

  for (i = 0; i < nevents; i++) {
    ci_event_t      *ev;
    ci_event_flags_t flags = 0;

    ev = ci_htable_asvp_get_direct(e->ev_sock_handles,
                                     (ci_socket_t)events[i].ident);
    if (ev == NULL || ev->cb == NULL) {
      continue;
    }

    cnt++;

    if (events[i].filter == EVFILT_READ ||
        events[i].flags & (EV_EOF | EV_ERROR)) {
      flags |= CI_EVENT_FLAG_READ;
    } else {
      flags |= CI_EVENT_FLAG_WRITE;
    }

    ev->cb(e, ev->fd, ev->data, flags);
  }

  return cnt;
}

const ci_event_sys_t ci_evsys_kqueue = { "kqueue",
                                             ci_evsys_kqueue_init,
                                             ci_evsys_kqueue_destroy,
                                             ci_evsys_kqueue_event_add,
                                             ci_evsys_kqueue_event_del,
                                             ci_evsys_kqueue_event_mod,
                                             ci_evsys_kqueue_wait };
#endif
