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

/* Some systems might default to something low like 256 (NetBSD), lets define
 * this to assist.  Really, no one should be using select, but lets be safe
 * anyhow */
#define FD_SETSIZE 4096

#include "ci_private.h"
#include "ci_event.h"
#ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h>
#endif

/* All systems have select(), but not all have a way to wake, so we require
 * pipe() to wake the select() */
#if defined(HAVE_PIPE)

static ci_bool_t ci_evsys_select_init(ci_event_thread_t *e)
{
  e->ev_signal = ci_pipeevent_create(e);
  if (e->ev_signal == NULL) {
    return CI_FALSE; /* LCOV_EXCL_LINE: UntestablePath */
  }
  return CI_TRUE;
}

static void ci_evsys_select_destroy(ci_event_thread_t *e)
{
  (void)e;
}

static ci_bool_t ci_evsys_select_event_add(ci_event_t *event)
{
  (void)event;
  return CI_TRUE;
}

static void ci_evsys_select_event_del(ci_event_t *event)
{
  (void)event;
}

static void ci_evsys_select_event_mod(ci_event_t      *event,
                                        ci_event_flags_t new_flags)
{
  (void)event;
  (void)new_flags;
}

static size_t ci_evsys_select_wait(ci_event_thread_t *e,
                                     unsigned long        timeout_ms)
{
  size_t          num_fds = 0;
  ci_socket_t  *fdlist  = ci_htable_asvp_keys(e->ev_sock_handles, &num_fds);
  int             rv;
  size_t          cnt = 0;
  size_t          i;
  fd_set          read_fds;
  fd_set          write_fds;
  fd_set          except_fds;
  int             nfds = 0;
  struct timeval  tv;
  struct timeval *tout = NULL;

  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  FD_ZERO(&except_fds);

  for (i = 0; i < num_fds; i++) {
    const ci_event_t *ev =
      ci_htable_asvp_get_direct(e->ev_sock_handles, fdlist[i]);
    if (ev->flags & CI_EVENT_FLAG_READ) {
      FD_SET(ev->fd, &read_fds);
    }
    if (ev->flags & CI_EVENT_FLAG_WRITE) {
      FD_SET(ev->fd, &write_fds);
    }
    FD_SET(ev->fd, &except_fds);
    if (ev->fd + 1 > nfds) {
      nfds = ev->fd + 1;
    }
  }

  if (timeout_ms) {
    tv.tv_sec  = (int)(timeout_ms / 1000);
    tv.tv_usec = (int)((timeout_ms % 1000) * 1000);
    tout       = &tv;
  }

  rv = select(nfds, &read_fds, &write_fds, &except_fds, tout);
  if (rv > 0) {
    for (i = 0; i < num_fds; i++) {
      ci_event_t      *ev;
      ci_event_flags_t flags = 0;

      ev = ci_htable_asvp_get_direct(e->ev_sock_handles, fdlist[i]);
      if (ev == NULL || ev->cb == NULL) {
        continue; /* LCOV_EXCL_LINE: DefensiveCoding */
      }

      if (FD_ISSET(fdlist[i], &read_fds) || FD_ISSET(fdlist[i], &except_fds)) {
        flags |= CI_EVENT_FLAG_READ;
      }

      if (FD_ISSET(fdlist[i], &write_fds)) {
        flags |= CI_EVENT_FLAG_WRITE;
      }

      if (flags == 0) {
        continue;
      }

      cnt++;

      ev->cb(e, fdlist[i], ev->data, flags);
    }
  }

  ci_free(fdlist);

  return cnt;
}

const ci_event_sys_t ci_evsys_select = {
  "select",
  ci_evsys_select_init,
  ci_evsys_select_destroy,   /* NoOp */
  ci_evsys_select_event_add, /* NoOp */
  ci_evsys_select_event_del, /* NoOp */
  ci_evsys_select_event_mod, /* NoOp */
  ci_evsys_select_wait
};

#endif
