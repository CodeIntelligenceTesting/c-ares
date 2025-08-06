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
#ifdef HAVE_POLL_H
#  include <poll.h>
#endif

#if defined(HAVE_POLL)

static ci_bool_t ci_evsys_poll_init(ci_event_thread_t *e)
{
  e->ev_signal = ci_pipeevent_create(e);
  if (e->ev_signal == NULL) {
    return CI_FALSE; /* LCOV_EXCL_LINE: UntestablePath */
  }
  return CI_TRUE;
}

static void ci_evsys_poll_destroy(ci_event_thread_t *e)
{
  (void)e;
}

static ci_bool_t ci_evsys_poll_event_add(ci_event_t *event)
{
  (void)event;
  return CI_TRUE;
}

static void ci_evsys_poll_event_del(ci_event_t *event)
{
  (void)event;
}

static void ci_evsys_poll_event_mod(ci_event_t      *event,
                                      ci_event_flags_t new_flags)
{
  (void)event;
  (void)new_flags;
}

static size_t ci_evsys_poll_wait(ci_event_thread_t *e,
                                   unsigned long        timeout_ms)
{
  size_t         num_fds = 0;
  ci_socket_t *fdlist  = ci_htable_asvp_keys(e->ev_sock_handles, &num_fds);
  struct pollfd *pollfd  = NULL;
  int            rv;
  size_t         cnt = 0;
  size_t         i;

  if (fdlist != NULL && num_fds) {
    pollfd = ci_malloc_zero(sizeof(*pollfd) * num_fds);
    if (pollfd == NULL) {
      goto done; /* LCOV_EXCL_LINE: OutOfMemory */
    }
    for (i = 0; i < num_fds; i++) {
      const ci_event_t *ev =
        ci_htable_asvp_get_direct(e->ev_sock_handles, fdlist[i]);
      pollfd[i].fd = ev->fd;
      if (ev->flags & CI_EVENT_FLAG_READ) {
        pollfd[i].events |= POLLIN;
      }
      if (ev->flags & CI_EVENT_FLAG_WRITE) {
        pollfd[i].events |= POLLOUT;
      }
    }
  }
  ci_free(fdlist);

  rv = poll(pollfd, (nfds_t)num_fds, (timeout_ms == 0) ? -1 : (int)timeout_ms);
  if (rv <= 0) {
    goto done;
  }

  for (i = 0; pollfd != NULL && i < num_fds; i++) {
    ci_event_t      *ev;
    ci_event_flags_t flags = 0;

    if (pollfd[i].revents == 0) {
      continue;
    }

    cnt++;

    ev = ci_htable_asvp_get_direct(e->ev_sock_handles, pollfd[i].fd);
    if (ev == NULL || ev->cb == NULL) {
      continue; /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    if (pollfd[i].revents & (POLLERR | POLLHUP | POLLIN)) {
      flags |= CI_EVENT_FLAG_READ;
    }

    if (pollfd[i].revents & POLLOUT) {
      flags |= CI_EVENT_FLAG_WRITE;
    }

    ev->cb(e, pollfd[i].fd, ev->data, flags);
  }

done:
  ci_free(pollfd);
  return cnt;
}

const ci_event_sys_t ci_evsys_poll = { "poll",
                                           ci_evsys_poll_init,
                                           ci_evsys_poll_destroy,   /* NoOp */
                                           ci_evsys_poll_event_add, /* NoOp */
                                           ci_evsys_poll_event_del, /* NoOp */
                                           ci_evsys_poll_event_mod, /* NoOp */
                                           ci_evsys_poll_wait };

#endif
