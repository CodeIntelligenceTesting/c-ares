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
#ifndef __CI__EVENT_H
#define __CI__EVENT_H

struct ci_event;
typedef struct ci_event ci_event_t;

typedef enum {
  CI_EVENT_FLAG_NONE  = 0,
  CI_EVENT_FLAG_READ  = 1 << 0,
  CI_EVENT_FLAG_WRITE = 1 << 1,
  CI_EVENT_FLAG_OTHER = 1 << 2
} ci_event_flags_t;

typedef void (*ci_event_cb_t)(ci_event_thread_t *e, ci_socket_t fd,
                                void *data, ci_event_flags_t flags);

typedef void (*ci_event_free_data_t)(void *data);

typedef void (*ci_event_signal_cb_t)(const ci_event_t *event);

struct ci_event {
  /*! Registered event thread this event is bound to */
  ci_event_thread_t   *e;
  /*! Flags to monitor. OTHER is only allowed if the socket is CI_SOCKET_BAD.
   */
  ci_event_flags_t     flags;
  /*! Callback to be called when event is triggered */
  ci_event_cb_t        cb;
  /*! Socket to monitor, allowed to be CI_SOCKET_BAD if not monitoring a
   *  socket. */
  ci_socket_t          fd;
  /*! Data associated with event handle that will be passed to the callback.
   *  Typically OS/event subsystem specific data.
   *  Optional, may be NULL. */
  /*! Data to be passed to callback. Optional, may be NULL. */
  void                  *data;
  /*! When cleaning up the registered event (either when removed or during
   *  shutdown), this function will be called to clean up the user-supplied
   *  data. Optional, May be NULL. */
  ci_event_free_data_t free_data_cb;
  /*! Callback to call to trigger an event. */
  ci_event_signal_cb_t signal_cb;
};

typedef struct {
  const char *name;
  ci_bool_t (*init)(ci_event_thread_t *e);
  void (*destroy)(ci_event_thread_t *e);
  ci_bool_t (*event_add)(ci_event_t *event);
  void (*event_del)(ci_event_t *event);
  void (*event_mod)(ci_event_t *event, ci_event_flags_t new_flags);
  size_t (*wait)(ci_event_thread_t *e, unsigned long timeout_ms);
} ci_event_sys_t;

struct ci_event_configchg;
typedef struct ci_event_configchg ci_event_configchg_t;

ci_status_t ci_event_configchg_init(ci_event_configchg_t **configchg,
                                        ci_event_thread_t     *e);

void          ci_event_configchg_destroy(ci_event_configchg_t *configchg);

struct ci_event_thread {
  /*! Whether the event thread should be online or not.  Checked on every wake
   *  event before sleeping. */
  ci_bool_t             isup;
  /*! Handle to the thread for joining during shutdown */
  ci_thread_t          *thread;
  /*! Lock to protect the data contained within the event thread itself */
  ci_thread_mutex_t    *mutex;
  /*! Reference to the ci channel, for being able to call things like
   *  ci_timeout() and ci_process_fd(). */
  ci_channel_t         *channel;
  /*! Whether or not on the next loop we should process a pending write */
  ci_bool_t             process_pending_write;
  /*! Not-yet-processed event handle updates.  These will get enqueued by a
   *  thread other than the event thread itself. The event thread will then
   *  be woken then process these updates itself */
  ci_llist_t           *ev_updates;
  /*! Registered socket event handles */
  ci_htable_asvp_t     *ev_sock_handles;
  /*! Registered custom event handles. Typically used for external triggering.
   */
  ci_htable_vpvp_t     *ev_cust_handles;
  /*! Pointer to the event handle which is used to signal and wake the event
   *  thread itself.  This is needed to be able to do things like update the
   *  file descriptors being waited on and to wake the event subsystem during
   *  shutdown */
  ci_event_t           *ev_signal;
  /*! Handle for configuration change monitoring */
  ci_event_configchg_t *configchg;
  /* Event subsystem callbacks */
  const ci_event_sys_t *ev_sys;
  /* Event subsystem private data */
  void                   *ev_sys_data;
};

/*! Queue an update for the event handle.
 *
 *  Will search by the fd passed if not CI_SOCKET_BAD to find a match and
 *  perform an update or delete (depending on flags).  Otherwise will add.
 *  Do not use the event handle returned if its not guaranteed to be an add
 *  operation.
 *
 *  \param[out] event        Event handle. Optional, can be NULL.  This handle
 *                           will be invalidate quickly if the result of the
 *                           operation is not an ADD.
 *  \param[in]  e            pointer to event thread handle
 *  \param[in]  flags        flags for the event handle.  Use
 *                           CI_EVENT_FLAG_NONE if removing a socket from
 *                           queue (not valid if socket is CI_SOCKET_BAD).
 *                           Non-socket events cannot be removed, and must have
 *                           CI_EVENT_FLAG_OTHER set.
 *  \param[in]  cb           Callback to call when
 *                           event is triggered. Required if flags is not
 *                           CI_EVENT_FLAG_NONE. Not allowed to be
 *                           changed, ignored on modification.
 *  \param[in]  fd           File descriptor/socket to monitor. May
 *                           be CI_SOCKET_BAD if not monitoring file
 *                           descriptor.
 *  \param[in]  data         Optional. Caller-supplied data to be passed to
 *                           callback. Only allowed on initial add, cannot be
 *                           modified later, ignored on modification.
 *  \param[in]  free_data_cb Optional. Callback to clean up caller-supplied
 *                           data. Only allowed on initial add, cannot be
 *                           modified later, ignored on modification.
 *  \param[in]  signal_cb    Optional. Callback to call to trigger an event.
 *  \return CI_SUCCESS on success
 */
ci_status_t ci_event_update(ci_event_t **event, ci_event_thread_t *e,
                                ci_event_flags_t flags, ci_event_cb_t cb,
                                ci_socket_t fd, void *data,
                                ci_event_free_data_t free_data_cb,
                                ci_event_signal_cb_t signal_cb);


#ifdef HAVE_PIPE
ci_event_t *ci_pipeevent_create(ci_event_thread_t *e);
#endif

#ifdef HAVE_POLL
extern const ci_event_sys_t ci_evsys_poll;
#endif

#ifdef HAVE_KQUEUE
extern const ci_event_sys_t ci_evsys_kqueue;
#endif

#ifdef HAVE_EPOLL
extern const ci_event_sys_t ci_evsys_epoll;
#endif

#ifdef _WIN32
extern const ci_event_sys_t ci_evsys_win32;
#endif

/* All systems have select(), but not all have a way to wake, so we require
 * pipe() to wake the select() */
#ifdef HAVE_PIPE
extern const ci_event_sys_t ci_evsys_select;
#endif

#endif
