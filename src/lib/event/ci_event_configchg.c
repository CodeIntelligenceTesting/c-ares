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

#ifdef __ANDROID__

ci_status_t ci_event_configchg_init(ci_event_configchg_t **configchg,
                                        ci_event_thread_t     *e)
{
  (void)configchg;
  (void)e;
  /* No ability */
  return CI_ENOTIMP;
}

void ci_event_configchg_destroy(ci_event_configchg_t *configchg)
{
  /* No-op */
  (void)configchg;
}

#elif defined(__linux__)

#  include <sys/inotify.h>

struct ci_event_configchg {
  int                  inotify_fd;
  ci_event_thread_t *e;
};

void ci_event_configchg_destroy(ci_event_configchg_t *configchg)
{
  if (configchg == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* Tell event system to stop monitoring for changes.  This will cause the
   * cleanup to be called */
  ci_event_update(NULL, configchg->e, CI_EVENT_FLAG_NONE, NULL,
                    configchg->inotify_fd, NULL, NULL, NULL);
}

static void ci_event_configchg_free(void *data)
{
  ci_event_configchg_t *configchg = data;
  if (configchg == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (configchg->inotify_fd >= 0) {
    close(configchg->inotify_fd);
    configchg->inotify_fd = -1;
  }

  ci_free(configchg);
}

static void ci_event_configchg_cb(ci_event_thread_t *e, ci_socket_t fd,
                                    void *data, ci_event_flags_t flags)
{
  const ci_event_configchg_t *configchg = data;

  /* Some systems cannot read integer variables if they are not
   * properly aligned. On other systems, incorrect alignment may
   * decrease performance. Hence, the buffer used for reading from
   * the inotify file descriptor should have the same alignment as
   * struct inotify_event. */
  unsigned char                 buf[4096]
    __attribute__((aligned(__alignof__(struct inotify_event))));
  const struct inotify_event *event;
  ssize_t                     len;
  ci_bool_t                 triggered = CI_FALSE;

  (void)fd;
  (void)flags;

  while (1) {
    const unsigned char *ptr;

    len = read(configchg->inotify_fd, buf, sizeof(buf));
    if (len <= 0) {
      break;
    }

    /* Loop over all events in the buffer. Says kernel will check the buffer
     * size provided, so I assume it won't ever return partial events. */
    for (ptr  = buf; ptr < buf + len;
         ptr += sizeof(struct inotify_event) + event->len) {
      event = (const struct inotify_event *)((const void *)ptr);

      if (event->len == 0 || ci_strlen(event->name) == 0) {
        continue;
      }

      if (ci_strcaseeq(event->name, "resolv.conf") ||
          ci_strcaseeq(event->name, "nsswitch.conf")) {
        triggered = CI_TRUE;
      }
    }
  }

  /* Only process after all events are read.  No need to process more often as
   * we don't want to reload the config back to back */
  if (triggered) {
    ci_reinit(e->channel);
  }
}

ci_status_t ci_event_configchg_init(ci_event_configchg_t **configchg,
                                        ci_event_thread_t     *e)
{
  ci_status_t           status = CI_SUCCESS;
  ci_event_configchg_t *c;

  (void)e;

  /* Not used by this implementation */
  *configchg = NULL;

  c = ci_malloc_zero(sizeof(*c));
  if (c == NULL) {
    return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  c->e          = e;
  c->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (c->inotify_fd == -1) {
    status = CI_ESERVFAIL; /* LCOV_EXCL_LINE: UntestablePath */
    goto done;               /* LCOV_EXCL_LINE: UntestablePath */
  }

  /* We need to monitor /etc/resolv.conf, /etc/nsswitch.conf */
  if (inotify_add_watch(c->inotify_fd, "/etc",
                        IN_CREATE | IN_MODIFY | IN_MOVED_TO | IN_ONLYDIR) ==
      -1) {
    status = CI_ESERVFAIL; /* LCOV_EXCL_LINE: UntestablePath */
    goto done;               /* LCOV_EXCL_LINE: UntestablePath */
  }

  status =
    ci_event_update(NULL, e, CI_EVENT_FLAG_READ, ci_event_configchg_cb,
                      c->inotify_fd, c, ci_event_configchg_free, NULL);

done:
  if (status != CI_SUCCESS) {
    ci_event_configchg_free(c);
  } else {
    *configchg = c;
  }
  return status;
}

#elif defined(USE_WINSOCK)

#  include <winsock2.h>
#  include <iphlpapi.h>
#  include <stdio.h>
#  include <windows.h>

struct ci_event_configchg {
  HANDLE               ifchg_hnd;
  HKEY                 regip4;
  HANDLE               regip4_event;
  HANDLE               regip4_wait;
  HKEY                 regip6;
  HANDLE               regip6_event;
  HANDLE               regip6_wait;
  ci_event_thread_t *e;
};

void ci_event_configchg_destroy(ci_event_configchg_t *configchg)
{
  if (configchg == NULL) {
    return;
  }

#  ifdef HAVE_NOTIFYIPINTERFACECHANGE
  if (configchg->ifchg_hnd != NULL) {
    CancelMibChangeNotify2(configchg->ifchg_hnd);
    configchg->ifchg_hnd = NULL;
  }
#  endif

#  ifdef HAVE_REGISTERWAITFORSINGLEOBJECT
  if (configchg->regip4_wait != NULL) {
    UnregisterWait(configchg->regip4_wait);
    configchg->regip4_wait = NULL;
  }

  if (configchg->regip6_wait != NULL) {
    UnregisterWait(configchg->regip6_wait);
    configchg->regip6_wait = NULL;
  }

  if (configchg->regip4 != NULL) {
    RegCloseKey(configchg->regip4);
    configchg->regip4 = NULL;
  }

  if (configchg->regip6 != NULL) {
    RegCloseKey(configchg->regip6);
    configchg->regip6 = NULL;
  }

  if (configchg->regip4_event != NULL) {
    CloseHandle(configchg->regip4_event);
    configchg->regip4_event = NULL;
  }

  if (configchg->regip6_event != NULL) {
    CloseHandle(configchg->regip6_event);
    configchg->regip6_event = NULL;
  }
#  endif

  ci_free(configchg);
}


#  ifdef HAVE_NOTIFYIPINTERFACECHANGE
static void NETIOAPI_API_
  ci_event_configchg_ip_cb(PVOID CallerContext, PMIB_IPINTERFACE_ROW Row,
                             MIB_NOTIFICATION_TYPE NotificationType)
{
  ci_event_configchg_t *configchg = CallerContext;
  (void)Row;
  (void)NotificationType;
  ci_reinit(configchg->e->channel);
}
#  endif

static ci_bool_t
  ci_event_configchg_regnotify(ci_event_configchg_t *configchg)
{
#  ifdef HAVE_REGISTERWAITFORSINGLEOBJECT
#    if defined(__WATCOMC__) && !defined(REG_NOTIFY_THREAD_AGNOSTIC)
#      define REG_NOTIFY_THREAD_AGNOSTIC 0x10000000L
#    endif
  DWORD flags = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET |
                REG_NOTIFY_THREAD_AGNOSTIC;

  if (RegNotifyChangeKeyValue(configchg->regip4, TRUE, flags,
                              configchg->regip4_event, TRUE) != ERROR_SUCCESS) {
    return CI_FALSE;
  }

  if (RegNotifyChangeKeyValue(configchg->regip6, TRUE, flags,
                              configchg->regip6_event, TRUE) != ERROR_SUCCESS) {
    return CI_FALSE;
  }
#  else
  (void)configchg;
#  endif
  return CI_TRUE;
}

static VOID CALLBACK ci_event_configchg_reg_cb(PVOID   lpParameter,
                                                 BOOLEAN TimerOrWaitFired)
{
  ci_event_configchg_t *configchg = lpParameter;
  (void)TimerOrWaitFired;

  ci_reinit(configchg->e->channel);

  /* Re-arm, as its single-shot.  However, we don't know which one needs to
   * be re-armed, so we just do both */
  ci_event_configchg_regnotify(configchg);
}

ci_status_t ci_event_configchg_init(ci_event_configchg_t **configchg,
                                        ci_event_thread_t     *e)
{
  ci_status_t           status = CI_SUCCESS;
  ci_event_configchg_t *c      = NULL;

  c = ci_malloc_zero(sizeof(**configchg));
  if (c == NULL) {
    return CI_ENOMEM;
  }

  c->e = e;

#  ifdef HAVE_NOTIFYIPINTERFACECHANGE
  /* NOTE: If a user goes into the control panel and changes the network
   *       adapter DNS addresses manually, this will NOT trigger a notification.
   *       We've also tried listening on NotifyUnicastIpAddressChange(), but
   *       that didn't get triggered either.
   */
  if (NotifyIpInterfaceChange(AF_UNSPEC, ci_event_configchg_ip_cb, c, FALSE,
                              &c->ifchg_hnd) != NO_ERROR) {
    status = CI_ESERVFAIL;
    goto done;
  }
#  endif

#  ifdef HAVE_REGISTERWAITFORSINGLEOBJECT
  /* Monitor HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces
   * and HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
   * for changes via RegNotifyChangeKeyValue() */
  if (RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        0, KEY_NOTIFY, &c->regip4) != ERROR_SUCCESS) {
    status = CI_ESERVFAIL;
    goto done;
  }

  if (RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces",
        0, KEY_NOTIFY, &c->regip6) != ERROR_SUCCESS) {
    status = CI_ESERVFAIL;
    goto done;
  }

  c->regip4_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (c->regip4_event == NULL) {
    status = CI_ESERVFAIL;
    goto done;
  }

  c->regip6_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (c->regip6_event == NULL) {
    status = CI_ESERVFAIL;
    goto done;
  }

  if (!RegisterWaitForSingleObject(&c->regip4_wait, c->regip4_event,
                                   ci_event_configchg_reg_cb, c, INFINITE,
                                   WT_EXECUTEDEFAULT)) {
    status = CI_ESERVFAIL;
    goto done;
  }

  if (!RegisterWaitForSingleObject(&c->regip6_wait, c->regip6_event,
                                   ci_event_configchg_reg_cb, c, INFINITE,
                                   WT_EXECUTEDEFAULT)) {
    status = CI_ESERVFAIL;
    goto done;
  }
#  endif

  if (!ci_event_configchg_regnotify(c)) {
    status = CI_ESERVFAIL;
    goto done;
  }

done:
  if (status != CI_SUCCESS) {
    ci_event_configchg_destroy(c);
  } else {
    *configchg = c;
  }

  return status;
}

#elif defined(__APPLE__)

#  include <sys/types.h>
#  include <unistd.h>
#  include <notify.h>
#  include <dlfcn.h>
#  include <fcntl.h>

struct ci_event_configchg {
  int fd;
  int token;
};

void ci_event_configchg_destroy(ci_event_configchg_t *configchg)
{
  (void)configchg;

  /* Cleanup happens automatically */
}

static void ci_event_configchg_free(void *data)
{
  ci_event_configchg_t *configchg = data;
  if (configchg == NULL) {
    return;
  }

  if (configchg->fd >= 0) {
    notify_cancel(configchg->token);
    /* automatically closes fd */
    configchg->fd = -1;
  }

  ci_free(configchg);
}

static void ci_event_configchg_cb(ci_event_thread_t *e, ci_socket_t fd,
                                    void *data, ci_event_flags_t flags)
{
  ci_event_configchg_t *configchg = data;
  ci_bool_t             triggered = CI_FALSE;

  (void)fd;
  (void)flags;

  while (1) {
    int     t = 0;
    ssize_t len;

    len = read(configchg->fd, &t, sizeof(t));

    if (len < (ssize_t)sizeof(t)) {
      break;
    }

    /* Token is read in network byte order (yeah, docs don't mention this) */
    t = (int)ntohl(t);

    if (t != configchg->token) {
      continue;
    }

    triggered = CI_TRUE;
  }

  /* Only process after all events are read.  No need to process more often as
   * we don't want to reload the config back to back */
  if (triggered) {
    ci_reinit(e->channel);
  }
}

ci_status_t ci_event_configchg_init(ci_event_configchg_t **configchg,
                                        ci_event_thread_t     *e)
{
  ci_status_t status                               = CI_SUCCESS;
  void         *handle                               = NULL;
  const char *(*pdns_configuration_notify_key)(void) = NULL;
  const char *notify_key                             = NULL;
  int         flags;
  size_t      i;
  const char *searchlibs[] = {
    "/usr/lib/libSystem.dylib",
    "/System/Library/Frameworks/SystemConfiguration.framework/"
    "SystemConfiguration",
    NULL
  };

  *configchg = ci_malloc_zero(sizeof(**configchg));
  if (*configchg == NULL) {
    return CI_ENOMEM;
  }

  /* Load symbol as it isn't normally public */
  for (i = 0; searchlibs[i] != NULL; i++) {
    handle = dlopen(searchlibs[i], RTLD_LAZY);
    if (handle == NULL) {
      /* Fail, loop! */
      continue;
    }

    pdns_configuration_notify_key =
      (const char *(*)(void))dlsym(handle, "dns_configuration_notify_key");
    if (pdns_configuration_notify_key != NULL) {
      break;
    }

    /* Fail, loop! */
    dlclose(handle);
    handle = NULL;
  }

  if (pdns_configuration_notify_key == NULL) {
    status = CI_ESERVFAIL;
    goto done;
  }

  notify_key = pdns_configuration_notify_key();
  if (notify_key == NULL) {
    status = CI_ESERVFAIL;
    goto done;
  }

  if (notify_register_file_descriptor(notify_key, &(*configchg)->fd, 0,
                                      &(*configchg)->token) !=
      NOTIFY_STATUS_OK) {
    status = CI_ESERVFAIL;
    goto done;
  }

  /* Set file descriptor to non-blocking */
  flags = fcntl((*configchg)->fd, F_GETFL, 0);
  fcntl((*configchg)->fd, F_SETFL, flags | O_NONBLOCK);

  /* Register file descriptor with event subsystem */
  status = ci_event_update(NULL, e, CI_EVENT_FLAG_READ,
                             ci_event_configchg_cb, (*configchg)->fd,
                             *configchg, ci_event_configchg_free, NULL);

done:
  if (status != CI_SUCCESS) {
    ci_event_configchg_free(*configchg);
    *configchg = NULL;
  }

  if (handle) {
    dlclose(handle);
  }

  return status;
}

#elif defined(HAVE_STAT) && !defined(_WIN32)
#  ifdef HAVE_SYS_TYPES_H
#    include <sys/types.h>
#  endif
#  ifdef HAVE_SYS_STAT_H
#    include <sys/stat.h>
#  endif

typedef struct {
  size_t size;
  time_t mtime;
} fileinfo_t;

struct ci_event_configchg {
  ci_bool_t          isup;
  ci_thread_t       *thread;
  ci_htable_strvp_t *filestat;
  ci_thread_mutex_t *lock;
  ci_thread_cond_t  *wake;
  const char          *resolvconf_path;
  ci_event_thread_t *e;
};

static ci_status_t config_change_check(ci_htable_strvp_t *filestat,
                                         const char          *resolvconf_path)
{
  size_t      i;
  const char *configfiles[5];
  ci_bool_t changed = CI_FALSE;

  configfiles[0] = resolvconf_path;
  configfiles[1] = "/etc/nsswitch.conf";
  configfiles[2] = "/etc/netsvc.conf";
  configfiles[3] = "/etc/svc.conf";
  configfiles[4] = NULL;

  for (i = 0; configfiles[i] != NULL; i++) {
    fileinfo_t *fi = ci_htable_strvp_get_direct(filestat, configfiles[i]);
    struct stat st;

    if (stat(configfiles[i], &st) == 0) {
      if (fi == NULL) {
        fi = ci_malloc_zero(sizeof(*fi));
        if (fi == NULL) {
          return CI_ENOMEM;
        }
        if (!ci_htable_strvp_insert(filestat, configfiles[i], fi)) {
          ci_free(fi);
          return CI_ENOMEM;
        }
      }
      if (fi->size != (size_t)st.st_size || fi->mtime != (time_t)st.st_mtime) {
        changed = CI_TRUE;
      }
      fi->size  = (size_t)st.st_size;
      fi->mtime = (time_t)st.st_mtime;
    } else if (fi != NULL) {
      /* File no longer exists, remove */
      ci_htable_strvp_remove(filestat, configfiles[i]);
      changed = CI_TRUE;
    }
  }

  if (changed) {
    return CI_SUCCESS;
  }
  return CI_ENOTFOUND;
}

static void *ci_event_configchg_thread(void *arg)
{
  ci_event_configchg_t *c = arg;

  ci_thread_mutex_lock(c->lock);
  while (c->isup) {
    ci_status_t status;

    if (ci_thread_cond_timedwait(c->wake, c->lock, 30000) != CI_ETIMEOUT) {
      continue;
    }

    /* make sure status didn't change even though we got a timeout */
    if (!c->isup) {
      break;
    }

    status = config_change_check(c->filestat, c->resolvconf_path);
    if (status == CI_SUCCESS) {
      ci_reinit(c->e->channel);
    }
  }

  ci_thread_mutex_unlock(c->lock);
  return NULL;
}

ci_status_t ci_event_configchg_init(ci_event_configchg_t **configchg,
                                        ci_event_thread_t     *e)
{
  ci_status_t           status = CI_SUCCESS;
  ci_event_configchg_t *c      = NULL;

  *configchg = NULL;

  c = ci_malloc_zero(sizeof(*c));
  if (c == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  c->e = e;

  c->filestat = ci_htable_strvp_create(ci_free);
  if (c->filestat == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  c->wake = ci_thread_cond_create();
  if (c->wake == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  c->resolvconf_path = c->e->channel->resolvconf_path;
  if (c->resolvconf_path == NULL) {
    c->resolvconf_path = PATH_RESOLV_CONF;
  }

  status = config_change_check(c->filestat, c->resolvconf_path);
  if (status == CI_ENOMEM) {
    goto done;
  }

  c->isup = CI_TRUE;
  status  = ci_thread_create(&c->thread, ci_event_configchg_thread, c);

done:
  if (status != CI_SUCCESS) {
    ci_event_configchg_destroy(c);
  } else {
    *configchg = c;
  }
  return status;
}

void ci_event_configchg_destroy(ci_event_configchg_t *configchg)
{
  if (configchg == NULL) {
    return;
  }

  if (configchg->lock) {
    ci_thread_mutex_lock(configchg->lock);
  }

  configchg->isup = CI_FALSE;
  if (configchg->wake) {
    ci_thread_cond_signal(configchg->wake);
  }

  if (configchg->lock) {
    ci_thread_mutex_unlock(configchg->lock);
  }

  if (configchg->thread) {
    void *rv = NULL;
    ci_thread_join(configchg->thread, &rv);
  }

  ci_thread_mutex_destroy(configchg->lock);
  ci_thread_cond_destroy(configchg->wake);
  ci_htable_strvp_destroy(configchg->filestat);
  ci_free(configchg);
}

#else

ci_status_t ci_event_configchg_init(ci_event_configchg_t **configchg,
                                        ci_event_thread_t     *e)
{
  /* No ability */
  return CI_ENOTIMP;
}

void ci_event_configchg_destroy(ci_event_configchg_t *configchg)
{
  /* No-op */
}

#endif
