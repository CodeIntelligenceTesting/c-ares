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

#ifndef __CI_SOCKET_H
#define __CI_SOCKET_H

/* Macro SOCKERRNO / SET_SOCKERRNO() returns / sets the *socket-related* errno
 * (or equivalent) on this platform to hide platform details to code using it.
 */
#ifdef USE_WINSOCK
#  define SOCKERRNO        ((int)WSAGetLastError())
#  define SET_SOCKERRNO(x) (WSASetLastError((int)(x)))
#else
#  define SOCKERRNO        (errno)
#  define SET_SOCKERRNO(x) (errno = (x))
#endif

/* Portable error number symbolic names defined to Winsock error codes. */
#ifdef USE_WINSOCK
#  undef EBADF           /* override definition in errno.h */
#  define EBADF WSAEBADF
#  undef EINTR           /* override definition in errno.h */
#  define EINTR WSAEINTR
#  undef EINVAL          /* override definition in errno.h */
#  define EINVAL WSAEINVAL
#  undef EWOULDBLOCK     /* override definition in errno.h */
#  define EWOULDBLOCK WSAEWOULDBLOCK
#  undef EINPROGRESS     /* override definition in errno.h */
#  define EINPROGRESS WSAEINPROGRESS
#  undef EALREADY        /* override definition in errno.h */
#  define EALREADY WSAEALREADY
#  undef ENOTSOCK        /* override definition in errno.h */
#  define ENOTSOCK WSAENOTSOCK
#  undef EDESTADDRREQ    /* override definition in errno.h */
#  define EDESTADDRREQ WSAEDESTADDRREQ
#  undef EMSGSIZE        /* override definition in errno.h */
#  define EMSGSIZE WSAEMSGSIZE
#  undef EPROTOTYPE      /* override definition in errno.h */
#  define EPROTOTYPE WSAEPROTOTYPE
#  undef ENOPROTOOPT     /* override definition in errno.h */
#  define ENOPROTOOPT WSAENOPROTOOPT
#  undef EPROTONOSUPPORT /* override definition in errno.h */
#  define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#  define ESOCKTNOSUPPORT WSAESOCKTNOSUPPORT
#  undef EOPNOTSUPP /* override definition in errno.h */
#  define EOPNOTSUPP WSAEOPNOTSUPP
#  undef ENOSYS     /* override definition in errno.h */
#  define ENOSYS       WSAEOPNOTSUPP
#  define EPFNOSUPPORT WSAEPFNOSUPPORT
#  undef EAFNOSUPPORT  /* override definition in errno.h */
#  define EAFNOSUPPORT WSAEAFNOSUPPORT
#  undef EADDRINUSE    /* override definition in errno.h */
#  define EADDRINUSE WSAEADDRINUSE
#  undef EADDRNOTAVAIL /* override definition in errno.h */
#  define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#  undef ENETDOWN      /* override definition in errno.h */
#  define ENETDOWN WSAENETDOWN
#  undef ENETUNREACH   /* override definition in errno.h */
#  define ENETUNREACH WSAENETUNREACH
#  undef ENETRESET     /* override definition in errno.h */
#  define ENETRESET WSAENETRESET
#  undef ECONNABORTED  /* override definition in errno.h */
#  define ECONNABORTED WSAECONNABORTED
#  undef ECONNRESET    /* override definition in errno.h */
#  define ECONNRESET WSAECONNRESET
#  undef ENOBUFS       /* override definition in errno.h */
#  define ENOBUFS WSAENOBUFS
#  undef EISCONN       /* override definition in errno.h */
#  define EISCONN WSAEISCONN
#  undef ENOTCONN      /* override definition in errno.h */
#  define ENOTCONN     WSAENOTCONN
#  define ESHUTDOWN    WSAESHUTDOWN
#  define ETOOMANYREFS WSAETOOMANYREFS
#  undef ETIMEDOUT     /* override definition in errno.h */
#  define ETIMEDOUT WSAETIMEDOUT
#  undef ECONNREFUSED  /* override definition in errno.h */
#  define ECONNREFUSED WSAECONNREFUSED
#  undef ELOOP         /* override definition in errno.h */
#  define ELOOP WSAELOOP
#  ifndef ENAMETOOLONG /* possible previous definition in errno.h */
#    define ENAMETOOLONG WSAENAMETOOLONG
#  endif
#  define EHOSTDOWN WSAEHOSTDOWN
#  undef EHOSTUNREACH /* override definition in errno.h */
#  define EHOSTUNREACH WSAEHOSTUNREACH
#  ifndef ENOTEMPTY   /* possible previous definition in errno.h */
#    define ENOTEMPTY WSAENOTEMPTY
#  endif
#  define EPROCLIM WSAEPROCLIM
#  define EUSERS   WSAEUSERS
#  define EDQUOT   WSAEDQUOT
#  define ESTALE   WSAESTALE
#  define EREMOTE  WSAEREMOTE
#endif

/*! Socket errors */
typedef enum {
  CI_CONN_ERR_SUCCESS      = 0,  /*!< Success */
  CI_CONN_ERR_WOULDBLOCK   = 1,  /*!< Operation would block */
  CI_CONN_ERR_CONNCLOSED   = 2,  /*!< Connection closed (gracefully) */
  CI_CONN_ERR_CONNABORTED  = 3,  /*!< Connection Aborted */
  CI_CONN_ERR_CONNRESET    = 4,  /*!< Connection Reset */
  CI_CONN_ERR_CONNREFUSED  = 5,  /*!< Connection Refused */
  CI_CONN_ERR_CONNTIMEDOUT = 6,  /*!< Connection Timed Out */
  CI_CONN_ERR_HOSTDOWN     = 7,  /*!< Host Down */
  CI_CONN_ERR_HOSTUNREACH  = 8,  /*!< Host Unreachable */
  CI_CONN_ERR_NETDOWN      = 9,  /*!< Network Down */
  CI_CONN_ERR_NETUNREACH   = 10, /*!< Network Unreachable */
  CI_CONN_ERR_INTERRUPT    = 11, /*!< Call interrupted by signal, repeat */
  CI_CONN_ERR_AFNOSUPPORT  = 12, /*!< Address family not supported */
  CI_CONN_ERR_BADADDR      = 13, /*!< Bad Address / Unavailable */
  CI_CONN_ERR_NOMEM        = 14, /*!< Out of memory */
  CI_CONN_ERR_INVALID      = 15, /*!< Invalid Usage */
  CI_CONN_ERR_TOOLARGE     = 16, /*!< Request size too large */
  CI_CONN_ERR_NOTIMP       = 17, /*!< Not implemented */
  CI_CONN_ERR_FAILURE      = 99  /*!< Generic failure */
} ci_conn_err_t;

ci_bool_t     ci_sockaddr_addr_eq(const struct sockaddr  *sa,
                                      const struct ci_addr *aa);
ci_status_t   ci_socket_configure(ci_channel_t *channel, int family,
                                      ci_bool_t is_tcp, ci_socket_t fd);
ci_conn_err_t ci_socket_enable_tfo(const ci_channel_t *channel,
                                       ci_socket_t         fd);
ci_conn_err_t ci_socket_open(ci_socket_t *sock, ci_channel_t *channel,
                                 int af, int type, int protocol);
ci_bool_t     ci_socket_try_again(int errnum);
void            ci_socket_close(ci_channel_t *channel, ci_socket_t s);
ci_conn_err_t ci_socket_connect(ci_channel_t *channel,
                                    ci_socket_t sockfd, ci_bool_t is_tfo,
                                    const struct sockaddr *addr,
                                    ci_socklen_t         addrlen);
ci_bool_t     ci_sockaddr_to_ci_addr(struct ci_addr      *ci_addr,
                                           unsigned short        *port,
                                           const struct sockaddr *sockaddr);
ci_conn_err_t ci_socket_write(ci_channel_t *channel, ci_socket_t fd,
                                  const void *data, size_t len, size_t *written,
                                  const struct sockaddr *sa,
                                  ci_socklen_t         salen);
#endif
