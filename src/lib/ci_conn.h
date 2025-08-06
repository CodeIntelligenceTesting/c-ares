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
#ifndef __CI_CONN_H
#define __CI_CONN_H

#include "ci_socket.h"

struct ci_conn;
typedef struct ci_conn ci_conn_t;

struct ci_server;
typedef struct ci_server ci_server_t;

typedef enum {
  /*! No flags */
  CI_CONN_FLAG_NONE = 0,
  /*! TCP connection, not UDP */
  CI_CONN_FLAG_TCP = 1 << 0,
  /*! TCP Fast Open is enabled and being used if supported by the OS */
  CI_CONN_FLAG_TFO = 1 << 1,
  /*! TCP Fast Open has not yet sent its first packet. Gets unset on first
   *  write to a connection */
  CI_CONN_FLAG_TFO_INITIAL = 1 << 2
} ci_conn_flags_t;

typedef enum {
  CI_CONN_STATE_NONE      = 0,
  CI_CONN_STATE_READ      = 1 << 0,
  CI_CONN_STATE_WRITE     = 1 << 1,
  CI_CONN_STATE_CONNECTED = 1 << 2, /* This doesn't get a callback */
  CI_CONN_STATE_CBFLAGS   = CI_CONN_STATE_READ | CI_CONN_STATE_WRITE
} ci_conn_state_flags_t;

struct ci_conn {
  ci_server_t          *server;
  ci_socket_t           fd;
  struct ci_addr        self_ip;
  ci_conn_flags_t       flags;
  ci_conn_state_flags_t state_flags;

  /*! Outbound buffered data that is not yet sent.  Exists as one contiguous
   *  stream in TCP format (big endian 16bit length prefix followed by DNS
   *  wire-format message).  For TCP this can be sent as-is, UDP this must
   *  be sent per-packet (stripping the length prefix) */
  ci_buf_t             *out_buf;

  /*! Inbound buffered data that is not yet parsed.  Exists as one contiguous
   *  stream in TCP format (big endian 16bit length prefix followed by DNS
   *  wire-format message).  TCP may have partial data and this needs to be
   *  handled gracefully, but UDP will always have a full message */
  ci_buf_t             *in_buf;

  /* total number of queries run on this connection since it was established */
  size_t                  total_queries;

  /* list of outstanding queries to this connection */
  ci_llist_t           *queries_to_conn;
};

/*! Various buckets for grouping history */
typedef enum {
  CI_METRIC_1MINUTE = 0, /*!< Bucket for tracking over the last minute */
  CI_METRIC_15MINUTES,   /*!< Bucket for tracking over the last 15 minutes */
  CI_METRIC_1HOUR,       /*!< Bucket for tracking over the last hour */
  CI_METRIC_1DAY,        /*!< Bucket for tracking over the last day */
  CI_METRIC_INCEPTION,   /*!< Bucket for tracking since inception */
  CI_METRIC_COUNT        /*!< Count of buckets, not a real bucket */
} ci_server_bucket_t;

/*! Data metrics collected for each bucket */
typedef struct {
  time_t        ts;             /*!< Timestamp divided by bucket divisor */
  unsigned int  latency_min_ms; /*!< Minimum latency for queries */
  unsigned int  latency_max_ms; /*!< Maximum latency for queries */
  ci_uint64_t total_ms;       /*!< Cumulative query time for bucket */
  ci_uint64_t total_count;    /*!< Number of queries for bucket */

  time_t        prev_ts;        /*!< Previous period bucket timestamp */
  ci_uint64_t
    prev_total_ms; /*!< Previous period bucket cumulative query time */
  ci_uint64_t prev_total_count; /*!< Previous period bucket query count */
} ci_server_metrics_t;

typedef enum {
  CI_COOKIE_INITIAL     = 0,
  CI_COOKIE_GENERATED   = 1,
  CI_COOKIE_SUPPORTED   = 2,
  CI_COOKIE_UNSUPPORTED = 3
} ci_cookie_state_t;

/*! Structure holding tracking data for RFC 7873/9018 DNS cookies.
 *  Implementation plan for this feature is here:
 *  https://github.com/c-ci/c-ci/issues/620
 */
typedef struct {
  /*! starts at INITIAL, transitions as needed. */
  ci_cookie_state_t state;
  /*! randomly-generate client cookie */
  unsigned char       client[8];
  /*! timestamp client cookie was generated, used for rotation purposes */
  ci_timeval_t      client_ts;
  /*! IP address last used for client to connect to server.  If this changes
   *  The client cookie gets invalidated */
  struct ci_addr    client_ip;
  /*! Server Cookie last received, 8-32 bytes in length */
  unsigned char       server[32];
  /*! Length of server cookie on file. */
  size_t              server_len;
  /*! Timestamp of last attempt to use cookies, but it was determined that the
   *  server didn't support them */
  ci_timeval_t      unsupported_ts;
} ci_cookie_t;

struct ci_server {
  /* Configuration */
  size_t                idx;      /* index for server in system configuration */
  struct ci_addr      addr;
  unsigned short        udp_port; /* host byte order */
  unsigned short        tcp_port; /* host byte order */
  char                  ll_iface[64];    /* IPv6 Link Local Interface */
  unsigned int          ll_scope;        /* IPv6 Link Local Scope */

  size_t                consec_failures; /* Consecutive query failure count
                                          * can be hard errors or timeouts
                                          */
  ci_bool_t           probe_pending;   /* Whether a probe is pending for this
                                          * server due to prior failures */
  ci_llist_t         *connections;
  ci_conn_t          *tcp_conn;

  /* The next time when we will retry this server if it has hit failures */
  ci_timeval_t        next_retry_time;

  /*! Buckets for collecting metrics about the server */
  ci_server_metrics_t metrics[CI_METRIC_COUNT];

  /*! RFC 7873/9018 DNS Cookies */
  ci_cookie_t         cookie;

  /* Link back to owning channel */
  ci_channel_t       *channel;
};

void ci_close_connection(ci_conn_t *conn, ci_status_t requeue_status);
void ci_close_sockets(ci_server_t *server);
void ci_check_cleanup_conns(const ci_channel_t *channel);

void ci_destroy_servers_state(ci_channel_t *channel);
ci_status_t   ci_open_connection(ci_conn_t   **conn_out,
                                     ci_channel_t *channel,
                                     ci_server_t *server, ci_bool_t is_tcp);

ci_conn_err_t ci_conn_write(ci_conn_t *conn, const void *data, size_t len,
                                size_t *written);
ci_status_t   ci_conn_flush(ci_conn_t *conn);
ci_conn_err_t ci_conn_read(ci_conn_t *conn, void *data, size_t len,
                               size_t *read_bytes);
ci_conn_t *ci_conn_from_fd(const ci_channel_t *channel, ci_socket_t fd);
void         ci_conn_sock_state_cb_update(ci_conn_t            *conn,
                                            ci_conn_state_flags_t flags);
ci_conn_err_t ci_socket_recv(ci_channel_t *channel, ci_socket_t s,
                                 ci_bool_t is_tcp, void *data,
                                 size_t data_len, size_t *read_bytes);
ci_conn_err_t ci_socket_recvfrom(ci_channel_t *channel, ci_socket_t s,
                                     ci_bool_t is_tcp, void *data,
                                     size_t data_len, int flags,
                                     struct sockaddr *from,
                                     ci_socklen_t  *from_len,
                                     size_t          *read_bytes);

void            ci_destroy_server(ci_server_t *server);

#endif
