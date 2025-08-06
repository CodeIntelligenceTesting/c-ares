/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2008 Daniel Stenberg
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

#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#include "ci_data.h"
#include "ci_inet_net_pton.h"

void ci_destroy_options(struct ci_options *options)
{
  int i;

  ci_free(options->servers);

  for (i = 0; options->domains && i < options->ndomains; i++) {
    ci_free(options->domains[i]);
  }

  ci_free(options->domains);
  ci_free(options->sortlist);
  ci_free(options->lookups);
  ci_free(options->resolvconf_path);
  ci_free(options->hosts_path);
}

static struct in_addr *ci_save_opt_servers(const ci_channel_t *channel,
                                             int                  *nservers)
{
  ci_slist_node_t *snode;
  struct in_addr    *out =
    ci_malloc_zero(ci_slist_len(channel->servers) * sizeof(*out));

  *nservers = 0;

  if (out == NULL) {
    return NULL;
  }

  for (snode = ci_slist_node_first(channel->servers); snode != NULL;
       snode = ci_slist_node_next(snode)) {
    const ci_server_t *server = ci_slist_node_val(snode);

    if (server->addr.family != AF_INET) {
      continue;
    }

    memcpy(&out[*nservers], &server->addr.addr.addr4, sizeof(*out));
    (*nservers)++;
  }

  return out;
}

/* Save options from initialized channel */
int ci_save_options(const ci_channel_t *channel,
                      struct ci_options *options, int *optmask)
{
  size_t i;

  /* NOTE: We can't zero the whole thing out, this is because the size of the
   *       struct ci_options changes over time, so if someone compiled
   *       with an older version, their struct size might be smaller and
   *       we might overwrite their memory! So using the optmask is critical
   *       here, as they could have only set options they knew about.
   *
   *       Unfortunately ci_destroy_options() doesn't take an optmask, so
   *       there are a few pointers we *must* zero out otherwise we won't
   *       know if they were allocated or not
   */
  options->servers         = NULL;
  options->domains         = NULL;
  options->sortlist        = NULL;
  options->lookups         = NULL;
  options->resolvconf_path = NULL;
  options->hosts_path      = NULL;

  if (!CI_CONFIG_CHECK(channel)) {
    return CI_ENODATA;
  }

  if (channel->optmask & CI_OPT_FLAGS) {
    options->flags = (int)channel->flags;
  }

  /* We convert CI_OPT_TIMEOUT to CI_OPT_TIMEOUTMS in
   * ci_init_by_options() */
  if (channel->optmask & CI_OPT_TIMEOUTMS) {
    options->timeout = (int)channel->timeout;
  }

  if (channel->optmask & CI_OPT_TRIES) {
    options->tries = (int)channel->tries;
  }

  if (channel->optmask & CI_OPT_NDOTS) {
    options->ndots = (int)channel->ndots;
  }

  if (channel->optmask & CI_OPT_MAXTIMEOUTMS) {
    options->maxtimeout = (int)channel->maxtimeout;
  }

  if (channel->optmask & CI_OPT_UDP_PORT) {
    options->udp_port = channel->udp_port;
  }
  if (channel->optmask & CI_OPT_TCP_PORT) {
    options->tcp_port = channel->tcp_port;
  }

  if (channel->optmask & CI_OPT_SOCK_STATE_CB) {
    options->sock_state_cb      = channel->sock_state_cb;
    options->sock_state_cb_data = channel->sock_state_cb_data;
  }

  if (channel->optmask & CI_OPT_SERVERS) {
    options->servers = ci_save_opt_servers(channel, &options->nservers);
    if (options->servers == NULL) {
      return CI_ENOMEM;
    }
  }

  if (channel->optmask & CI_OPT_DOMAINS) {
    options->domains = NULL;
    if (channel->ndomains) {
      options->domains = ci_malloc(channel->ndomains * sizeof(char *));
      if (!options->domains) {
        return CI_ENOMEM;
      }

      for (i = 0; i < channel->ndomains; i++) {
        options->domains[i] = ci_strdup(channel->domains[i]);
        if (!options->domains[i]) {
          options->ndomains = (int)i;
          return CI_ENOMEM;
        }
      }
    }
    options->ndomains = (int)channel->ndomains;
  }

  if (channel->optmask & CI_OPT_LOOKUPS) {
    options->lookups = ci_strdup(channel->lookups);
    if (!options->lookups && channel->lookups) {
      return CI_ENOMEM;
    }
  }

  if (channel->optmask & CI_OPT_SORTLIST) {
    options->sortlist = NULL;
    if (channel->nsort) {
      options->sortlist = ci_malloc(channel->nsort * sizeof(struct apattern));
      if (!options->sortlist) {
        return CI_ENOMEM;
      }
      for (i = 0; i < channel->nsort; i++) {
        options->sortlist[i] = channel->sortlist[i];
      }
    }
    options->nsort = (int)channel->nsort;
  }

  if (channel->optmask & CI_OPT_RESOLVCONF) {
    options->resolvconf_path = ci_strdup(channel->resolvconf_path);
    if (!options->resolvconf_path) {
      return CI_ENOMEM;
    }
  }

  if (channel->optmask & CI_OPT_HOSTS_FILE) {
    options->hosts_path = ci_strdup(channel->hosts_path);
    if (!options->hosts_path) {
      return CI_ENOMEM;
    }
  }

  if (channel->optmask & CI_OPT_SOCK_SNDBUF &&
      channel->socket_send_buffer_size > 0) {
    options->socket_send_buffer_size = channel->socket_send_buffer_size;
  }

  if (channel->optmask & CI_OPT_SOCK_RCVBUF &&
      channel->socket_receive_buffer_size > 0) {
    options->socket_receive_buffer_size = channel->socket_receive_buffer_size;
  }

  if (channel->optmask & CI_OPT_EDNSPSZ) {
    options->ednspsz = (int)channel->ednspsz;
  }

  if (channel->optmask & CI_OPT_UDP_MAX_QUERIES) {
    options->udp_max_queries = (int)channel->udp_max_queries;
  }

  if (channel->optmask & CI_OPT_QUERY_CACHE) {
    options->qcache_max_ttl = channel->qcache_max_ttl;
  }

  if (channel->optmask & CI_OPT_EVENT_THREAD) {
    options->evsys = channel->evsys;
  }

  /* Set options for server failover behavior */
  if (channel->optmask & CI_OPT_SERVER_FAILOVER) {
    options->server_failover_opts.retry_chance = channel->server_retry_chance;
    options->server_failover_opts.retry_delay  = channel->server_retry_delay;
  }

  *optmask = (int)channel->optmask;

  return CI_SUCCESS;
}

static ci_status_t ci_init_options_servers(ci_channel_t       *channel,
                                               const struct in_addr *servers,
                                               size_t                nservers)
{
  ci_llist_t *slist = NULL;
  ci_status_t status;

  status = ci_in_addr_to_sconfig_llist(servers, nservers, &slist);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  status = ci_servers_update(channel, slist, CI_TRUE);

  ci_llist_destroy(slist);

  return status;
}

ci_status_t ci_init_by_options(ci_channel_t            *channel,
                                   const struct ci_options *options,
                                   int                        optmask)
{
  size_t i;

  if (channel == NULL) {
    return CI_ENODATA; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (options == NULL) {
    if (optmask != 0) {
      return CI_ENODATA; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
    return CI_SUCCESS;
  }

  /* Easy stuff. */

  /* Event Thread requires threading support and is incompatible with socket
   * state callbacks */
  if (optmask & CI_OPT_EVENT_THREAD) {
    if (!ci_threadsafety()) {
      return CI_ENOTIMP;
    }
    if (optmask & CI_OPT_SOCK_STATE_CB) {
      return CI_EFORMERR;
    }
    channel->evsys = options->evsys;
  }

  if (optmask & CI_OPT_FLAGS) {
    channel->flags = (unsigned int)options->flags;
  }

  if (optmask & CI_OPT_TIMEOUTMS) {
    /* Apparently some integrations were passing -1 to tell c-ci to use
     * the default instead of just omitting the optmask */
    if (options->timeout <= 0) {
      optmask &= ~(CI_OPT_TIMEOUTMS);
    } else {
      channel->timeout = (unsigned int)options->timeout;
    }
  } else if (optmask & CI_OPT_TIMEOUT) {
    optmask &= ~(CI_OPT_TIMEOUT);
    /* Apparently some integrations were passing -1 to tell c-ci to use
     * the default instead of just omitting the optmask */
    if (options->timeout > 0) {
      /* Convert to milliseconds */
      optmask          |= CI_OPT_TIMEOUTMS;
      channel->timeout  = (unsigned int)options->timeout * 1000;
    }
  }

  if (optmask & CI_OPT_TRIES) {
    if (options->tries <= 0) {
      optmask &= ~(CI_OPT_TRIES);
    } else {
      channel->tries = (size_t)options->tries;
    }
  }

  if (optmask & CI_OPT_NDOTS) {
    if (options->ndots < 0) {
      optmask &= ~(CI_OPT_NDOTS);
    } else {
      channel->ndots = (size_t)options->ndots;
    }
  }

  if (optmask & CI_OPT_MAXTIMEOUTMS) {
    if (options->maxtimeout <= 0) {
      optmask &= ~(CI_OPT_MAXTIMEOUTMS);
    } else {
      channel->maxtimeout = (size_t)options->maxtimeout;
    }
  }

  if (optmask & CI_OPT_ROTATE) {
    channel->rotate = CI_TRUE;
  }

  if (optmask & CI_OPT_NOROTATE) {
    channel->rotate = CI_FALSE;
  }

  if (optmask & CI_OPT_UDP_PORT) {
    channel->udp_port = options->udp_port;
  }

  if (optmask & CI_OPT_TCP_PORT) {
    channel->tcp_port = options->tcp_port;
  }

  if (optmask & CI_OPT_SOCK_STATE_CB) {
    channel->sock_state_cb      = options->sock_state_cb;
    channel->sock_state_cb_data = options->sock_state_cb_data;
  }

  if (optmask & CI_OPT_SOCK_SNDBUF) {
    if (options->socket_send_buffer_size <= 0) {
      optmask &= ~(CI_OPT_SOCK_SNDBUF);
    } else {
      channel->socket_send_buffer_size = options->socket_send_buffer_size;
    }
  }

  if (optmask & CI_OPT_SOCK_RCVBUF) {
    if (options->socket_receive_buffer_size <= 0) {
      optmask &= ~(CI_OPT_SOCK_RCVBUF);
    } else {
      channel->socket_receive_buffer_size = options->socket_receive_buffer_size;
    }
  }

  if (optmask & CI_OPT_EDNSPSZ) {
    if (options->ednspsz <= 0) {
      optmask &= ~(CI_OPT_EDNSPSZ);
    } else {
      channel->ednspsz = (size_t)options->ednspsz;
    }
  }

  /* Copy the domains, if given.  Keep channel->ndomains consistent so
   * we can clean up in case of error.
   */
  if (optmask & CI_OPT_DOMAINS && options->ndomains > 0) {
    channel->domains =
      ci_malloc_zero((size_t)options->ndomains * sizeof(char *));
    if (!channel->domains) {
      return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
    channel->ndomains = (size_t)options->ndomains;
    for (i = 0; i < (size_t)options->ndomains; i++) {
      channel->domains[i] = ci_strdup(options->domains[i]);
      if (!channel->domains[i]) {
        return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  /* Set lookups, if given. */
  if (optmask & CI_OPT_LOOKUPS) {
    if (options->lookups == NULL) {
      optmask &= ~(CI_OPT_LOOKUPS);
    } else {
      channel->lookups = ci_strdup(options->lookups);
      if (!channel->lookups) {
        return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  /* copy sortlist */
  if (optmask & CI_OPT_SORTLIST && options->nsort > 0) {
    channel->nsort = (size_t)options->nsort;
    channel->sortlist =
      ci_malloc((size_t)options->nsort * sizeof(struct apattern));
    if (!channel->sortlist) {
      return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
    for (i = 0; i < (size_t)options->nsort; i++) {
      channel->sortlist[i] = options->sortlist[i];
    }
  }

  /* Set path for resolv.conf file, if given. */
  if (optmask & CI_OPT_RESOLVCONF) {
    if (options->resolvconf_path == NULL) {
      optmask &= ~(CI_OPT_RESOLVCONF);
    } else {
      channel->resolvconf_path = ci_strdup(options->resolvconf_path);
      if (channel->resolvconf_path == NULL) {
        return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  /* Set path for hosts file, if given. */
  if (optmask & CI_OPT_HOSTS_FILE) {
    if (options->hosts_path == NULL) {
      optmask &= ~(CI_OPT_HOSTS_FILE);
    } else {
      channel->hosts_path = ci_strdup(options->hosts_path);
      if (channel->hosts_path == NULL) {
        return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  if (optmask & CI_OPT_UDP_MAX_QUERIES) {
    if (options->udp_max_queries <= 0) {
      optmask &= ~(CI_OPT_UDP_MAX_QUERIES);
    } else {
      channel->udp_max_queries = (size_t)options->udp_max_queries;
    }
  }

  /* As of c-ci 1.31.0, the Query Cache is on by default.  The only way to
   * disable it is to set options->qcache_max_ttl = 0 while specifying the
   * CI_OPT_QUERY_CACHE which will actually disable it completely. */
  if (optmask & CI_OPT_QUERY_CACHE) {
    /* qcache_max_ttl is unsigned unlike the others */
    channel->qcache_max_ttl = options->qcache_max_ttl;
  } else {
    optmask                 |= CI_OPT_QUERY_CACHE;
    channel->qcache_max_ttl  = 3600;
  }

  /* Initialize the ipv4 servers if provided */
  if (optmask & CI_OPT_SERVERS) {
    if (options->nservers <= 0) {
      optmask &= ~(CI_OPT_SERVERS);
    } else {
      ci_status_t status;
      status = ci_init_options_servers(channel, options->servers,
                                         (size_t)options->nservers);
      if (status != CI_SUCCESS) {
        return status; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  /* Set fields for server failover behavior */
  if (optmask & CI_OPT_SERVER_FAILOVER) {
    channel->server_retry_chance = options->server_failover_opts.retry_chance;
    channel->server_retry_delay  = options->server_failover_opts.retry_delay;
  }

  channel->optmask = (unsigned int)optmask;

  return CI_SUCCESS;
}
