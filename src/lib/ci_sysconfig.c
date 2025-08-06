/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2007 Daniel Stenberg
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

#ifdef HAVE_SYS_PARAM_H
#  include <sys/param.h>
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif

#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#if defined(ANDROID) || defined(__ANDROID__)
#  include <sys/system_properties.h>
#  include "ci_android.h"
/* From the Bionic sources */
#  define DNS_PROP_NAME_PREFIX "net.dns"
#  define MAX_DNS_PROPERTIES   8
#endif

#if defined(CI_USE_LIBRESOLV)
#  include <resolv.h>
#endif

#include "ci_inet_net_pton.h"


#if defined(__MVS__)
static ci_status_t ci_init_sysconfig_mvs(const ci_channel_t *channel,
                                             ci_sysconfig_t     *sysconfig)
{
  struct __res_state *res = 0;
  size_t              count4;
  size_t              count6;
  int                 i;
  __STATEEXTIPV6     *v6;
  arse__llist_t      *sconfig = NULL;
  ci_status_t       status;

  if (0 == res) {
    int rc = res_init();
    while (rc == -1 && h_errno == TRY_AGAIN) {
      rc = res_init();
    }
    if (rc == -1) {
      return CI_ENOMEM;
    }
    res = __res();
  }

  v6 = res->__res_extIPv6;
  if (res->nscount > 0) {
    count4 = (size_t)res->nscount;
  }

  if (v6 && v6->__stat_nscount > 0) {
    count6 = (size_t)v6->__stat_nscount;
  } else {
    count6 = 0;
  }

  for (i = 0; i < count4; i++) {
    struct sockaddr_in *addr_in = &(res->nsaddr_list[i]);
    struct ci_addr    addr;

    addr.addr.addr4.s_addr = addr_in->sin_addr.s_addr;
    addr.family            = AF_INET;

    status = ci_sconfig_append(channel, &sysconfig->sconfig, &addr,
                                 htons(addr_in->sin_port),
                                 htons(addr_in->sin_port), NULL);

    if (status != CI_SUCCESS) {
      return status;
    }
  }

  for (i = 0; i < count6; i++) {
    struct sockaddr_in6 *addr_in = &(v6->__stat_nsaddr_list[i]);
    struct ci_addr     addr;

    addr.family = AF_INET6;
    memcpy(&(addr.addr.addr6), &(addr_in->sin6_addr),
           sizeof(addr_in->sin6_addr));

    status = ci_sconfig_append(channel, &sysconfig->sconfig, &addr,
                                 htons(addr_in->sin_port),
                                 htons(addr_in->sin_port), NULL);

    if (status != CI_SUCCESS) {
      return status;
    }
  }

  return CI_SUCCESS;
}
#endif

#if defined(__riscos__)
static ci_status_t ci_init_sysconfig_riscos(const ci_channel_t *channel,
                                                ci_sysconfig_t     *sysconfig)
{
  char         *line;
  ci_status_t status = CI_SUCCESS;

  /* Under RISC OS, name servers are listed in the
     system variable Inet$Resolvers, space separated. */
  line = getenv("Inet$Resolvers");
  if (line) {
    char *resolvers = ci_strdup(line);
    char *pos;
    char *space;

    if (!resolvers) {
      return CI_ENOMEM;
    }

    pos = resolvers;
    do {
      space = strchr(pos, ' ');
      if (space) {
        *space = '\0';
      }
      status = ci_sconfig_append_fromstr(channel, &sysconfig->sconfig, pos,
                                           CI_TRUE);
      if (status != CI_SUCCESS) {
        break;
      }
      pos = space + 1;
    } while (space);

    ci_free(resolvers);
  }

  return status;
}
#endif

#if defined(WATT32)
static ci_status_t ci_init_sysconfig_watt32(const ci_channel_t *channel,
                                                ci_sysconfig_t     *sysconfig)
{
  size_t        i;
  ci_status_t status;

  sock_init();

  for (i = 0; def_nameservers[i]; i++) {
    struct ci_addr addr;

    addr.family            = AF_INET;
    addr.addr.addr4.s_addr = htonl(def_nameservers[i]);

    status =
      ci_sconfig_append(channel, &sysconfig->sconfig, &addr, 0, 0, NULL);

    if (status != CI_SUCCESS) {
      return status;
    }
  }

  return CI_SUCCESS;
}
#endif

#if defined(ANDROID) || defined(__ANDROID__)
static ci_status_t ci_init_sysconfig_android(const ci_channel_t *channel,
                                                 ci_sysconfig_t *sysconfig)
{
  size_t        i;
  char        **dns_servers;
  char         *domains;
  size_t        num_servers;
  ci_status_t status = CI_EFILE;

  /* Use the Android connectivity manager to get a list
   * of DNS servers. As of Android 8 (Oreo) net.dns#
   * system properties are no longer available. Google claims this
   * improves privacy. Apps now need the ACCESS_NETWORK_STATE
   * permission and must use the ConnectivityManager which
   * is Java only. */
  dns_servers = ci_get_android_server_list(MAX_DNS_PROPERTIES, &num_servers);
  if (dns_servers != NULL) {
    for (i = 0; i < num_servers; i++) {
      status = ci_sconfig_append_fromstr(channel, &sysconfig->sconfig,
                                           dns_servers[i], CI_TRUE);
      if (status != CI_SUCCESS) {
        return status;
      }
    }
    for (i = 0; i < num_servers; i++) {
      ci_free(dns_servers[i]);
    }
    ci_free(dns_servers);
  }

  domains            = ci_get_android_search_domains_list();
  sysconfig->domains = ci_strsplit(domains, ", ", &sysconfig->ndomains);
  ci_free(domains);

#  ifdef HAVE___SYSTEM_PROPERTY_GET
  /* Old way using the system property still in place as
   * a fallback. Older android versions can still use this.
   * it's possible for older apps not not have added the new
   * permission and we want to try to avoid breaking those.
   *
   * We'll only run this if we don't have any dns servers
   * because this will get the same ones (if it works). */
  if (sysconfig->sconfig == NULL) {
    char propname[PROP_NAME_MAX];
    char propvalue[PROP_VALUE_MAX] = "";
    for (i = 1; i <= MAX_DNS_PROPERTIES; i++) {
      snprintf(propname, sizeof(propname), "%s%zu", DNS_PROP_NAME_PREFIX, i);
      if (__system_property_get(propname, propvalue) < 1) {
        break;
      }
      status = ci_sconfig_append_fromstr(channel, &sysconfig->sconfig,
                                           propvalue, CI_TRUE);
      if (status != CI_SUCCESS) {
        return status;
      }
    }
  }
#  endif /* HAVE___SYSTEM_PROPERTY_GET */

  return status;
}
#endif

#if defined(CI_USE_LIBRESOLV)
static ci_status_t
  ci_init_sysconfig_libresolv(const ci_channel_t *channel,
                                ci_sysconfig_t     *sysconfig)
{
  struct __res_state       res;
  ci_status_t            status = CI_SUCCESS;
  union res_sockaddr_union addr[MAXNS];
  int                      nscount;
  size_t                   i;
  size_t                   entries = 0;
  ci_buf_t              *ipbuf   = NULL;

  memset(&res, 0, sizeof(res));

  if (res_ninit(&res) != 0 || !(res.options & RES_INIT)) {
    return CI_EFILE;
  }

  nscount = res_getservers(&res, addr, MAXNS);

  for (i = 0; i < (size_t)nscount; ++i) {
    char           ipaddr[INET6_ADDRSTRLEN] = "";
    char          *ipstr                    = NULL;
    unsigned short port                     = 0;
    unsigned int   ll_scope                 = 0;

    sa_family_t    family = addr[i].sin.sin_family;
    if (family == AF_INET) {
      ci_inet_ntop(family, &addr[i].sin.sin_addr, ipaddr, sizeof(ipaddr));
      port = ntohs(addr[i].sin.sin_port);
    } else if (family == AF_INET6) {
      ci_inet_ntop(family, &addr[i].sin6.sin6_addr, ipaddr, sizeof(ipaddr));
      port     = ntohs(addr[i].sin6.sin6_port);
      ll_scope = addr[i].sin6.sin6_scope_id;
    } else {
      continue;
    }


    /* [ip]:port%iface */
    ipbuf = ci_buf_create();
    if (ipbuf == NULL) {
      status = CI_ENOMEM;
      goto done;
    }

    status = ci_buf_append_str(ipbuf, "[");
    if (status != CI_SUCCESS) {
      goto done;
    }

    status = ci_buf_append_str(ipbuf, ipaddr);
    if (status != CI_SUCCESS) {
      goto done;
    }

    status = ci_buf_append_str(ipbuf, "]");
    if (status != CI_SUCCESS) {
      goto done;
    }

    if (port) {
      status = ci_buf_append_str(ipbuf, ":");
      if (status != CI_SUCCESS) {
        goto done;
      }
      status = ci_buf_append_num_dec(ipbuf, port, 0);
      if (status != CI_SUCCESS) {
        goto done;
      }
    }

    if (ll_scope) {
      status = ci_buf_append_str(ipbuf, "%");
      if (status != CI_SUCCESS) {
        goto done;
      }
      status = ci_buf_append_num_dec(ipbuf, ll_scope, 0);
      if (status != CI_SUCCESS) {
        goto done;
      }
    }

    ipstr = ci_buf_finish_str(ipbuf, NULL);
    ipbuf = NULL;
    if (ipstr == NULL) {
      status = CI_ENOMEM;
      goto done;
    }

    status = ci_sconfig_append_fromstr(channel, &sysconfig->sconfig, ipstr,
                                         CI_TRUE);

    ci_free(ipstr);
    if (status != CI_SUCCESS) {
      goto done;
    }
  }

  while ((entries < MAXDNSRCH) && res.dnsrch[entries]) {
    entries++;
  }

  if (entries) {
    sysconfig->domains = ci_malloc_zero(entries * sizeof(char *));
    if (sysconfig->domains == NULL) {
      status = CI_ENOMEM;
      goto done;
    } else {
      sysconfig->ndomains = entries;
      for (i = 0; i < sysconfig->ndomains; i++) {
        sysconfig->domains[i] = ci_strdup(res.dnsrch[i]);
        if (sysconfig->domains[i] == NULL) {
          status = CI_ENOMEM;
          goto done;
        }
      }
    }
  }

  if (res.ndots >= 0) {
    sysconfig->ndots = (size_t)res.ndots;
  }
/* Apple does not allow configuration of retry, so this is a static dummy
 * value, ignore */
#  ifndef __APPLE__
  if (res.retry > 0) {
    sysconfig->tries = (size_t)res.retry;
  }
#  endif
  if (res.options & RES_ROTATE) {
    sysconfig->rotate = CI_TRUE;
  }

  if (res.retrans > 0) {
/* Apple does not allow configuration of retrans, so this is a dummy value
 * that is extremely high (5s) */
#  ifndef __APPLE__
    if (res.retrans > 0) {
      sysconfig->timeout_ms = (unsigned int)res.retrans * 1000;
    }
#  endif
  }

done:
  ci_buf_destroy(ipbuf);
  res_ndestroy(&res);
  return status;
}
#endif

static void ci_sysconfig_free(ci_sysconfig_t *sysconfig)
{
  ci_llist_destroy(sysconfig->sconfig);
  ci_strsplit_free(sysconfig->domains, sysconfig->ndomains);
  ci_free(sysconfig->sortlist);
  ci_free(sysconfig->lookups);
  memset(sysconfig, 0, sizeof(*sysconfig));
}

static ci_status_t ci_sysconfig_apply(ci_channel_t         *channel,
                                          const ci_sysconfig_t *sysconfig)
{
  ci_status_t status;

  if (sysconfig->sconfig && !(channel->optmask & CI_OPT_SERVERS)) {
    status = ci_servers_update(channel, sysconfig->sconfig, CI_FALSE);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  if (sysconfig->domains && !(channel->optmask & CI_OPT_DOMAINS)) {
    /* Make sure we duplicate first then replace so even if there is
     * CI_ENOMEM, the channel stays in a good state */
    char **temp =
      ci_strsplit_duplicate(sysconfig->domains, sysconfig->ndomains);
    if (temp == NULL) {
      return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    ci_strsplit_free(channel->domains, channel->ndomains);
    channel->domains  = temp;
    channel->ndomains = sysconfig->ndomains;
  }

  if (sysconfig->lookups && !(channel->optmask & CI_OPT_LOOKUPS)) {
    char *temp = ci_strdup(sysconfig->lookups);
    if (temp == NULL) {
      return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    ci_free(channel->lookups);
    channel->lookups = temp;
  }

  if (sysconfig->sortlist && !(channel->optmask & CI_OPT_SORTLIST)) {
    struct apattern *temp =
      ci_malloc(sizeof(*channel->sortlist) * sysconfig->nsortlist);
    if (temp == NULL) {
      return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
    memcpy(temp, sysconfig->sortlist,
           sizeof(*channel->sortlist) * sysconfig->nsortlist);

    ci_free(channel->sortlist);
    channel->sortlist = temp;
    channel->nsort    = sysconfig->nsortlist;
  }

  if (!(channel->optmask & CI_OPT_NDOTS)) {
    channel->ndots = sysconfig->ndots;
  }

  if (sysconfig->tries && !(channel->optmask & CI_OPT_TRIES)) {
    channel->tries = sysconfig->tries;
  }

  if (sysconfig->timeout_ms && !(channel->optmask & CI_OPT_TIMEOUTMS)) {
    channel->timeout = sysconfig->timeout_ms;
  }

  if (!(channel->optmask & (CI_OPT_ROTATE | CI_OPT_NOROTATE))) {
    channel->rotate = sysconfig->rotate;
  }

  if (sysconfig->usevc) {
    channel->flags |= CI_FLAG_USEVC;
  }

  return CI_SUCCESS;
}

ci_status_t ci_init_by_sysconfig(ci_channel_t *channel)
{
  ci_status_t    status;
  ci_sysconfig_t sysconfig;

  memset(&sysconfig, 0, sizeof(sysconfig));
  sysconfig.ndots = 1; /* Default value if not otherwise set */

#if defined(USE_WINSOCK)
  status = ci_init_sysconfig_windows(channel, &sysconfig);
#elif defined(__MVS__)
  status = ci_init_sysconfig_mvs(channel, &sysconfig);
#elif defined(__riscos__)
  status = ci_init_sysconfig_riscos(channel, &sysconfig);
#elif defined(WATT32)
  status = ci_init_sysconfig_watt32(channel, &sysconfig);
#elif defined(ANDROID) || defined(__ANDROID__)
  status = ci_init_sysconfig_android(channel, &sysconfig);
#elif defined(__APPLE__)
  status = ci_init_sysconfig_macos(channel, &sysconfig);
#elif defined(CI_USE_LIBRESOLV)
  status = ci_init_sysconfig_libresolv(channel, &sysconfig);
#else
  status = ci_init_sysconfig_files(channel, &sysconfig);
#endif

  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Environment is supposed to override sysconfig */
  status = ci_init_by_environment(&sysconfig);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Lock when applying the configuration to the channel.  Don't need to
   * lock prior to this. */

  ci_channel_lock(channel);

  status = ci_sysconfig_apply(channel, &sysconfig);
  ci_channel_unlock(channel);

  if (status != CI_SUCCESS) {
    goto done;
  }

done:
  ci_sysconfig_free(&sysconfig);

  return status;
}
