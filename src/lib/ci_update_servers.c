/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2008 Daniel Stenberg
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

#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_NET_IF_H
#  include <net/if.h>
#endif
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

#if defined(USE_WINSOCK)
#  if defined(HAVE_IPHLPAPI_H)
#    include <iphlpapi.h>
#  endif
#  if defined(HAVE_NETIOAPI_H)
#    include <netioapi.h>
#  endif
#endif

#include "ci_data.h"
#include "ci_inet_net_pton.h"

typedef struct {
  struct ci_addr addr;
  unsigned short   tcp_port;
  unsigned short   udp_port;

  char             ll_iface[IF_NAMESIZE];
  unsigned int     ll_scope;
} ci_sconfig_t;

static ci_bool_t ci_addr_match(const struct ci_addr *addr1,
                                   const struct ci_addr *addr2)
{
  if (addr1 == NULL && addr2 == NULL) {
    return CI_TRUE; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (addr1 == NULL || addr2 == NULL) {
    return CI_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (addr1->family != addr2->family) {
    return CI_FALSE;
  }

  if (addr1->family == AF_INET && memcmp(&addr1->addr.addr4, &addr2->addr.addr4,
                                         sizeof(addr1->addr.addr4)) == 0) {
    return CI_TRUE;
  }

  if (addr1->family == AF_INET6 &&
      memcmp(&addr1->addr.addr6._S6_un._S6_u8, &addr2->addr.addr6._S6_un._S6_u8,
             sizeof(addr1->addr.addr6._S6_un._S6_u8)) == 0) {
    return CI_TRUE;
  }

  return CI_FALSE;
}

ci_bool_t ci_subnet_match(const struct ci_addr *addr,
                              const struct ci_addr *subnet,
                              unsigned char           netmask)
{
  const unsigned char *addr_ptr;
  const unsigned char *subnet_ptr;
  size_t               len;
  size_t               i;

  if (addr == NULL || subnet == NULL) {
    return CI_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (addr->family != subnet->family) {
    return CI_FALSE;
  }

  if (addr->family == AF_INET) {
    addr_ptr   = (const unsigned char *)&addr->addr.addr4;
    subnet_ptr = (const unsigned char *)&subnet->addr.addr4;
    len        = 4;

    if (netmask > 32) {
      return CI_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  } else if (addr->family == AF_INET6) {
    addr_ptr   = (const unsigned char *)&addr->addr.addr6;
    subnet_ptr = (const unsigned char *)&subnet->addr.addr6;
    len        = 16;

    if (netmask > 128) {
      return CI_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  } else {
    return CI_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  for (i = 0; i < len && netmask > 0; i++) {
    unsigned char mask = 0xff;
    if (netmask < 8) {
      mask    <<= (8 - netmask);
      netmask   = 0;
    } else {
      netmask -= 8;
    }

    if ((addr_ptr[i] & mask) != (subnet_ptr[i] & mask)) {
      return CI_FALSE;
    }
  }

  return CI_TRUE;
}

ci_bool_t ci_addr_is_linklocal(const struct ci_addr *addr)
{
  struct ci_addr    subnet;
  const unsigned char subnetaddr[16] = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00 };

  /* fe80::/10 */
  subnet.family = AF_INET6;
  memcpy(&subnet.addr.addr6, subnetaddr, 16);

  return ci_subnet_match(addr, &subnet, 10);
}

static ci_bool_t ci_server_blacklisted(const struct ci_addr *addr)
{
  /* A list of blacklisted IPv6 subnets. */
  const struct {
    const unsigned char netbase[16];
    unsigned char       netmask;
  } blacklist_v6[] = {
    /* fec0::/10 was deprecated by [RFC3879] in September 2004. Formerly a
     * Site-Local scoped address prefix.  These are never valid DNS servers,
     * but are known to be returned at least sometimes on Windows and Android.
     */
    { { 0xfe, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00 },
     10 }
  };

  size_t i;

  if (addr->family != AF_INET6) {
    return CI_FALSE;
  }

  /* See if ipaddr matches any of the entries in the blacklist. */
  for (i = 0; i < sizeof(blacklist_v6) / sizeof(*blacklist_v6); i++) {
    struct ci_addr subnet;
    subnet.family = AF_INET6;
    memcpy(&subnet.addr.addr6, blacklist_v6[i].netbase, 16);
    if (ci_subnet_match(addr, &subnet, blacklist_v6[i].netmask)) {
      return CI_TRUE;
    }
  }
  return CI_FALSE;
}

static ci_status_t parse_nameserver_uri(ci_buf_t     *buf,
                                          ci_sconfig_t *sconfig)
{
  ci_uri_t   *uri    = NULL;
  ci_status_t status = CI_SUCCESS;
  const char   *port;
  char         *ll_scope;
  char          hoststr[256];
  size_t        addrlen;

  status = ci_uri_parse_buf(&uri, buf);
  if (status != CI_SUCCESS) {
    return status;
  }

  if (!ci_streq("dns", ci_uri_get_scheme(uri))) {
    status = CI_EBADSTR;
    goto done;
  }

  ci_strcpy(hoststr, ci_uri_get_host(uri), sizeof(hoststr));
  ll_scope = strchr(hoststr, '%');
  if (ll_scope != NULL) {
    *ll_scope = 0;
    ll_scope++;
    ci_strcpy(sconfig->ll_iface, ll_scope, sizeof(sconfig->ll_iface));
  }

  /* Convert ip address from string to network byte order */
  sconfig->addr.family = AF_UNSPEC;
  if (ci_dns_pton(hoststr, &sconfig->addr, &addrlen) == NULL) {
    status = CI_EBADSTR;
    goto done;
  }

  sconfig->udp_port = ci_uri_get_port(uri);
  sconfig->tcp_port = sconfig->udp_port;
  port              = ci_uri_get_query_key(uri, "tcpport");
  if (port != NULL) {
    sconfig->tcp_port = (unsigned short)atoi(port);
  }

done:
  ci_uri_destroy(uri);
  return status;
}

/* Parse address and port in these formats, either ipv4 or ipv6 addresses
 * are allowed:
 *   ipaddr
 *   ipv4addr:port
 *   [ipaddr]
 *   [ipaddr]:port
 *
 * Modifiers: %iface
 *
 * TODO: #domain modifier
 *
 * If a port is not specified, will set port to 0.
 *
 * Will fail if an IPv6 nameserver as detected by
 * ci_ipv6_server_blacklisted()
 *
 * Returns an error code on failure, else CI_SUCCESS
 */

static ci_status_t parse_nameserver(ci_buf_t *buf, ci_sconfig_t *sconfig)
{
  ci_status_t status;
  char          ipaddr[INET6_ADDRSTRLEN] = "";
  size_t        addrlen;

  memset(sconfig, 0, sizeof(*sconfig));

  /* Consume any leading whitespace */
  ci_buf_consume_whitespace(buf, CI_TRUE);

  /* pop off IP address.  If it is in [ ] then it can be ipv4 or ipv6.  If
   * not, ipv4 only */
  if (ci_buf_begins_with(buf, (const unsigned char *)"[", 1)) {
    /* Consume [ */
    ci_buf_consume(buf, 1);

    ci_buf_tag(buf);

    /* Consume until ] */
    if (ci_buf_consume_until_charset(buf, (const unsigned char *)"]", 1,
                                       CI_TRUE) == SIZE_MAX) {
      return CI_EBADSTR;
    }

    status = ci_buf_tag_fetch_string(buf, ipaddr, sizeof(ipaddr));
    if (status != CI_SUCCESS) {
      return status;
    }

    /* Skip over ] */
    ci_buf_consume(buf, 1);
  } else {
    size_t offset;

    /* Not in [ ], see if '.' is in first 4 characters, if it is, then its ipv4,
     * otherwise treat as ipv6 */
    ci_buf_tag(buf);

    offset = ci_buf_consume_until_charset(buf, (const unsigned char *)".", 1,
                                            CI_TRUE);
    ci_buf_tag_rollback(buf);
    ci_buf_tag(buf);

    if (offset > 0 && offset < 4) {
      /* IPv4 */
      if (ci_buf_consume_charset(buf, (const unsigned char *)"0123456789.",
                                   11) == 0) {
        return CI_EBADSTR;
      }
    } else {
      /* IPv6 */
      const unsigned char ipv6_charset[] = "ABCDEFabcdef0123456789.:";
      if (ci_buf_consume_charset(buf, ipv6_charset,
                                   sizeof(ipv6_charset) - 1) == 0) {
        return CI_EBADSTR;
      }
    }

    status = ci_buf_tag_fetch_string(buf, ipaddr, sizeof(ipaddr));
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  /* Convert ip address from string to network byte order */
  sconfig->addr.family = AF_UNSPEC;
  if (ci_dns_pton(ipaddr, &sconfig->addr, &addrlen) == NULL) {
    return CI_EBADSTR;
  }

  /* Pull off port */
  if (ci_buf_begins_with(buf, (const unsigned char *)":", 1)) {
    char portstr[6];

    /* Consume : */
    ci_buf_consume(buf, 1);

    ci_buf_tag(buf);

    /* Read numbers */
    if (ci_buf_consume_charset(buf, (const unsigned char *)"0123456789",
                                 10) == 0) {
      return CI_EBADSTR;
    }

    status = ci_buf_tag_fetch_string(buf, portstr, sizeof(portstr));
    if (status != CI_SUCCESS) {
      return status;
    }

    sconfig->udp_port = (unsigned short)atoi(portstr);
    sconfig->tcp_port = sconfig->udp_port;
  }

  /* Pull off interface modifier */
  if (ci_buf_begins_with(buf, (const unsigned char *)"%", 1)) {
    const unsigned char iface_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                          "abcdefghijklmnopqrstuvwxyz"
                                          "0123456789.-_\\:{}";
    /* Consume % */
    ci_buf_consume(buf, 1);

    ci_buf_tag(buf);

    if (ci_buf_consume_charset(buf, iface_charset,
                                 sizeof(iface_charset) - 1) == 0) {
      return CI_EBADSTR;
    }

    status = ci_buf_tag_fetch_string(buf, sconfig->ll_iface,
                                       sizeof(sconfig->ll_iface));
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  /* Consume any trailing whitespace so we can bail out if there is something
   * after we didn't read */
  ci_buf_consume_whitespace(buf, CI_TRUE);

  if (ci_buf_len(buf) != 0) {
    return CI_EBADSTR;
  }

  return CI_SUCCESS;
}

static ci_status_t ci_sconfig_linklocal(const ci_channel_t *channel,
                                            ci_sconfig_t       *s,
                                            const char           *ll_iface)
{
  unsigned int ll_scope = 0;


  if (ci_str_isnum(ll_iface)) {
    char ifname[IF_NAMESIZE] = "";
    ll_scope                 = (unsigned int)atoi(ll_iface);
    if (channel->sock_funcs.aif_indextoname == NULL ||
        channel->sock_funcs.aif_indextoname(ll_scope, ifname, sizeof(ifname),
                                            channel->sock_func_cb_data) ==
          NULL) {
      DEBUGF(fprintf(stderr, "Interface %s for ipv6 Link Local not found\n",
                     ll_iface));
      return CI_ENOTFOUND;
    }
    ci_strcpy(s->ll_iface, ifname, sizeof(s->ll_iface));
    s->ll_scope = ll_scope;
    return CI_SUCCESS;
  }

  if (channel->sock_funcs.aif_nametoindex != NULL) {
    ll_scope =
      channel->sock_funcs.aif_nametoindex(ll_iface, channel->sock_func_cb_data);
  }
  if (ll_scope == 0) {
    DEBUGF(fprintf(stderr, "Interface %s for ipv6 Link Local not found\n",
                   ll_iface));
    return CI_ENOTFOUND;
  }
  ci_strcpy(s->ll_iface, ll_iface, sizeof(s->ll_iface));
  s->ll_scope = ll_scope;
  return CI_SUCCESS;
}

ci_status_t ci_sconfig_append(const ci_channel_t   *channel,
                                  ci_llist_t          **sconfig,
                                  const struct ci_addr *addr,
                                  unsigned short          udp_port,
                                  unsigned short tcp_port, const char *ll_iface)
{
  ci_sconfig_t *s;
  ci_status_t   status;

  if (sconfig == NULL || addr == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* Silently skip blacklisted IPv6 servers. */
  if (ci_server_blacklisted(addr)) {
    return CI_SUCCESS;
  }

  s = ci_malloc_zero(sizeof(*s));
  if (s == NULL) {
    return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (*sconfig == NULL) {
    *sconfig = ci_llist_create(ci_free);
    if (*sconfig == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto fail;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  memcpy(&s->addr, addr, sizeof(s->addr));
  s->udp_port = udp_port;
  s->tcp_port = tcp_port;

  /* Handle link-local enumeration. If an interface is specified on a
   * non-link-local address, we'll simply end up ignoring that */
  if (ci_addr_is_linklocal(&s->addr)) {
    if (ci_strlen(ll_iface) == 0) {
      /* Silently ignore this entry, we require an interface */
      status = CI_SUCCESS;
      goto fail;
    }
    status = ci_sconfig_linklocal(channel, s, ll_iface);
    /* Silently ignore this entry, we can't validate the interface */
    if (status != CI_SUCCESS) {
      status = CI_SUCCESS;
      goto fail;
    }
  }

  if (ci_llist_insert_last(*sconfig, s) == NULL) {
    status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto fail;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  return CI_SUCCESS;

fail:
  ci_free(s);

  return status;
}

/* Add the IPv4 or IPv6 nameservers in str (separated by commas or spaces) to
 * the servers list, updating servers and nservers as required.
 *
 * If a nameserver is encapsulated in [ ] it may optionally include a port
 * suffix, e.g.:
 *    [127.0.0.1]:59591
 *
 * The extended format is required to support OpenBSD's resolv.conf format:
 *   https://man.openbsd.org/OpenBSD-5.1/resolv.conf.5
 * As well as MacOS libresolv that may include a non-default port number.
 *
 * This will silently ignore blacklisted IPv6 nameservers as detected by
 * ci_ipv6_server_blacklisted().
 *
 * Returns an error code on failure, else CI_SUCCESS.
 */
ci_status_t ci_sconfig_append_fromstr(const ci_channel_t *channel,
                                          ci_llist_t        **sconfig,
                                          const char           *str,
                                          ci_bool_t           ignore_invalid)
{
  ci_status_t status = CI_SUCCESS;
  ci_buf_t   *buf    = NULL;
  ci_array_t *list   = NULL;
  size_t        num;
  size_t        i;

  /* On Windows, there may be more than one nameserver specified in the same
   * registry key, so we parse input as a space or comma separated list.
   */
  buf = ci_buf_create_const((const unsigned char *)str, ci_strlen(str));
  if (buf == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  status = ci_buf_split(buf, (const unsigned char *)" ,", 2,
                          CI_BUF_SPLIT_NONE, 0, &list);
  if (status != CI_SUCCESS) {
    goto done;
  }

  num = ci_array_len(list);
  for (i = 0; i < num; i++) {
    ci_buf_t   **bufptr = ci_array_at(list, i);
    ci_buf_t    *entry  = *bufptr;
    ci_sconfig_t s;

    status = parse_nameserver_uri(entry, &s);
    if (status != CI_SUCCESS) {
      status = parse_nameserver(entry, &s);
    }

    if (status != CI_SUCCESS) {
      if (ignore_invalid) {
        continue;
      } else {
        goto done;
      }
    }

    status = ci_sconfig_append(channel, sconfig, &s.addr, s.udp_port,
                                 s.tcp_port, s.ll_iface);
    if (status != CI_SUCCESS) {
      goto done; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  status = CI_SUCCESS;

done:
  ci_array_destroy(list);
  ci_buf_destroy(buf);
  return status;
}

static unsigned short ci_sconfig_get_port(const ci_channel_t *channel,
                                            const ci_sconfig_t *s,
                                            ci_bool_t           is_tcp)
{
  unsigned short port = is_tcp ? s->tcp_port : s->udp_port;

  if (port == 0) {
    port = is_tcp ? channel->tcp_port : channel->udp_port;
  }

  if (port == 0) {
    port = 53;
  }

  return port;
}

static ci_slist_node_t *ci_server_find(const ci_channel_t *channel,
                                           const ci_sconfig_t *s)
{
  ci_slist_node_t *node;

  for (node = ci_slist_node_first(channel->servers); node != NULL;
       node = ci_slist_node_next(node)) {
    const ci_server_t *server = ci_slist_node_val(node);

    if (!ci_addr_match(&server->addr, &s->addr)) {
      continue;
    }

    if (server->tcp_port != ci_sconfig_get_port(channel, s, CI_TRUE)) {
      continue;
    }

    if (server->udp_port != ci_sconfig_get_port(channel, s, CI_FALSE)) {
      continue;
    }

    return node;
  }
  return NULL;
}

static ci_bool_t ci_server_isdup(const ci_channel_t *channel,
                                     ci_llist_node_t    *s)
{
  /* Scan backwards to see if this is a duplicate */
  ci_llist_node_t    *prev;
  const ci_sconfig_t *server = ci_llist_node_val(s);

  for (prev = ci_llist_node_prev(s); prev != NULL;
       prev = ci_llist_node_prev(prev)) {
    const ci_sconfig_t *p = ci_llist_node_val(prev);

    if (!ci_addr_match(&server->addr, &p->addr)) {
      continue;
    }

    if (ci_sconfig_get_port(channel, server, CI_TRUE) !=
        ci_sconfig_get_port(channel, p, CI_TRUE)) {
      continue;
    }

    if (ci_sconfig_get_port(channel, server, CI_FALSE) !=
        ci_sconfig_get_port(channel, p, CI_FALSE)) {
      continue;
    }

    return CI_TRUE;
  }

  return CI_FALSE;
}

static ci_status_t ci_server_create(ci_channel_t       *channel,
                                        const ci_sconfig_t *sconfig,
                                        size_t                idx)
{
  ci_status_t  status;
  ci_server_t *server = ci_malloc_zero(sizeof(*server));

  if (server == NULL) {
    return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  server->idx         = idx;
  server->channel     = channel;
  server->udp_port    = ci_sconfig_get_port(channel, sconfig, CI_FALSE);
  server->tcp_port    = ci_sconfig_get_port(channel, sconfig, CI_TRUE);
  server->addr.family = sconfig->addr.family;
  server->next_retry_time.sec  = 0;
  server->next_retry_time.usec = 0;

  if (sconfig->addr.family == AF_INET) {
    memcpy(&server->addr.addr.addr4, &sconfig->addr.addr.addr4,
           sizeof(server->addr.addr.addr4));
  } else if (sconfig->addr.family == AF_INET6) {
    memcpy(&server->addr.addr.addr6, &sconfig->addr.addr.addr6,
           sizeof(server->addr.addr.addr6));
  }

  /* Copy over link-local settings */
  if (ci_strlen(sconfig->ll_iface)) {
    ci_strcpy(server->ll_iface, sconfig->ll_iface, sizeof(server->ll_iface));
    server->ll_scope = sconfig->ll_scope;
  }

  server->connections = ci_llist_create(NULL);
  if (server->connections == NULL) {
    status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (ci_slist_insert(channel->servers, server) == NULL) {
    status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  status = CI_SUCCESS;

done:
  if (status != CI_SUCCESS) {
    ci_destroy_server(server); /* LCOV_EXCL_LINE: OutOfMemory */
  }

  return status;
}

static ci_bool_t ci_server_in_newconfig(const ci_server_t *server,
                                            ci_llist_t        *srvlist)
{
  ci_llist_node_t    *node;
  const ci_channel_t *channel = server->channel;

  for (node = ci_llist_node_first(srvlist); node != NULL;
       node = ci_llist_node_next(node)) {
    const ci_sconfig_t *s = ci_llist_node_val(node);

    if (!ci_addr_match(&server->addr, &s->addr)) {
      continue;
    }

    if (server->tcp_port != ci_sconfig_get_port(channel, s, CI_TRUE)) {
      continue;
    }

    if (server->udp_port != ci_sconfig_get_port(channel, s, CI_FALSE)) {
      continue;
    }

    return CI_TRUE;
  }

  return CI_FALSE;
}

static ci_bool_t ci_servers_remove_stale(ci_channel_t *channel,
                                             ci_llist_t   *srvlist)
{
  ci_bool_t        stale_removed = CI_FALSE;
  ci_slist_node_t *snode         = ci_slist_node_first(channel->servers);

  while (snode != NULL) {
    ci_slist_node_t   *snext  = ci_slist_node_next(snode);
    const ci_server_t *server = ci_slist_node_val(snode);
    if (!ci_server_in_newconfig(server, srvlist)) {
      /* This will clean up all server state via the destruction callback and
       * move any queries to new servers */
      ci_slist_node_destroy(snode);
      stale_removed = CI_TRUE;
    }
    snode = snext;
  }
  return stale_removed;
}

static void ci_servers_trim_single(ci_channel_t *channel)
{
  while (ci_slist_len(channel->servers) > 1) {
    ci_slist_node_destroy(ci_slist_node_last(channel->servers));
  }
}

ci_status_t ci_servers_update(ci_channel_t *channel,
                                  ci_llist_t   *server_list,
                                  ci_bool_t     user_specified)
{
  ci_llist_node_t *node;
  size_t             idx = 0;
  ci_status_t      status;
  ci_bool_t        list_changed = CI_FALSE;

  if (channel == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* NOTE: a NULL or zero entry server list is considered valid due to
   *       real-world people needing support for this for their test harnesses
   */

  /* Add new entries */
  for (node = ci_llist_node_first(server_list); node != NULL;
       node = ci_llist_node_next(node)) {
    const ci_sconfig_t *sconfig = ci_llist_node_val(node);
    ci_slist_node_t    *snode;

    /* If a server has already appeared in the list of new servers, skip it. */
    if (ci_server_isdup(channel, node)) {
      continue;
    }

    snode = ci_server_find(channel, sconfig);
    if (snode != NULL) {
      ci_server_t *server = ci_slist_node_val(snode);

      /* Copy over link-local settings.  Its possible some of this data has
       * changed, maybe ...  */
      if (ci_strlen(sconfig->ll_iface)) {
        ci_strcpy(server->ll_iface, sconfig->ll_iface,
                    sizeof(server->ll_iface));
        server->ll_scope = sconfig->ll_scope;
      }

      if (server->idx != idx) {
        server->idx = idx;
        /* Index changed, reinsert node, doesn't require any memory
         * allocations so can't fail. */
        ci_slist_node_reinsert(snode);
      }
    } else {
      status = ci_server_create(channel, sconfig, idx);
      if (status != CI_SUCCESS) {
        goto done;
      }

      list_changed = CI_TRUE;
    }

    idx++;
  }

  /* Remove any servers that don't exist in the current configuration */
  if (ci_servers_remove_stale(channel, server_list)) {
    list_changed = CI_TRUE;
  }

  /* Trim to one server if CI_FLAG_PRIMARY is set. */
  if (channel->flags & CI_FLAG_PRIMARY) {
    ci_servers_trim_single(channel);
  }

  if (user_specified) {
    /* Save servers as if they were passed in as an option */
    channel->optmask |= CI_OPT_SERVERS;
  }

  /* Clear any cached query results only if the server list changed */
  if (list_changed) {
    ci_qcache_flush(channel->qcache);
  }

  status = CI_SUCCESS;

done:
  return status;
}

static ci_status_t
  ci_addr_node_to_sconfig_llist(const struct ci_addr_node *servers,
                                  ci_llist_t               **llist)
{
  const struct ci_addr_node *node;
  ci_llist_t                *s;

  *llist = NULL;

  s = ci_llist_create(ci_free);
  if (s == NULL) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  for (node = servers; node != NULL; node = node->next) {
    ci_sconfig_t *sconfig;

    /* Invalid entry */
    if (node->family != AF_INET && node->family != AF_INET6) {
      continue;
    }

    sconfig = ci_malloc_zero(sizeof(*sconfig));
    if (sconfig == NULL) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    sconfig->addr.family = node->family;
    if (node->family == AF_INET) {
      memcpy(&sconfig->addr.addr.addr4, &node->addr.addr4,
             sizeof(sconfig->addr.addr.addr4));
    } else if (sconfig->addr.family == AF_INET6) {
      memcpy(&sconfig->addr.addr.addr6, &node->addr.addr6,
             sizeof(sconfig->addr.addr.addr6));
    }

    if (ci_llist_insert_last(s, sconfig) == NULL) {
      ci_free(sconfig); /* LCOV_EXCL_LINE: OutOfMemory */
      goto fail;          /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  *llist = s;
  return CI_SUCCESS;

/* LCOV_EXCL_START: OutOfMemory */
fail:
  ci_llist_destroy(s);
  return CI_ENOMEM;
  /* LCOV_EXCL_STOP */
}

static ci_status_t
  ci_addrpnode_to_sconfig_llist(const struct ci_addr_port_node *servers,
                                  ci_llist_t                    **llist)
{
  const struct ci_addr_port_node *node;
  ci_llist_t                     *s;

  *llist = NULL;

  s = ci_llist_create(ci_free);
  if (s == NULL) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  for (node = servers; node != NULL; node = node->next) {
    ci_sconfig_t *sconfig;

    /* Invalid entry */
    if (node->family != AF_INET && node->family != AF_INET6) {
      continue;
    }

    sconfig = ci_malloc_zero(sizeof(*sconfig));
    if (sconfig == NULL) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    sconfig->addr.family = node->family;
    if (node->family == AF_INET) {
      memcpy(&sconfig->addr.addr.addr4, &node->addr.addr4,
             sizeof(sconfig->addr.addr.addr4));
    } else if (sconfig->addr.family == AF_INET6) {
      memcpy(&sconfig->addr.addr.addr6, &node->addr.addr6,
             sizeof(sconfig->addr.addr.addr6));
    }

    sconfig->tcp_port = (unsigned short)node->tcp_port;
    sconfig->udp_port = (unsigned short)node->udp_port;

    if (ci_llist_insert_last(s, sconfig) == NULL) {
      ci_free(sconfig); /* LCOV_EXCL_LINE: OutOfMemory */
      goto fail;          /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  *llist = s;
  return CI_SUCCESS;

/* LCOV_EXCL_START: OutOfMemory */
fail:
  ci_llist_destroy(s);
  return CI_ENOMEM;
  /* LCOV_EXCL_STOP */
}

ci_status_t ci_in_addr_to_sconfig_llist(const struct in_addr *servers,
                                            size_t                nservers,
                                            ci_llist_t        **llist)
{
  size_t        i;
  ci_llist_t *s;

  *llist = NULL;

  s = ci_llist_create(ci_free);
  if (s == NULL) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  for (i = 0; servers != NULL && i < nservers; i++) {
    ci_sconfig_t *sconfig;

    sconfig = ci_malloc_zero(sizeof(*sconfig));
    if (sconfig == NULL) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    sconfig->addr.family = AF_INET;
    memcpy(&sconfig->addr.addr.addr4, &servers[i],
           sizeof(sconfig->addr.addr.addr4));

    if (ci_llist_insert_last(s, sconfig) == NULL) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  *llist = s;
  return CI_SUCCESS;

/* LCOV_EXCL_START: OutOfMemory */
fail:
  ci_llist_destroy(s);
  return CI_ENOMEM;
  /* LCOV_EXCL_STOP */
}

static ci_bool_t ci_server_use_uri(const ci_server_t *server)
{
  /* Currently only reason to use new format is if the ports for udp and tcp
   * are different */
  if (server->tcp_port != server->udp_port) {
    return CI_TRUE;
  }
  return CI_FALSE;
}

static ci_status_t ci_get_server_addr_uri(const ci_server_t *server,
                                              ci_buf_t          *buf)
{
  ci_uri_t   *uri = NULL;
  ci_status_t status;
  char          addr[INET6_ADDRSTRLEN];

  uri = ci_uri_create();
  if (uri == NULL) {
    return CI_ENOMEM;
  }

  status = ci_uri_set_scheme(uri, "dns");
  if (status != CI_SUCCESS) {
    goto done;
  }

  ci_inet_ntop(server->addr.family, &server->addr.addr, addr, sizeof(addr));

  if (ci_strlen(server->ll_iface)) {
    char addr_iface[256];

    snprintf(addr_iface, sizeof(addr_iface), "%s%%%s", addr, server->ll_iface);
    status = ci_uri_set_host(uri, addr_iface);
  } else {
    status = ci_uri_set_host(uri, addr);
  }

  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_set_port(uri, server->udp_port);
  if (status != CI_SUCCESS) {
    goto done;
  }

  if (server->udp_port != server->tcp_port) {
    char port[6];
    snprintf(port, sizeof(port), "%d", server->tcp_port);
    status = ci_uri_set_query_key(uri, "tcpport", port);
    if (status != CI_SUCCESS) {
      goto done;
    }
  }

  status = ci_uri_write_buf(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

done:
  ci_uri_destroy(uri);
  return status;
}

/* Write out the details of a server to a buffer */
ci_status_t ci_get_server_addr(const ci_server_t *server, ci_buf_t *buf)
{
  ci_status_t status;
  char          addr[INET6_ADDRSTRLEN];

  if (ci_server_use_uri(server)) {
    return ci_get_server_addr_uri(server, buf);
  }

  /* ipv4addr or [ipv6addr] */
  if (server->addr.family == AF_INET6) {
    status = ci_buf_append_byte(buf, '[');
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  ci_inet_ntop(server->addr.family, &server->addr.addr, addr, sizeof(addr));

  status = ci_buf_append_str(buf, addr);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (server->addr.family == AF_INET6) {
    status = ci_buf_append_byte(buf, ']');
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  /* :port */
  status = ci_buf_append_byte(buf, ':');
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  status = ci_buf_append_num_dec(buf, server->udp_port, 0);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* %iface */
  if (ci_strlen(server->ll_iface)) {
    status = ci_buf_append_byte(buf, '%');
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    status = ci_buf_append_str(buf, server->ll_iface);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  return CI_SUCCESS;
}

int ci_get_servers(const ci_channel_t   *channel,
                     struct ci_addr_node **servers)
{
  struct ci_addr_node *srvr_head = NULL;
  struct ci_addr_node *srvr_last = NULL;
  struct ci_addr_node *srvr_curr;
  ci_status_t          status = CI_SUCCESS;
  ci_slist_node_t     *node;

  if (channel == NULL) {
    return CI_ENODATA;
  }

  ci_channel_lock(channel);

  for (node = ci_slist_node_first(channel->servers); node != NULL;
       node = ci_slist_node_next(node)) {
    const ci_server_t *server = ci_slist_node_val(node);

    /* Allocate storage for this server node appending it to the list */
    srvr_curr = ci_malloc_data(CI_DATATYPE_ADDR_NODE);
    if (!srvr_curr) {
      status = CI_ENOMEM;
      break;
    }
    if (srvr_last) {
      srvr_last->next = srvr_curr;
    } else {
      srvr_head = srvr_curr;
    }
    srvr_last = srvr_curr;

    /* Fill this server node data */
    srvr_curr->family = server->addr.family;
    if (srvr_curr->family == AF_INET) {
      memcpy(&srvr_curr->addr.addr4, &server->addr.addr.addr4,
             sizeof(srvr_curr->addr.addr4));
    } else {
      memcpy(&srvr_curr->addr.addr6, &server->addr.addr.addr6,
             sizeof(srvr_curr->addr.addr6));
    }
  }

  if (status != CI_SUCCESS) {
    ci_free_data(srvr_head);
    srvr_head = NULL;
  }

  *servers = srvr_head;

  ci_channel_unlock(channel);

  return (int)status;
}

int ci_get_servers_ports(const ci_channel_t        *channel,
                           struct ci_addr_port_node **servers)
{
  struct ci_addr_port_node *srvr_head = NULL;
  struct ci_addr_port_node *srvr_last = NULL;
  struct ci_addr_port_node *srvr_curr;
  ci_status_t               status = CI_SUCCESS;
  ci_slist_node_t          *node;

  if (channel == NULL) {
    return CI_ENODATA;
  }

  ci_channel_lock(channel);

  for (node = ci_slist_node_first(channel->servers); node != NULL;
       node = ci_slist_node_next(node)) {
    const ci_server_t *server = ci_slist_node_val(node);

    /* Allocate storage for this server node appending it to the list */
    srvr_curr = ci_malloc_data(CI_DATATYPE_ADDR_PORT_NODE);
    if (!srvr_curr) {
      status = CI_ENOMEM;
      break;
    }
    if (srvr_last) {
      srvr_last->next = srvr_curr;
    } else {
      srvr_head = srvr_curr;
    }
    srvr_last = srvr_curr;

    /* Fill this server node data */
    srvr_curr->family   = server->addr.family;
    srvr_curr->udp_port = server->udp_port;
    srvr_curr->tcp_port = server->tcp_port;

    if (srvr_curr->family == AF_INET) {
      memcpy(&srvr_curr->addr.addr4, &server->addr.addr.addr4,
             sizeof(srvr_curr->addr.addr4));
    } else {
      memcpy(&srvr_curr->addr.addr6, &server->addr.addr.addr6,
             sizeof(srvr_curr->addr.addr6));
    }
  }

  if (status != CI_SUCCESS) {
    ci_free_data(srvr_head);
    srvr_head = NULL;
  }

  *servers = srvr_head;

  ci_channel_unlock(channel);
  return (int)status;
}

int ci_set_servers(ci_channel_t              *channel,
                     const struct ci_addr_node *servers)
{
  ci_llist_t *slist;
  ci_status_t status;

  if (channel == NULL) {
    return CI_ENODATA;
  }

  status = ci_addr_node_to_sconfig_llist(servers, &slist);
  if (status != CI_SUCCESS) {
    return (int)status;
  }

  ci_channel_lock(channel);
  status = ci_servers_update(channel, slist, CI_TRUE);
  ci_channel_unlock(channel);

  ci_llist_destroy(slist);

  return (int)status;
}

int ci_set_servers_ports(ci_channel_t                   *channel,
                           const struct ci_addr_port_node *servers)
{
  ci_llist_t *slist;
  ci_status_t status;

  if (channel == NULL) {
    return CI_ENODATA;
  }

  status = ci_addrpnode_to_sconfig_llist(servers, &slist);
  if (status != CI_SUCCESS) {
    return (int)status;
  }

  ci_channel_lock(channel);
  status = ci_servers_update(channel, slist, CI_TRUE);
  ci_channel_unlock(channel);

  ci_llist_destroy(slist);

  return (int)status;
}

/* Incoming string format: host[:port][,host[:port]]... */
/* IPv6 addresses with ports require square brackets [fe80::1]:53 */
static ci_status_t set_servers_csv(ci_channel_t *channel, const char *_csv)
{
  ci_status_t status;
  ci_llist_t *slist = NULL;

  if (channel == NULL) {
    return CI_ENODATA;
  }

  if (ci_strlen(_csv) == 0) {
    /* blank all servers */
    ci_channel_lock(channel);
    status = ci_servers_update(channel, NULL, CI_TRUE);
    ci_channel_unlock(channel);
    return status;
  }

  status = ci_sconfig_append_fromstr(channel, &slist, _csv, CI_FALSE);
  if (status != CI_SUCCESS) {
    ci_llist_destroy(slist);
    return status;
  }

  ci_channel_lock(channel);
  status = ci_servers_update(channel, slist, CI_TRUE);
  ci_channel_unlock(channel);

  ci_llist_destroy(slist);

  return status;
}

/* We'll go ahead and honor ports anyhow */
int ci_set_servers_csv(ci_channel_t *channel, const char *_csv)
{
  return (int)set_servers_csv(channel, _csv);
}

int ci_set_servers_ports_csv(ci_channel_t *channel, const char *_csv)
{
  return (int)set_servers_csv(channel, _csv);
}

char *ci_get_servers_csv(const ci_channel_t *channel)
{
  ci_buf_t        *buf = NULL;
  char              *out = NULL;
  ci_slist_node_t *node;

  ci_channel_lock(channel);

  buf = ci_buf_create();
  if (buf == NULL) {
    goto done; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  for (node = ci_slist_node_first(channel->servers); node != NULL;
       node = ci_slist_node_next(node)) {
    ci_status_t        status;
    const ci_server_t *server = ci_slist_node_val(node);

    if (ci_buf_len(buf)) {
      status = ci_buf_append_byte(buf, ',');
      if (status != CI_SUCCESS) {
        goto done; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }

    status = ci_get_server_addr(server, buf);
    if (status != CI_SUCCESS) {
      goto done; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  out = ci_buf_finish_str(buf, NULL);
  buf = NULL;

done:
  ci_channel_unlock(channel);
  ci_buf_destroy(buf);
  return out;
}

void ci_set_server_state_callback(ci_channel_t            *channel,
                                    ci_server_state_callback cb, void *data)
{
  if (channel == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }
  channel->server_state_cb      = cb;
  channel->server_state_cb_data = data;
}
