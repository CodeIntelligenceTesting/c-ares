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
#include "ci_private.h"
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
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
#include <time.h>

/* HOSTS FILE PROCESSING OVERVIEW
 * ==============================
 * The hosts file on the system contains static entries to be processed locally
 * rather than querying the nameserver.  Each row is an IP address followed by
 * a list of space delimited hostnames that match the ip address.  This is used
 * for both forward and reverse lookups.
 *
 * We are caching the entire parsed hosts file for performance reasons.  Some
 * files may be quite sizable and as per Issue #458 can approach 1/2MB in size,
 * and the parse overhead on a rapid succession of queries can be quite large.
 * The entries are stored in forwards and backwards hashtables so we can get
 * O(1) performance on lookup.  The file is cached until the file modification
 * timestamp changes.
 *
 * The hosts file processing is quite unique. It has to merge all related hosts
 * and ips into a single entry due to file formatting requirements.  For
 * instance take the below:
 *
 * 127.0.0.1    localhost.localdomain localhost
 * ::1          localhost.localdomain localhost
 * 192.168.1.1  host.example.com host
 * 192.168.1.5  host.example.com host
 * 2620:1234::1 host.example.com host6.example.com host6 host
 *
 * This will yield 2 entries.
 *  1) ips: 127.0.0.1,::1
 *     hosts: localhost.localdomain,localhost
 *  2) ips: 192.168.1.1,192.168.1.5,2620:1234::1
 *     hosts: host.example.com,host,host6.example.com,host6
 *
 * It could be argued that if searching for 192.168.1.1 that the 'host6'
 * hostnames should not be returned, but this implementation will return them
 * since they are related.  It is unlikely this will matter in the real world.
 */

struct ci_hosts_file {
  time_t               ts;
  /*! cache the filename so we know if the filename changes it automatically
   *  invalidates the cache */
  char                *filename;
  /*! iphash is the owner of the 'entry' object as there is only ever a single
   *  match to the object. */
  ci_htable_strvp_t *iphash;
  /*! hosthash does not own the entry so won't free on destruction */
  ci_htable_strvp_t *hosthash;
};

struct ci_hosts_entry {
  size_t        refcnt; /*! If the entry is stored multiple times in the
                         *  ip address hash, we have to reference count it */
  ci_llist_t *ips;
  ci_llist_t *hosts;
};

const void *ci_dns_pton(const char *ipaddr, struct ci_addr *addr,
                          size_t *out_len)
{
  const void *ptr     = NULL;
  size_t      ptr_len = 0;

  if (ipaddr == NULL || addr == NULL || out_len == NULL) {
    return NULL; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *out_len = 0;

  if (addr->family == AF_INET &&
      ci_inet_pton(AF_INET, ipaddr, &addr->addr.addr4) > 0) {
    ptr     = &addr->addr.addr4;
    ptr_len = sizeof(addr->addr.addr4);
  } else if (addr->family == AF_INET6 &&
             ci_inet_pton(AF_INET6, ipaddr, &addr->addr.addr6) > 0) {
    ptr     = &addr->addr.addr6;
    ptr_len = sizeof(addr->addr.addr6);
  } else if (addr->family == AF_UNSPEC) {
    if (ci_inet_pton(AF_INET, ipaddr, &addr->addr.addr4) > 0) {
      addr->family = AF_INET;
      ptr          = &addr->addr.addr4;
      ptr_len      = sizeof(addr->addr.addr4);
    } else if (ci_inet_pton(AF_INET6, ipaddr, &addr->addr.addr6) > 0) {
      addr->family = AF_INET6;
      ptr          = &addr->addr.addr6;
      ptr_len      = sizeof(addr->addr.addr6);
    }
  }

  *out_len = ptr_len;
  return ptr;
}

static ci_bool_t ci_normalize_ipaddr(const char *ipaddr, char *out,
                                         size_t out_len)
{
  struct ci_addr data;
  const void      *addr;
  size_t           addr_len = 0;

  memset(&data, 0, sizeof(data));
  data.family = AF_UNSPEC;

  addr = ci_dns_pton(ipaddr, &data, &addr_len);
  if (addr == NULL) {
    return CI_FALSE;
  }

  if (!ci_inet_ntop(data.family, addr, out, (ci_socklen_t)out_len)) {
    return CI_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  return CI_TRUE;
}

static void ci_hosts_entry_destroy(ci_hosts_entry_t *entry)
{
  if (entry == NULL) {
    return;
  }

  /* Honor reference counting */
  if (entry->refcnt != 0) {
    entry->refcnt--;
  }

  if (entry->refcnt > 0) {
    return;
  }

  ci_llist_destroy(entry->hosts);
  ci_llist_destroy(entry->ips);
  ci_free(entry);
}

static void ci_hosts_entry_destroy_cb(void *entry)
{
  ci_hosts_entry_destroy(entry);
}

void ci_hosts_file_destroy(ci_hosts_file_t *hf)
{
  if (hf == NULL) {
    return;
  }

  ci_free(hf->filename);
  ci_htable_strvp_destroy(hf->hosthash);
  ci_htable_strvp_destroy(hf->iphash);
  ci_free(hf);
}

static ci_hosts_file_t *ci_hosts_file_create(const char *filename)
{
  ci_hosts_file_t *hf = ci_malloc_zero(sizeof(*hf));
  if (hf == NULL) {
    goto fail;
  }

  hf->ts = time(NULL);

  hf->filename = ci_strdup(filename);
  if (hf->filename == NULL) {
    goto fail;
  }

  hf->iphash = ci_htable_strvp_create(ci_hosts_entry_destroy_cb);
  if (hf->iphash == NULL) {
    goto fail;
  }

  hf->hosthash = ci_htable_strvp_create(NULL);
  if (hf->hosthash == NULL) {
    goto fail;
  }

  return hf;

fail:
  ci_hosts_file_destroy(hf);
  return NULL;
}

typedef enum {
  CI_MATCH_NONE   = 0,
  CI_MATCH_IPADDR = 1,
  CI_MATCH_HOST   = 2
} ci_hosts_file_match_t;

static ci_status_t ci_hosts_file_merge_entry(
  const ci_hosts_file_t *hf, ci_hosts_entry_t *existing,
  ci_hosts_entry_t *entry, ci_hosts_file_match_t matchtype)
{
  ci_llist_node_t *node;

  /* If we matched on IP address, we know there can only be 1, so there's no
   * reason to do anything */
  if (matchtype != CI_MATCH_IPADDR) {
    while ((node = ci_llist_node_first(entry->ips)) != NULL) {
      const char *ipaddr = ci_llist_node_val(node);

      if (ci_htable_strvp_get_direct(hf->iphash, ipaddr) != NULL) {
        ci_llist_node_destroy(node);
        continue;
      }

      ci_llist_node_mvparent_last(node, existing->ips);
    }
  }


  while ((node = ci_llist_node_first(entry->hosts)) != NULL) {
    const char *hostname = ci_llist_node_val(node);

    if (ci_htable_strvp_get_direct(hf->hosthash, hostname) != NULL) {
      ci_llist_node_destroy(node);
      continue;
    }

    ci_llist_node_mvparent_last(node, existing->hosts);
  }

  ci_hosts_entry_destroy(entry);
  return CI_SUCCESS;
}

static ci_hosts_file_match_t
  ci_hosts_file_match(const ci_hosts_file_t *hf, ci_hosts_entry_t *entry,
                        ci_hosts_entry_t **match)
{
  ci_llist_node_t *node;
  *match = NULL;

  for (node = ci_llist_node_first(entry->ips); node != NULL;
       node = ci_llist_node_next(node)) {
    const char *ipaddr = ci_llist_node_val(node);
    *match             = ci_htable_strvp_get_direct(hf->iphash, ipaddr);
    if (*match != NULL) {
      return CI_MATCH_IPADDR;
    }
  }

  for (node = ci_llist_node_first(entry->hosts); node != NULL;
       node = ci_llist_node_next(node)) {
    const char *host = ci_llist_node_val(node);
    *match           = ci_htable_strvp_get_direct(hf->hosthash, host);
    if (*match != NULL) {
      return CI_MATCH_HOST;
    }
  }

  return CI_MATCH_NONE;
}

/*! entry is invalidated upon calling this function, always, even on error */
static ci_status_t ci_hosts_file_add(ci_hosts_file_t  *hosts,
                                         ci_hosts_entry_t *entry)
{
  ci_hosts_entry_t     *match  = NULL;
  ci_status_t           status = CI_SUCCESS;
  ci_llist_node_t      *node;
  ci_hosts_file_match_t matchtype;
  size_t                  num_hostnames;

  /* Record the number of hostnames in this entry file.  If we merge into an
   * existing record, these will be *appended* to the entry, so we'll count
   * backwards when adding to the hosts hashtable */
  num_hostnames = ci_llist_len(entry->hosts);

  matchtype = ci_hosts_file_match(hosts, entry, &match);

  if (matchtype != CI_MATCH_NONE) {
    status = ci_hosts_file_merge_entry(hosts, match, entry, matchtype);
    if (status != CI_SUCCESS) {
      ci_hosts_entry_destroy(entry); /* LCOV_EXCL_LINE: DefensiveCoding */
      return status;                   /* LCOV_EXCL_LINE: DefensiveCoding */
    }
    /* entry was invalidated above by merging */
    entry = match;
  }

  if (matchtype != CI_MATCH_IPADDR) {
    const char *ipaddr = ci_llist_last_val(entry->ips);

    if (!ci_htable_strvp_get(hosts->iphash, ipaddr, NULL)) {
      if (!ci_htable_strvp_insert(hosts->iphash, ipaddr, entry)) {
        ci_hosts_entry_destroy(entry);
        return CI_ENOMEM;
      }
      entry->refcnt++;
    }
  }

  /* Go backwards, on a merge, hostnames are appended.  Breakout once we've
   * consumed all the hosts that we appended */
  for (node = ci_llist_node_last(entry->hosts); node != NULL;
       node = ci_llist_node_prev(node)) {
    const char *val = ci_llist_node_val(node);

    if (num_hostnames == 0) {
      break;
    }

    num_hostnames--;

    /* first hostname match wins.  If we detect a duplicate hostname for another
     * ip it will automatically be added to the same entry */
    if (ci_htable_strvp_get(hosts->hosthash, val, NULL)) {
      continue;
    }

    if (!ci_htable_strvp_insert(hosts->hosthash, val, entry)) {
      return CI_ENOMEM;
    }
  }

  return CI_SUCCESS;
}

static ci_bool_t ci_hosts_entry_isdup(ci_hosts_entry_t *entry,
                                          const char         *host)
{
  ci_llist_node_t *node;

  for (node = ci_llist_node_first(entry->ips); node != NULL;
       node = ci_llist_node_next(node)) {
    const char *myhost = ci_llist_node_val(node);
    if (ci_strcaseeq(myhost, host)) {
      return CI_TRUE;
    }
  }

  return CI_FALSE;
}

static ci_status_t ci_parse_hosts_hostnames(ci_buf_t         *buf,
                                                ci_hosts_entry_t *entry)
{
  entry->hosts = ci_llist_create(ci_free);
  if (entry->hosts == NULL) {
    return CI_ENOMEM;
  }

  /* Parse hostnames and aliases */
  while (ci_buf_len(buf)) {
    char          hostname[256];
    char         *temp;
    ci_status_t status;
    unsigned char comment = '#';

    ci_buf_consume_whitespace(buf, CI_FALSE);

    if (ci_buf_len(buf) == 0) {
      break;
    }

    /* See if it is a comment, if so stop processing */
    if (ci_buf_begins_with(buf, &comment, 1)) {
      break;
    }

    ci_buf_tag(buf);

    /* Must be at end of line */
    if (ci_buf_consume_nonwhitespace(buf) == 0) {
      break;
    }

    status = ci_buf_tag_fetch_string(buf, hostname, sizeof(hostname));
    if (status != CI_SUCCESS) {
      /* Bad entry, just ignore as long as its not the first.  If its the first,
       * it must be valid */
      if (ci_llist_len(entry->hosts) == 0) {
        return CI_EBADSTR;
      }

      continue;
    }

    /* Validate it is a valid hostname characterset */
    if (!ci_is_hostname(hostname)) {
      continue;
    }

    /* Don't add a duplicate to the same entry */
    if (ci_hosts_entry_isdup(entry, hostname)) {
      continue;
    }

    /* Add to list */
    temp = ci_strdup(hostname);
    if (temp == NULL) {
      return CI_ENOMEM;
    }

    if (ci_llist_insert_last(entry->hosts, temp) == NULL) {
      ci_free(temp);
      return CI_ENOMEM;
    }
  }

  /* Must have at least 1 entry */
  if (ci_llist_len(entry->hosts) == 0) {
    return CI_EBADSTR;
  }

  return CI_SUCCESS;
}

static ci_status_t ci_parse_hosts_ipaddr(ci_buf_t          *buf,
                                             ci_hosts_entry_t **entry_out)
{
  char                addr[INET6_ADDRSTRLEN];
  char               *temp;
  ci_hosts_entry_t *entry = NULL;
  ci_status_t       status;

  *entry_out = NULL;

  ci_buf_tag(buf);
  ci_buf_consume_nonwhitespace(buf);
  status = ci_buf_tag_fetch_string(buf, addr, sizeof(addr));
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Validate and normalize the ip address format */
  if (!ci_normalize_ipaddr(addr, addr, sizeof(addr))) {
    return CI_EBADSTR;
  }

  entry = ci_malloc_zero(sizeof(*entry));
  if (entry == NULL) {
    return CI_ENOMEM;
  }

  entry->ips = ci_llist_create(ci_free);
  if (entry->ips == NULL) {
    ci_hosts_entry_destroy(entry);
    return CI_ENOMEM;
  }

  temp = ci_strdup(addr);
  if (temp == NULL) {
    ci_hosts_entry_destroy(entry);
    return CI_ENOMEM;
  }

  if (ci_llist_insert_first(entry->ips, temp) == NULL) {
    ci_free(temp);
    ci_hosts_entry_destroy(entry);
    return CI_ENOMEM;
  }

  *entry_out = entry;

  return CI_SUCCESS;
}

static ci_status_t ci_parse_hosts(const char         *filename,
                                      ci_hosts_file_t **out)
{
  ci_buf_t         *buf    = NULL;
  ci_status_t       status = CI_EBADRESP;
  ci_hosts_file_t  *hf     = NULL;
  ci_hosts_entry_t *entry  = NULL;

  *out = NULL;

  buf = ci_buf_create();
  if (buf == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  status = ci_buf_load_file(filename, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  hf = ci_hosts_file_create(filename);
  if (hf == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  while (ci_buf_len(buf)) {
    unsigned char comment = '#';

    /* -- Start of new line here -- */

    /* Consume any leading whitespace */
    ci_buf_consume_whitespace(buf, CI_FALSE);

    if (ci_buf_len(buf) == 0) {
      break;
    }

    /* See if it is a comment, if so, consume remaining line */
    if (ci_buf_begins_with(buf, &comment, 1)) {
      ci_buf_consume_line(buf, CI_TRUE);
      continue;
    }

    /* Pull off ip address */
    status = ci_parse_hosts_ipaddr(buf, &entry);
    if (status == CI_ENOMEM) {
      goto done;
    }
    if (status != CI_SUCCESS) {
      /* Bad line, consume and go onto next */
      ci_buf_consume_line(buf, CI_TRUE);
      continue;
    }

    /* Parse of the hostnames */
    status = ci_parse_hosts_hostnames(buf, entry);
    if (status == CI_ENOMEM) {
      goto done;
    } else if (status != CI_SUCCESS) {
      /* Bad line, consume and go onto next */
      ci_hosts_entry_destroy(entry);
      entry = NULL;
      ci_buf_consume_line(buf, CI_TRUE);
      continue;
    }

    /* Append the successful entry to the hosts file */
    status = ci_hosts_file_add(hf, entry);
    entry  = NULL; /* is always invalidated by this function, even on error */
    if (status != CI_SUCCESS) {
      goto done;
    }

    /* Go to next line */
    ci_buf_consume_line(buf, CI_TRUE);
  }

  status = CI_SUCCESS;

done:
  ci_hosts_entry_destroy(entry);
  ci_buf_destroy(buf);
  if (status != CI_SUCCESS) {
    ci_hosts_file_destroy(hf);
  } else {
    *out = hf;
  }
  return status;
}

static ci_bool_t ci_hosts_expired(const char              *filename,
                                      const ci_hosts_file_t *hf)
{
  time_t mod_ts = 0;

#ifdef HAVE_STAT
  struct stat st;
  if (stat(filename, &st) == 0) {
    mod_ts = st.st_mtime;
  }
#elif defined(_WIN32)
  struct _stat st;
  if (_stat(filename, &st) == 0) {
    mod_ts = st.st_mtime;
  }
#else
  (void)filename;
#endif

  if (hf == NULL) {
    return CI_TRUE;
  }

  /* Expire every 60s if we can't get a time */
  if (mod_ts == 0) {
    mod_ts =
      time(NULL) - 60; /* LCOV_EXCL_LINE: only on systems without stat() */
  }

  /* If filenames are different, its expired */
  if (!ci_strcaseeq(hf->filename, filename)) {
    return CI_TRUE;
  }

  if (hf->ts <= mod_ts) {
    return CI_TRUE;
  }

  return CI_FALSE;
}

static ci_status_t ci_hosts_path(const ci_channel_t *channel,
                                     ci_bool_t use_env, char **path)
{
  char *path_hosts = NULL;

  *path = NULL;

  if (channel->hosts_path) {
    path_hosts = ci_strdup(channel->hosts_path);
    if (!path_hosts) {
      return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  if (use_env) {
    if (path_hosts) {
      ci_free(path_hosts);
    }

    path_hosts = ci_strdup(getenv("CI_HOSTS"));
    if (!path_hosts) {
      return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  if (!path_hosts) {
#if defined(USE_WINSOCK)
    char  PATH_HOSTS[MAX_PATH] = "";
    char  tmp[MAX_PATH];
    HKEY  hkeyHosts;
    DWORD dwLength = sizeof(tmp);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, WIN_NS_NT_KEY, 0, KEY_READ,
                      &hkeyHosts) != ERROR_SUCCESS) {
      return CI_ENOTFOUND;
    }
    RegQueryValueExA(hkeyHosts, DATABASEPATH, NULL, NULL, (LPBYTE)tmp,
                     &dwLength);
    ExpandEnvironmentStringsA(tmp, PATH_HOSTS, MAX_PATH);
    RegCloseKey(hkeyHosts);
    strcat(PATH_HOSTS, WIN_PATH_HOSTS);
#elif defined(WATT32)
    const char *PATH_HOSTS = _w32_GetHostsFile();

    if (!PATH_HOSTS) {
      return CI_ENOTFOUND;
    }
#endif
    path_hosts = ci_strdup(PATH_HOSTS);
    if (!path_hosts) {
      return CI_ENOMEM;
    }
  }

  *path = path_hosts;
  return CI_SUCCESS;
}

static ci_status_t ci_hosts_update(ci_channel_t *channel,
                                       ci_bool_t     use_env)
{
  ci_status_t status;
  char         *filename = NULL;

  status = ci_hosts_path(channel, use_env, &filename);
  if (status != CI_SUCCESS) {
    return status;
  }

  if (!ci_hosts_expired(filename, channel->hf)) {
    ci_free(filename);
    return CI_SUCCESS;
  }

  ci_hosts_file_destroy(channel->hf);
  channel->hf = NULL;

  status = ci_parse_hosts(filename, &channel->hf);
  ci_free(filename);
  return status;
}

ci_status_t ci_hosts_search_ipaddr(ci_channel_t *channel,
                                       ci_bool_t use_env, const char *ipaddr,
                                       const ci_hosts_entry_t **entry)
{
  ci_status_t status;
  char          addr[INET6_ADDRSTRLEN];

  *entry = NULL;

  status = ci_hosts_update(channel, use_env);
  if (status != CI_SUCCESS) {
    return status;
  }

  if (channel->hf == NULL) {
    return CI_ENOTFOUND; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (!ci_normalize_ipaddr(ipaddr, addr, sizeof(addr))) {
    return CI_EBADNAME;
  }

  *entry = ci_htable_strvp_get_direct(channel->hf->iphash, addr);
  if (*entry == NULL) {
    return CI_ENOTFOUND;
  }

  return CI_SUCCESS;
}

ci_status_t ci_hosts_search_host(ci_channel_t *channel,
                                     ci_bool_t use_env, const char *host,
                                     const ci_hosts_entry_t **entry)
{
  ci_status_t status;

  *entry = NULL;

  status = ci_hosts_update(channel, use_env);
  if (status != CI_SUCCESS) {
    return status;
  }

  if (channel->hf == NULL) {
    return CI_ENOTFOUND; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *entry = ci_htable_strvp_get_direct(channel->hf->hosthash, host);
  if (*entry == NULL) {
    return CI_ENOTFOUND;
  }

  return CI_SUCCESS;
}

static ci_status_t
  ci_hosts_ai_append_cnames(const ci_hosts_entry_t    *entry,
                              struct ci_addrinfo_cname **cnames_out)
{
  struct ci_addrinfo_cname *cname  = NULL;
  struct ci_addrinfo_cname *cnames = NULL;
  const char                 *primaryhost;
  ci_llist_node_t          *node;
  ci_status_t               status;
  size_t                      cnt = 0;

  node        = ci_llist_node_first(entry->hosts);
  primaryhost = ci_llist_node_val(node);
  /* Skip to next node to start with aliases */
  node = ci_llist_node_next(node);

  while (node != NULL) {
    const char *host = ci_llist_node_val(node);

    /* Cap at 100 entries. , some people use
     * https://github.com/StevenBlack/hosts and we don't need 200k+ aliases */
    cnt++;
    if (cnt > 100) {
      break; /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    cname = ci_append_addrinfo_cname(&cnames);
    if (cname == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    cname->alias = ci_strdup(host);
    if (cname->alias == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    cname->name = ci_strdup(primaryhost);
    if (cname->name == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    node = ci_llist_node_next(node);
  }

  /* No entries, add only primary */
  if (cnames == NULL) {
    cname = ci_append_addrinfo_cname(&cnames);
    if (cname == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    cname->name = ci_strdup(primaryhost);
    if (cname->name == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }
  status = CI_SUCCESS;

done:
  if (status != CI_SUCCESS) {
    ci_freeaddrinfo_cnames(cnames); /* LCOV_EXCL_LINE: DefensiveCoding */
    return status;                    /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *cnames_out = cnames;
  return CI_SUCCESS;
}

ci_status_t ci_hosts_entry_to_addrinfo(const ci_hosts_entry_t *entry,
                                           const char *name, int family,
                                           unsigned short        port,
                                           ci_bool_t           want_cnames,
                                           struct ci_addrinfo *ai)
{
  ci_status_t               status;
  struct ci_addrinfo_cname *cnames  = NULL;
  struct ci_addrinfo_node  *ainodes = NULL;
  ci_llist_node_t          *node;

  switch (family) {
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      break;
    default:                  /* LCOV_EXCL_LINE: DefensiveCoding */
      return CI_EBADFAMILY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (name != NULL) {
    ai->name = ci_strdup(name);
    if (ai->name == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  for (node = ci_llist_node_first(entry->ips); node != NULL;
       node = ci_llist_node_next(node)) {
    struct ci_addr addr;
    const void      *ptr     = NULL;
    size_t           ptr_len = 0;
    const char      *ipaddr  = ci_llist_node_val(node);

    memset(&addr, 0, sizeof(addr));
    addr.family = family;
    ptr         = ci_dns_pton(ipaddr, &addr, &ptr_len);

    if (ptr == NULL) {
      continue;
    }

    status = ci_append_ai_node(addr.family, port, 0, ptr, &ainodes);
    if (status != CI_SUCCESS) {
      goto done; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  }

  if (want_cnames) {
    status = ci_hosts_ai_append_cnames(entry, &cnames);
    if (status != CI_SUCCESS) {
      goto done; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  }

  status = CI_SUCCESS;

done:
  if (status != CI_SUCCESS) {
    /* LCOV_EXCL_START: defensive coding */
    ci_freeaddrinfo_cnames(cnames);
    ci_freeaddrinfo_nodes(ainodes);
    ci_free(ai->name);
    ai->name = NULL;
    return status;
    /* LCOV_EXCL_STOP */
  }
  ci_addrinfo_cat_cnames(&ai->cnames, cnames);
  ci_addrinfo_cat_nodes(&ai->nodes, ainodes);

  return status;
}

ci_status_t ci_hosts_entry_to_hostent(const ci_hosts_entry_t *entry,
                                          int family, struct hostent **hostent)
{
  ci_status_t         status;
  struct ci_addrinfo *ai = ci_malloc_zero(sizeof(*ai));

  *hostent = NULL;

  if (ai == NULL) {
    return CI_ENOMEM;
  }

  status = ci_hosts_entry_to_addrinfo(entry, NULL, family, 0, CI_TRUE, ai);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_addrinfo2hostent(ai, family, hostent);
  if (status != CI_SUCCESS) {
    goto done;
  }

done:
  ci_freeaddrinfo(ai);
  if (status != CI_SUCCESS) {
    ci_free_hostent(*hostent);
    *hostent = NULL;
  }

  return status;
}
