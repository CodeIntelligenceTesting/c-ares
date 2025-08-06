/* MIT License
 *
 * Copyright (c) 1998, 2011, 2013 Massachusetts Institute of Technology
 * Copyright (c) 2017 Christian Ammer
 * Copyright (c) 2019 Andrew Selivanov
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

#ifdef HAVE_GETSERVBYNAME_R
#  if !defined(GETSERVBYNAME_R_ARGS) || (GETSERVBYNAME_R_ARGS < 4) || \
    (GETSERVBYNAME_R_ARGS > 6)
#    error "you MUST specify a valid number of arguments for getservbyname_r"
#  endif
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

#include "ci_nameser.h"

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
#include <assert.h>

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include "ci_dns.h"

struct host_query {
  ci_channel_t            *channel;
  char                      *name;
  unsigned short             port; /* in host order */
  ci_addrinfo_callback     callback;
  void                      *arg;
  struct ci_addrinfo_hints hints;
  int    sent_family; /* this family is what was is being used */
  size_t timeouts;    /* number of timeouts we saw for this request */
  char  *lookups; /* Duplicate memory from channel because of ci_reinit() */
  const char *remaining_lookups; /* types of lookup we need to perform ("fb" by
                                    default, file and dns respectively) */

  /* Search order for names */
  char      **names;
  size_t      names_cnt;
  size_t      next_name_idx;       /* next name index being attempted */

  struct ci_addrinfo *ai;        /* store results between lookups */
  unsigned short        qid_a;     /* qid for A request */
  unsigned short        qid_aaaa;  /* qid for AAAA request */

  size_t                remaining; /* number of DNS answers waiting for */

  /* Track nodata responses to possibly override final result */
  size_t                nodata_cnt;
};

static const struct ci_addrinfo_hints default_hints = {
  0,         /* ai_flags */
  AF_UNSPEC, /* ai_family */
  0,         /* ai_socktype */
  0,         /* ai_protocol */
};

/* forward declarations */
static ci_bool_t next_dns_lookup(struct host_query *hquery);

struct ci_addrinfo_cname *
  ci_append_addrinfo_cname(struct ci_addrinfo_cname **head)
{
  struct ci_addrinfo_cname *tail = ci_malloc_zero(sizeof(*tail));
  struct ci_addrinfo_cname *last = *head;

  if (tail == NULL) {
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (!last) {
    *head = tail;
    return tail;
  }

  while (last->next) {
    last = last->next;
  }

  last->next = tail;
  return tail;
}

void ci_addrinfo_cat_cnames(struct ci_addrinfo_cname **head,
                              struct ci_addrinfo_cname  *tail)
{
  struct ci_addrinfo_cname *last = *head;
  if (!last) {
    *head = tail;
    return;
  }

  while (last->next) {
    last = last->next;
  }

  last->next = tail;
}

/* Allocate new addrinfo and append to the tail. */
struct ci_addrinfo_node *
  ci_append_addrinfo_node(struct ci_addrinfo_node **head)
{
  struct ci_addrinfo_node *tail = ci_malloc_zero(sizeof(*tail));
  struct ci_addrinfo_node *last = *head;

  if (tail == NULL) {
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (!last) {
    *head = tail;
    return tail;
  }

  while (last->ai_next) {
    last = last->ai_next;
  }

  last->ai_next = tail;
  return tail;
}

void ci_addrinfo_cat_nodes(struct ci_addrinfo_node **head,
                             struct ci_addrinfo_node  *tail)
{
  struct ci_addrinfo_node *last = *head;
  if (!last) {
    *head = tail;
    return;
  }

  while (last->ai_next) {
    last = last->ai_next;
  }

  last->ai_next = tail;
}

/* Resolve service name into port number given in host byte order.
 * If not resolved, return 0.
 */
static unsigned short lookup_service(const char *service, int flags)
{
  const char     *proto;
  struct servent *sep;
#ifdef HAVE_GETSERVBYNAME_R
  struct servent se;
  char           tmpbuf[4096];
#endif

  if (service) {
    if (flags & CI_NI_UDP) {
      proto = "udp";
    } else if (flags & CI_NI_SCTP) {
      proto = "sctp";
    } else if (flags & CI_NI_DCCP) {
      proto = "dccp";
    } else {
      proto = "tcp";
    }
#ifdef HAVE_GETSERVBYNAME_R
    memset(&se, 0, sizeof(se));
    sep = &se;
    memset(tmpbuf, 0, sizeof(tmpbuf));
#  if GETSERVBYNAME_R_ARGS == 6
    if (getservbyname_r(service, proto, &se, (void *)tmpbuf, sizeof(tmpbuf),
                        &sep) != 0) {
      sep = NULL; /* LCOV_EXCL_LINE: buffer large so this never fails */
    }
#  elif GETSERVBYNAME_R_ARGS == 5
    sep = getservbyname_r(service, proto, &se, (void *)tmpbuf, sizeof(tmpbuf));
#  elif GETSERVBYNAME_R_ARGS == 4
    if (getservbyname_r(service, proto, &se, (void *)tmpbuf) != 0) {
      sep = NULL;
    }
#  else
    /* Lets just hope the OS uses TLS! */
    sep = getservbyname(service, proto);
#  endif
#else
    /* Lets just hope the OS uses TLS! */
#  if (defined(NETWARE) && !defined(__NOVELL_LIBC__))
    sep = getservbyname(service, (char *)proto);
#  else
    sep = getservbyname(service, proto);
#  endif
#endif
    return (sep ? ntohs((unsigned short)sep->s_port) : 0);
  }
  return 0;
}

/* If the name looks like an IP address or an error occurred,
 * fake up a host entry, end the query immediately, and return true.
 * Otherwise return false.
 */
static ci_bool_t fake_addrinfo(const char *name, unsigned short port,
                                 const struct ci_addrinfo_hints *hints,
                                 struct ci_addrinfo             *ai,
                                 ci_addrinfo_callback callback, void *arg)
{
  struct ci_addrinfo_cname *cname;
  ci_status_t               status = CI_SUCCESS;
  ci_bool_t                 result = CI_FALSE;
  int                         family = hints->ai_family;
  if (family == AF_INET || family == AF_INET6 || family == AF_UNSPEC) {
    /* It only looks like an IP address if it's all numbers and dots. */
    size_t      numdots = 0;
    ci_bool_t valid   = CI_TRUE;
    const char *p;
    for (p = name; *p; p++) {
      if (!ci_isdigit(*p) && *p != '.') {
        valid = CI_FALSE;
        break;
      } else if (*p == '.') {
        numdots++;
      }
    }

    /* if we don't have 3 dots, it is illegal
     * (although inet_pton doesn't think so).
     */
    if (numdots != 3 || !valid) {
      result = CI_FALSE;
    } else {
      struct in_addr addr4;
      result =
        ci_inet_pton(AF_INET, name, &addr4) < 1 ? CI_FALSE : CI_TRUE;
      if (result) {
        status = ci_append_ai_node(AF_INET, port, 0, &addr4, &ai->nodes);
        if (status != CI_SUCCESS) {
          callback(arg, (int)status, 0, NULL); /* LCOV_EXCL_LINE: OutOfMemory */
          return CI_TRUE;                    /* LCOV_EXCL_LINE: OutOfMemory */
        }
      }
    }
  }

  if (!result && (family == AF_INET6 || family == AF_UNSPEC)) {
    struct ci_in6_addr addr6;
    result =
      ci_inet_pton(AF_INET6, name, &addr6) < 1 ? CI_FALSE : CI_TRUE;
    if (result) {
      status = ci_append_ai_node(AF_INET6, port, 0, &addr6, &ai->nodes);
      if (status != CI_SUCCESS) {
        callback(arg, (int)status, 0, NULL); /* LCOV_EXCL_LINE: OutOfMemory */
        return CI_TRUE;                    /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  if (!result) {
    return CI_FALSE;
  }

  if (hints->ai_flags & CI_AI_CANONNAME) {
    cname = ci_append_addrinfo_cname(&ai->cnames);
    if (!cname) {
      /* LCOV_EXCL_START: OutOfMemory */
      ci_freeaddrinfo(ai);
      callback(arg, CI_ENOMEM, 0, NULL);
      return CI_TRUE;
      /* LCOV_EXCL_STOP */
    }

    /* Duplicate the name, to avoid a constness violation. */
    cname->name = ci_strdup(name);
    if (!cname->name) {
      ci_freeaddrinfo(ai);
      callback(arg, CI_ENOMEM, 0, NULL);
      return CI_TRUE;
    }
  }

  ai->nodes->ai_socktype = hints->ai_socktype;
  ai->nodes->ai_protocol = hints->ai_protocol;

  callback(arg, CI_SUCCESS, 0, ai);
  return CI_TRUE;
}

static void hquery_free(struct host_query *hquery, ci_bool_t cleanup_ai)
{
  if (cleanup_ai) {
    ci_freeaddrinfo(hquery->ai);
  }
  ci_strsplit_free(hquery->names, hquery->names_cnt);
  ci_free(hquery->name);
  ci_free(hquery->lookups);
  ci_free(hquery);
}

static void end_hquery(struct host_query *hquery, ci_status_t status)
{
  struct ci_addrinfo_node  sentinel;
  struct ci_addrinfo_node *next;

  if (status == CI_SUCCESS) {
    if (!(hquery->hints.ai_flags & CI_AI_NOSORT) && hquery->ai->nodes) {
      sentinel.ai_next = hquery->ai->nodes;
      ci_sortaddrinfo(hquery->channel, &sentinel);
      hquery->ai->nodes = sentinel.ai_next;
    }
    next = hquery->ai->nodes;

    while (next) {
      next->ai_socktype = hquery->hints.ai_socktype;
      next->ai_protocol = hquery->hints.ai_protocol;
      next              = next->ai_next;
    }
  } else {
    /* Clean up what we have collected by so far. */
    ci_freeaddrinfo(hquery->ai);
    hquery->ai = NULL;
  }

  hquery->callback(hquery->arg, (int)status, (int)hquery->timeouts, hquery->ai);
  hquery_free(hquery, CI_FALSE);
}

ci_bool_t ci_is_localhost(const char *name)
{
  /* RFC6761 6.3 says : The domain "localhost." and any names falling within
   * ".localhost." */
  size_t len;

  if (name == NULL) {
    return CI_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (ci_strcaseeq(name, "localhost")) {
    return CI_TRUE;
  }

  len = ci_strlen(name);
  if (len < 10 /* strlen(".localhost") */) {
    return CI_FALSE;
  }

  if (ci_strcaseeq(name + (len - 10 /* strlen(".localhost") */),
                     ".localhost")) {
    return CI_TRUE;
  }

  return CI_FALSE;
}

static ci_status_t file_lookup(struct host_query *hquery)
{
  const ci_hosts_entry_t *entry;
  ci_status_t             status;

  /* Per RFC 7686, reject queries for ".onion" domain names with NXDOMAIN. */
  if (ci_is_onion_domain(hquery->name)) {
    return CI_ENOTFOUND;
  }

  status = ci_hosts_search_host(
    hquery->channel,
    (hquery->hints.ai_flags & CI_AI_ENVHOSTS) ? CI_TRUE : CI_FALSE,
    hquery->name, &entry);

  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_hosts_entry_to_addrinfo(
    entry, hquery->name, hquery->hints.ai_family, hquery->port,
    (hquery->hints.ai_flags & CI_AI_CANONNAME) ? CI_TRUE : CI_FALSE,
    hquery->ai);

  if (status != CI_SUCCESS) {
    goto done; /* LCOV_EXCL_LINE: OutOfMemory */
  }


done:
  /* RFC6761 section 6.3 #3 states that "Name resolution APIs and libraries
   * SHOULD recognize localhost names as special and SHOULD always return the
   * IP loopback address for address queries".
   * We will also ignore ALL errors when trying to resolve localhost, such
   * as permissions errors reading /etc/hosts or a malformed /etc/hosts */
  if (status != CI_SUCCESS && status != CI_ENOMEM &&
      ci_is_localhost(hquery->name)) {
    return ci_addrinfo_localhost(hquery->name, hquery->port, &hquery->hints,
                                   hquery->ai);
  }

  return status;
}

static void next_lookup(struct host_query *hquery, ci_status_t status)
{
  switch (*hquery->remaining_lookups) {
    case 'b':
      /* RFC6761 section 6.3 #3 says "Name resolution APIs SHOULD NOT send
       * queries for localhost names to their configured caching DNS
       * server(s)."
       * Otherwise, DNS lookup. */
      if (!ci_is_localhost(hquery->name) && next_dns_lookup(hquery)) {
        break;
      }

      hquery->remaining_lookups++;
      next_lookup(hquery, status);
      break;

    case 'f':
      /* Host file lookup */
      if (file_lookup(hquery) == CI_SUCCESS) {
        end_hquery(hquery, CI_SUCCESS);
        break;
      }
      hquery->remaining_lookups++;
      next_lookup(hquery, status);
      break;
    default:
      /* No lookup left */
      end_hquery(hquery, status);
      break;
  }
}

static void terminate_retries(const struct host_query *hquery,
                              unsigned short           qid)
{
  unsigned short term_qid =
    (qid == hquery->qid_a) ? hquery->qid_aaaa : hquery->qid_a;
  const ci_channel_t *channel = hquery->channel;
  ci_query_t         *query   = NULL;

  /* No other outstanding queries, nothing to do */
  if (!hquery->remaining) {
    return;
  }

  query = ci_htable_szvp_get_direct(channel->queries_by_qid, term_qid);
  if (query == NULL) {
    return;
  }

  query->no_retries = CI_TRUE;
}

static void host_callback(void *arg, ci_status_t status, size_t timeouts,
                          const ci_dns_record_t *dnsrec)
{
  struct host_query *hquery         = (struct host_query *)arg;
  ci_status_t      addinfostatus  = CI_SUCCESS;
  hquery->timeouts                 += timeouts;
  hquery->remaining--;

  if (status == CI_SUCCESS) {
    if (dnsrec == NULL) {
      addinfostatus = CI_EBADRESP; /* LCOV_EXCL_LINE: DefensiveCoding */
    } else {
      addinfostatus =
        ci_parse_into_addrinfo(dnsrec, CI_TRUE, hquery->port, hquery->ai);
    }
    if (addinfostatus == CI_SUCCESS) {
      terminate_retries(hquery, ci_dns_record_get_id(dnsrec));
    }
  }

  if (!hquery->remaining) {
    if (status == CI_EDESTRUCTION || status == CI_ECANCELLED) {
      /* must make sure we don't do next_lookup() on destroy or cancel,
       * and return the appropriate status.  We won't return a partial
       * result in this case. */
      end_hquery(hquery, status);
    } else if (addinfostatus != CI_SUCCESS && addinfostatus != CI_ENODATA) {
      /* error in parsing result e.g. no memory */
      if (addinfostatus == CI_EBADRESP && hquery->ai->nodes) {
        /* We got a bad response from server, but at least one query
         * ended with CI_SUCCESS */
        end_hquery(hquery, CI_SUCCESS);
      } else {
        end_hquery(hquery, addinfostatus);
      }
    } else if (hquery->ai->nodes) {
      /* at least one query ended with CI_SUCCESS */
      end_hquery(hquery, CI_SUCCESS);
    } else if (status == CI_ENOTFOUND || status == CI_ENODATA ||
               addinfostatus == CI_ENODATA) {
      if (status == CI_ENODATA || addinfostatus == CI_ENODATA) {
        hquery->nodata_cnt++;
      }
      next_lookup(hquery, hquery->nodata_cnt ? CI_ENODATA : status);
    } else if ((status == CI_ESERVFAIL || status == CI_EREFUSED) &&
               ci_name_label_cnt(hquery->names[hquery->next_name_idx - 1]) ==
                 1) {
      /* Issue #852, systemd-resolved may return SERVFAIL or REFUSED on a
       * single label domain name. */
      next_lookup(hquery, hquery->nodata_cnt ? CI_ENODATA : status);
    } else {
      end_hquery(hquery, status);
    }
  }

  /* at this point we keep on waiting for the next query to finish */
}

static void ci_getaddrinfo_int(ci_channel_t *channel, const char *name,
                                 const char                       *service,
                                 const struct ci_addrinfo_hints *hints,
                                 ci_addrinfo_callback callback, void *arg)
{
  struct host_query    *hquery;
  unsigned short        port = 0;
  int                   family;
  struct ci_addrinfo *ai;
  ci_status_t         status;

  if (!hints) {
    hints = &default_hints;
  }

  family = hints->ai_family;

  /* Right now we only know how to look up Internet addresses
     and unspec means try both basically. */
  if (family != AF_INET && family != AF_INET6 && family != AF_UNSPEC) {
    callback(arg, CI_ENOTIMP, 0, NULL);
    return;
  }

  if (ci_is_onion_domain(name)) {
    callback(arg, CI_ENOTFOUND, 0, NULL);
    return;
  }

  if (service) {
    if (hints->ai_flags & CI_AI_NUMERICSERV) {
      unsigned long val;
      errno = 0;
      val   = strtoul(service, NULL, 0);
      if ((val == 0 && errno != 0) || val > 65535) {
        callback(arg, CI_ESERVICE, 0, NULL);
        return;
      }
      port = (unsigned short)val;
    } else {
      port = lookup_service(service, 0);
      if (!port) {
        unsigned long val;
        errno = 0;
        val   = strtoul(service, NULL, 0);
        if ((val == 0 && errno != 0) || val > 65535) {
          callback(arg, CI_ESERVICE, 0, NULL);
          return;
        }
        port = (unsigned short)val;
      }
    }
  }

  ai = ci_malloc_zero(sizeof(*ai));
  if (!ai) {
    callback(arg, CI_ENOMEM, 0, NULL);
    return;
  }

  if (fake_addrinfo(name, port, hints, ai, callback, arg)) {
    return;
  }

  /* Allocate and fill in the host query structure. */
  hquery = ci_malloc_zero(sizeof(*hquery));
  if (!hquery) {
    ci_freeaddrinfo(ai);
    callback(arg, CI_ENOMEM, 0, NULL);
    return;
  }

  hquery->port        = port;
  hquery->channel     = channel;
  hquery->hints       = *hints;
  hquery->sent_family = -1; /* nothing is sent yet */
  hquery->callback    = callback;
  hquery->arg         = arg;
  hquery->ai          = ai;
  hquery->name        = ci_strdup(name);
  if (hquery->name == NULL) {
    hquery_free(hquery, CI_TRUE);
    callback(arg, CI_ENOMEM, 0, NULL);
    return;
  }

  status =
    ci_search_name_list(channel, name, &hquery->names, &hquery->names_cnt);
  if (status != CI_SUCCESS) {
    hquery_free(hquery, CI_TRUE);
    callback(arg, (int)status, 0, NULL);
    return;
  }
  hquery->next_name_idx = 0;


  hquery->lookups = ci_strdup(channel->lookups);
  if (hquery->lookups == NULL) {
    hquery_free(hquery, CI_TRUE);
    callback(arg, CI_ENOMEM, 0, NULL);
    return;
  }
  hquery->remaining_lookups = hquery->lookups;

  /* Start performing lookups according to channel->lookups. */
  next_lookup(hquery, CI_ECONNREFUSED /* initial error code */);
}

void ci_getaddrinfo(ci_channel_t *channel, const char *name,
                      const char                       *service,
                      const struct ci_addrinfo_hints *hints,
                      ci_addrinfo_callback callback, void *arg)
{
  if (channel == NULL) {
    return;
  }
  ci_channel_lock(channel);
  ci_getaddrinfo_int(channel, name, service, hints, callback, arg);
  ci_channel_unlock(channel);
}

static ci_bool_t next_dns_lookup(struct host_query *hquery)
{
  const char *name = NULL;

  if (hquery->next_name_idx >= hquery->names_cnt) {
    return CI_FALSE;
  }

  name = hquery->names[hquery->next_name_idx++];

  /* NOTE: hquery may be invalidated during the call to ci_query_qid(),
   *       so should not be referenced after this point */
  switch (hquery->hints.ai_family) {
    case AF_INET:
      hquery->remaining += 1;
      ci_query_nolock(hquery->channel, name, CI_CLASS_IN, CI_REC_TYPE_A,
                        host_callback, hquery, &hquery->qid_a);
      break;
    case AF_INET6:
      hquery->remaining += 1;
      ci_query_nolock(hquery->channel, name, CI_CLASS_IN,
                        CI_REC_TYPE_AAAA, host_callback, hquery,
                        &hquery->qid_aaaa);
      break;
    case AF_UNSPEC:
      hquery->remaining += 2;
      ci_query_nolock(hquery->channel, name, CI_CLASS_IN, CI_REC_TYPE_A,
                        host_callback, hquery, &hquery->qid_a);
      ci_query_nolock(hquery->channel, name, CI_CLASS_IN,
                        CI_REC_TYPE_AAAA, host_callback, hquery,
                        &hquery->qid_aaaa);
      break;
    default:
      break;
  }

  return CI_TRUE;
}
