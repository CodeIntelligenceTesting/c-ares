/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2005 Dominick Meglio
 * Copyright (c) 2019 Andrew Selivanov
 * Copyright (c) 2021 Brad House
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

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif


ci_status_t ci_addrinfo2hostent(const struct ci_addrinfo *ai, int family,
                                    struct hostent **host)
{
  struct ci_addrinfo_node  *next;
  struct ci_addrinfo_cname *next_cname;
  char                      **aliases  = NULL;
  char                       *addrs    = NULL;
  size_t                      naliases = 0;
  size_t                      naddrs   = 0;
  size_t                      alias    = 0;
  size_t                      i;

  if (ai == NULL || host == NULL) {
    return CI_EBADQUERY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* Use the first node of the response as the family, since hostent can only
   * represent one family.  We assume getaddrinfo() returned a sorted list if
   * the user requested AF_UNSPEC. */
  if (family == AF_UNSPEC && ai->nodes) {
    family = ai->nodes->ai_family;
  }

  if (family != AF_INET && family != AF_INET6) {
    return CI_EBADQUERY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *host = ci_malloc(sizeof(**host));
  if (!(*host)) {
    goto enomem; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  memset(*host, 0, sizeof(**host));

  next = ai->nodes;
  while (next) {
    if (next->ai_family == family) {
      ++naddrs;
    }
    next = next->ai_next;
  }

  next_cname = ai->cnames;
  while (next_cname) {
    if (next_cname->alias) {
      ++naliases;
    }
    next_cname = next_cname->next;
  }

  aliases = ci_malloc((naliases + 1) * sizeof(char *));
  if (!aliases) {
    goto enomem; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  (*host)->h_aliases = aliases;
  memset(aliases, 0, (naliases + 1) * sizeof(char *));

  if (naliases) {
    for (next_cname = ai->cnames; next_cname != NULL;
         next_cname = next_cname->next) {
      if (next_cname->alias == NULL) {
        continue;
      }
      aliases[alias] = ci_strdup(next_cname->alias);
      if (!aliases[alias]) {
        goto enomem; /* LCOV_EXCL_LINE: OutOfMemory */
      }
      alias++;
    }
  }


  (*host)->h_addr_list = ci_malloc((naddrs + 1) * sizeof(char *));
  if (!(*host)->h_addr_list) {
    goto enomem; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  memset((*host)->h_addr_list, 0, (naddrs + 1) * sizeof(char *));

  if (ai->cnames) {
    (*host)->h_name = ci_strdup(ai->cnames->name);
    if ((*host)->h_name == NULL && ai->cnames->name) {
      goto enomem; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  } else {
    (*host)->h_name = ci_strdup(ai->name);
    if ((*host)->h_name == NULL && ai->name) {
      goto enomem; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  (*host)->h_addrtype = (HOSTENT_ADDRTYPE_TYPE)family;

  if (family == AF_INET) {
    (*host)->h_length = sizeof(struct in_addr);
  }

  if (family == AF_INET6) {
    (*host)->h_length = sizeof(struct ci_in6_addr);
  }

  if (naddrs) {
    addrs = ci_malloc(naddrs * (size_t)(*host)->h_length);
    if (!addrs) {
      goto enomem; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    i = 0;
    for (next = ai->nodes; next != NULL; next = next->ai_next) {
      if (next->ai_family != family) {
        continue;
      }
      (*host)->h_addr_list[i] = addrs + (i * (size_t)(*host)->h_length);
      if (family == AF_INET6) {
        memcpy((*host)->h_addr_list[i],
               &(CI_INADDR_CAST(const struct sockaddr_in6 *, next->ai_addr)
                   ->sin6_addr),
               (size_t)(*host)->h_length);
      }
      if (family == AF_INET) {
        memcpy((*host)->h_addr_list[i],
               &(CI_INADDR_CAST(const struct sockaddr_in *, next->ai_addr)
                   ->sin_addr),
               (size_t)(*host)->h_length);
      }
      ++i;
    }

    if (i == 0) {
      ci_free(addrs);
    }
  }

  if (naddrs == 0 && naliases == 0) {
    ci_free_hostent(*host);
    *host = NULL;
    return CI_ENODATA;
  }

  return CI_SUCCESS;

/* LCOV_EXCL_START: OutOfMemory */
enomem:
  ci_free_hostent(*host);
  *host = NULL;
  return CI_ENOMEM;
  /* LCOV_EXCL_STOP */
}

ci_status_t ci_addrinfo2addrttl(const struct ci_addrinfo *ai, int family,
                                    size_t                req_naddrttls,
                                    struct ci_addrttl  *addrttls,
                                    struct ci_addr6ttl *addr6ttls,
                                    size_t               *naddrttls)
{
  struct ci_addrinfo_node  *next;
  struct ci_addrinfo_cname *next_cname;
  int                         cname_ttl = INT_MAX;

  if (family != AF_INET && family != AF_INET6) {
    return CI_EBADQUERY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (ai == NULL || naddrttls == NULL) {
    return CI_EBADQUERY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (family == AF_INET && addrttls == NULL) {
    return CI_EBADQUERY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (family == AF_INET6 && addr6ttls == NULL) {
    return CI_EBADQUERY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (req_naddrttls == 0) {
    return CI_EBADQUERY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *naddrttls = 0;

  next_cname = ai->cnames;
  while (next_cname) {
    if (next_cname->ttl < cname_ttl) {
      cname_ttl = next_cname->ttl;
    }
    next_cname = next_cname->next;
  }

  for (next = ai->nodes; next != NULL; next = next->ai_next) {
    if (next->ai_family != family) {
      continue;
    }

    if (*naddrttls >= req_naddrttls) {
      break;
    }

    if (family == AF_INET6) {
      if (next->ai_ttl > cname_ttl) {
        addr6ttls[*naddrttls].ttl = cname_ttl;
      } else {
        addr6ttls[*naddrttls].ttl = next->ai_ttl;
      }

      memcpy(&addr6ttls[*naddrttls].ip6addr,
             &(CI_INADDR_CAST(const struct sockaddr_in6 *, next->ai_addr)
                 ->sin6_addr),
             sizeof(struct ci_in6_addr));
    } else {
      if (next->ai_ttl > cname_ttl) {
        addrttls[*naddrttls].ttl = cname_ttl;
      } else {
        addrttls[*naddrttls].ttl = next->ai_ttl;
      }
      memcpy(&addrttls[*naddrttls].ipaddr,
             &(CI_INADDR_CAST(const struct sockaddr_in *, next->ai_addr)
                 ->sin_addr),
             sizeof(struct in_addr));
    }
    (*naddrttls)++;
  }

  return CI_SUCCESS;
}
