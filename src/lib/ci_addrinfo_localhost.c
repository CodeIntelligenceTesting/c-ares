/* MIT License
 *
 * Copyright (c) Massachusetts Institute of Technology
 * Copyright (c) Daniel Stenberg
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

#if defined(USE_WINSOCK)
#  if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600
#    include <ws2ipdef.h>
#  endif
#  if defined(HAVE_IPHLPAPI_H)
#    include <iphlpapi.h>
#  endif
#  if defined(HAVE_NETIOAPI_H)
#    include <netioapi.h>
#  endif
#endif

ci_status_t ci_append_ai_node(int aftype, unsigned short port,
                                  unsigned int ttl, const void *adata,
                                  struct ci_addrinfo_node **nodes)
{
  struct ci_addrinfo_node *node;

  node = ci_append_addrinfo_node(nodes);
  if (!node) {
    return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  memset(node, 0, sizeof(*node));

  if (aftype == AF_INET) {
    struct sockaddr_in *sin = ci_malloc(sizeof(*sin));
    if (!sin) {
      return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    memset(sin, 0, sizeof(*sin));
    memcpy(&sin->sin_addr.s_addr, adata, sizeof(sin->sin_addr.s_addr));
    sin->sin_family = AF_INET;
    sin->sin_port   = htons(port);

    node->ai_addr    = (struct sockaddr *)sin;
    node->ai_family  = AF_INET;
    node->ai_addrlen = sizeof(*sin);
    node->ai_addr    = (struct sockaddr *)sin;
    node->ai_ttl     = (int)ttl;
  }

  if (aftype == AF_INET6) {
    struct sockaddr_in6 *sin6 = ci_malloc(sizeof(*sin6));
    if (!sin6) {
      return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    memset(sin6, 0, sizeof(*sin6));
    memcpy(&sin6->sin6_addr.s6_addr, adata, sizeof(sin6->sin6_addr.s6_addr));
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port   = htons(port);

    node->ai_addr    = (struct sockaddr *)sin6;
    node->ai_family  = AF_INET6;
    node->ai_addrlen = sizeof(*sin6);
    node->ai_addr    = (struct sockaddr *)sin6;
    node->ai_ttl     = (int)ttl;
  }

  return CI_SUCCESS;
}

static ci_status_t
  ci_default_loopback_addrs(int aftype, unsigned short port,
                              struct ci_addrinfo_node **nodes)
{
  ci_status_t status = CI_SUCCESS;

  if (aftype == AF_UNSPEC || aftype == AF_INET6) {
    struct ci_in6_addr addr6;
    ci_inet_pton(AF_INET6, "::1", &addr6);
    status = ci_append_ai_node(AF_INET6, port, 0, &addr6, nodes);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  if (aftype == AF_UNSPEC || aftype == AF_INET) {
    struct in_addr addr4;
    ci_inet_pton(AF_INET, "127.0.0.1", &addr4);
    status = ci_append_ai_node(AF_INET, port, 0, &addr4, nodes);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  return status;
}

static ci_status_t
  ci_system_loopback_addrs(int aftype, unsigned short port,
                             struct ci_addrinfo_node **nodes)
{
#if defined(USE_WINSOCK) && defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600 && \
  !defined(__WATCOMC__)
  PMIB_UNICASTIPADDRESS_TABLE table;
  unsigned int                i;
  ci_status_t               status = CI_ENOTFOUND;

  *nodes = NULL;

  if (GetUnicastIpAddressTable((ADDRESS_FAMILY)aftype, &table) != NO_ERROR) {
    return CI_ENOTFOUND;
  }

  for (i = 0; i < table->NumEntries; i++) {
    if (table->Table[i].InterfaceLuid.Info.IfType !=
        IF_TYPE_SOFTWARE_LOOPBACK) {
      continue;
    }

    if (table->Table[i].Address.si_family == AF_INET) {
      status =
        ci_append_ai_node(table->Table[i].Address.si_family, port, 0,
                            &table->Table[i].Address.Ipv4.sin_addr, nodes);
    } else if (table->Table[i].Address.si_family == AF_INET6) {
      status =
        ci_append_ai_node(table->Table[i].Address.si_family, port, 0,
                            &table->Table[i].Address.Ipv6.sin6_addr, nodes);
    } else {
      /* Ignore any others */
      continue;
    }

    if (status != CI_SUCCESS) {
      goto fail;
    }
  }

  if (*nodes == NULL) {
    status = CI_ENOTFOUND;
  }

fail:
  FreeMibTable(table);

  if (status != CI_SUCCESS) {
    ci_freeaddrinfo_nodes(*nodes);
    *nodes = NULL;
  }

  return status;

#else
  (void)aftype;
  (void)port;
  (void)nodes;
  /* Not supported on any other OS at this time */
  return CI_ENOTFOUND;
#endif
}

ci_status_t ci_addrinfo_localhost(const char *name, unsigned short port,
                                      const struct ci_addrinfo_hints *hints,
                                      struct ci_addrinfo             *ai)
{
  struct ci_addrinfo_node *nodes = NULL;
  ci_status_t              status;

  /* Validate family */
  switch (hints->ai_family) {
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      break;
    default:                  /* LCOV_EXCL_LINE: DefensiveCoding */
      return CI_EBADFAMILY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ai->name = ci_strdup(name);
  if (!ai->name) {
    goto enomem; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  status = ci_system_loopback_addrs(hints->ai_family, port, &nodes);

  if (status == CI_ENOTFOUND) {
    status = ci_default_loopback_addrs(hints->ai_family, port, &nodes);
  }

  ci_addrinfo_cat_nodes(&ai->nodes, nodes);

  return status;

/* LCOV_EXCL_START: OutOfMemory */
enomem:
  ci_freeaddrinfo_nodes(nodes);
  ci_free(ai->name);
  ai->name = NULL;
  return CI_ENOMEM;
  /* LCOV_EXCL_STOP */
}
