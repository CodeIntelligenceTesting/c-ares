/* MIT License
 *
 * Copyright (c) 2019 Andrew Selivanov
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


ci_status_t ci_parse_into_addrinfo(const ci_dns_record_t *dnsrec,
                                       ci_bool_t    cname_only_is_enodata,
                                       unsigned short port,
                                       struct ci_addrinfo *ai)
{
  ci_status_t               status;
  size_t                      i;
  size_t                      ancount;
  const char                 *hostname  = NULL;
  ci_bool_t                 got_a     = CI_FALSE;
  ci_bool_t                 got_aaaa  = CI_FALSE;
  ci_bool_t                 got_cname = CI_FALSE;
  struct ci_addrinfo_cname *cnames    = NULL;
  struct ci_addrinfo_node  *nodes     = NULL;

  /* Save question hostname */
  status = ci_dns_record_query_get(dnsrec, 0, &hostname, NULL, NULL);
  if (status != CI_SUCCESS) {
    goto done; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ancount = ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER);
  if (ancount == 0) {
    status = CI_ENODATA;
    goto done;
  }

  for (i = 0; i < ancount; i++) {
    ci_dns_rec_type_t  rtype;
    const ci_dns_rr_t *rr =
      ci_dns_record_rr_get_const(dnsrec, CI_SECTION_ANSWER, i);

    if (ci_dns_rr_get_class(rr) != CI_CLASS_IN) {
      continue;
    }

    rtype = ci_dns_rr_get_type(rr);

    /* Issue #683
     * Old code did this hostname sanity check, however it appears this is
     * flawed logic.  Other resolvers don't do this sanity check.  Leaving
     * this code commented out for future reference.
     *
     * rname = ci_dns_rr_get_name(rr);
     * if ((rtype == CI_REC_TYPE_A || rtype == CI_REC_TYPE_AAAA) &&
     *     !ci_strcaseeq(rname, hostname)) {
     *   continue;
     * }
     */

    if (rtype == CI_REC_TYPE_CNAME) {
      struct ci_addrinfo_cname *cname;

      got_cname = CI_TRUE;
      /* replace hostname with data from cname
       * SA: Seems wrong as it introduces order dependency. */
      hostname = ci_dns_rr_get_str(rr, CI_RR_CNAME_CNAME);

      cname = ci_append_addrinfo_cname(&cnames);
      if (cname == NULL) {
        status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
      cname->ttl   = (int)ci_dns_rr_get_ttl(rr);
      cname->alias = ci_strdup(ci_dns_rr_get_name(rr));
      if (cname->alias == NULL) {
        status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
      cname->name = ci_strdup(hostname);
      if (cname->name == NULL) {
        status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
    } else if (rtype == CI_REC_TYPE_A) {
      got_a = CI_TRUE;
      status =
        ci_append_ai_node(AF_INET, port, ci_dns_rr_get_ttl(rr),
                            ci_dns_rr_get_addr(rr, CI_RR_A_ADDR), &nodes);
      if (status != CI_SUCCESS) {
        goto done; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    } else if (rtype == CI_REC_TYPE_AAAA) {
      got_aaaa = CI_TRUE;
      status   = ci_append_ai_node(AF_INET6, port, ci_dns_rr_get_ttl(rr),
                                     ci_dns_rr_get_addr6(rr, CI_RR_AAAA_ADDR),
                                     &nodes);
      if (status != CI_SUCCESS) {
        goto done; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    } else {
      continue;
    }
  }

  if (!got_a && !got_aaaa &&
      (!got_cname || (got_cname && cname_only_is_enodata))) {
    status = CI_ENODATA;
    goto done;
  }

  /* save the hostname as ai->name */
  if (ai->name == NULL || !ci_strcaseeq(ai->name, hostname)) {
    ci_free(ai->name);
    ai->name = ci_strdup(hostname);
    if (ai->name == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  if (got_a || got_aaaa) {
    ci_addrinfo_cat_nodes(&ai->nodes, nodes);
    nodes = NULL;
  }

  if (got_cname) {
    ci_addrinfo_cat_cnames(&ai->cnames, cnames);
    cnames = NULL;
  }

done:
  ci_freeaddrinfo_cnames(cnames);
  ci_freeaddrinfo_nodes(nodes);

  /* compatibility */
  if (status == CI_EBADNAME) {
    status = CI_EBADRESP;
  }

  return status;
}
