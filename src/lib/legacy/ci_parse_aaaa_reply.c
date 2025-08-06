/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2005 Dominick Meglio
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

#include "ci_inet_net_pton.h"

int ci_parse_aaaa_reply(const unsigned char *abuf, int alen,
                          struct hostent **host, struct ci_addr6ttl *addrttls,
                          int *naddrttls)
{
  struct ci_addrinfo ai;
  char                *question_hostname = NULL;
  ci_status_t        status;
  size_t               req_naddrttls = 0;
  ci_dns_record_t   *dnsrec        = NULL;

  if (alen < 0) {
    return CI_EBADRESP;
  }

  if (naddrttls) {
    req_naddrttls = (size_t)*naddrttls;
    *naddrttls    = 0;
  }

  memset(&ai, 0, sizeof(ai));

  status = ci_dns_parse(abuf, (size_t)alen, 0, &dnsrec);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  status = ci_parse_into_addrinfo(dnsrec, 0, 0, &ai);
  if (status != CI_SUCCESS && status != CI_ENODATA) {
    goto fail;
  }

  if (host != NULL) {
    status = ci_addrinfo2hostent(&ai, AF_INET6, host);
    if (status != CI_SUCCESS && status != CI_ENODATA) {
      goto fail; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  }

  if (addrttls != NULL && req_naddrttls) {
    size_t temp_naddrttls = 0;
    ci_addrinfo2addrttl(&ai, AF_INET6, req_naddrttls, NULL, addrttls,
                          &temp_naddrttls);
    *naddrttls = (int)temp_naddrttls;
  }

fail:
  ci_freeaddrinfo_cnames(ai.cnames);
  ci_freeaddrinfo_nodes(ai.nodes);
  ci_free(question_hostname);
  ci_free(ai.name);
  ci_dns_record_destroy(dnsrec);

  if (status == CI_EBADNAME) {
    status = CI_EBADRESP;
  }

  return (int)status;
}
