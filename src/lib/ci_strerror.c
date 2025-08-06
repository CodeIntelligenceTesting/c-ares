/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) The c-ci project and its contributors
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

const char *ci_strerror(int code)
{
  ci_status_t status = (ci_status_t)code;
  switch (status) {
    case CI_SUCCESS:
      return "Successful completion";
    case CI_ENODATA:
      return "DNS server returned answer with no data";
    case CI_EFORMERR:
      return "DNS server claims query was misformatted";
    case CI_ESERVFAIL:
      return "DNS server returned general failure";
    case CI_ENOTFOUND:
      return "Domain name not found";
    case CI_ENOTIMP:
      return "DNS server does not implement requested operation";
    case CI_EREFUSED:
      return "DNS server refused query";
    case CI_EBADQUERY:
      return "Misformatted DNS query";
    case CI_EBADNAME:
      return "Misformatted domain name";
    case CI_EBADFAMILY:
      return "Unsupported address family";
    case CI_EBADRESP:
      return "Misformatted DNS reply";
    case CI_ECONNREFUSED:
      return "Could not contact DNS servers";
    case CI_ETIMEOUT:
      return "Timeout while contacting DNS servers";
    case CI_EOF:
      return "End of file";
    case CI_EFILE:
      return "Error reading file";
    case CI_ENOMEM:
      return "Out of memory";
    case CI_EDESTRUCTION:
      return "Channel is being destroyed";
    case CI_EBADSTR:
      return "Misformatted string";
    case CI_EBADFLAGS:
      return "Illegal flags specified";
    case CI_ENONAME:
      return "Given hostname is not numeric";
    case CI_EBADHINTS:
      return "Illegal hints flags specified";
    case CI_ENOTINITIALIZED:
      return "c-ci library initialization not yet performed";
    case CI_ELOADIPHLPAPI:
      return "Error loading iphlpapi.dll";
    case CI_EADDRGETNETWORKPARAMS:
      return "Could not find GetNetworkParams function";
    case CI_ECANCELLED:
      return "DNS query cancelled";
    case CI_ESERVICE:
      return "Invalid service name or number";
    case CI_ENOSERVER:
      return "No DNS servers were configured";
  }

  return "unknown";
}
