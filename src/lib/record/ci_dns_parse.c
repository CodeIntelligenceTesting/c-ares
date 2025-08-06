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
#include <limits.h>
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

static size_t ci_dns_rr_remaining_len(const ci_buf_t *buf, size_t orig_len,
                                        size_t rdlength)
{
  size_t used_len = orig_len - ci_buf_len(buf);
  if (used_len >= rdlength) {
    return 0;
  }
  return rdlength - used_len;
}

static ci_status_t ci_dns_parse_and_set_dns_name(ci_buf_t    *buf,
                                                     ci_bool_t    is_hostname,
                                                     ci_dns_rr_t *rr,
                                                     ci_dns_rr_key_t key)
{
  ci_status_t status;
  char         *name = NULL;

  status = ci_dns_name_parse(buf, &name, is_hostname);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_rr_set_str_own(rr, key, name);
  if (status != CI_SUCCESS) {
    ci_free(name);
    return status;
  }
  return CI_SUCCESS;
}

static ci_status_t ci_dns_parse_and_set_dns_str(ci_buf_t       *buf,
                                                    size_t            max_len,
                                                    ci_dns_rr_t    *rr,
                                                    ci_dns_rr_key_t key,
                                                    ci_bool_t blank_allowed)
{
  ci_status_t status;
  char         *str = NULL;

  status = ci_buf_parse_dns_str(buf, max_len, &str);
  if (status != CI_SUCCESS) {
    return status;
  }

  if (!blank_allowed && ci_strlen(str) == 0) {
    ci_free(str);
    return CI_EBADRESP;
  }

  status = ci_dns_rr_set_str_own(rr, key, str);
  if (status != CI_SUCCESS) {
    ci_free(str);
    return status;
  }
  return CI_SUCCESS;
}

static ci_status_t
  ci_dns_parse_and_set_dns_abin(ci_buf_t *buf, size_t max_len,
                                  ci_dns_rr_t *rr, ci_dns_rr_key_t key,
                                  ci_bool_t validate_printable)
{
  ci_status_t           status;
  ci_dns_multistring_t *strs = NULL;

  status =
    ci_dns_multistring_parse_buf(buf, max_len, &strs, validate_printable);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_rr_set_abin_own(rr, key, strs);
  if (status != CI_SUCCESS) {
    ci_dns_multistring_destroy(strs);
    return status;
  }
  return CI_SUCCESS;
}

static ci_status_t ci_dns_parse_and_set_be32(ci_buf_t       *buf,
                                                 ci_dns_rr_t    *rr,
                                                 ci_dns_rr_key_t key)
{
  ci_status_t status;
  unsigned int  u32;

  status = ci_buf_fetch_be32(buf, &u32);
  if (status != CI_SUCCESS) {
    return status;
  }

  return ci_dns_rr_set_u32(rr, key, u32);
}

static ci_status_t ci_dns_parse_and_set_be16(ci_buf_t       *buf,
                                                 ci_dns_rr_t    *rr,
                                                 ci_dns_rr_key_t key)
{
  ci_status_t  status;
  unsigned short u16;

  status = ci_buf_fetch_be16(buf, &u16);
  if (status != CI_SUCCESS) {
    return status;
  }

  return ci_dns_rr_set_u16(rr, key, u16);
}

static ci_status_t ci_dns_parse_and_set_u8(ci_buf_t       *buf,
                                               ci_dns_rr_t    *rr,
                                               ci_dns_rr_key_t key)
{
  ci_status_t status;
  unsigned char u8;

  status = ci_buf_fetch_bytes(buf, &u8, 1);
  if (status != CI_SUCCESS) {
    return status;
  }

  return ci_dns_rr_set_u8(rr, key, u8);
}

static ci_status_t ci_dns_parse_rr_a(ci_buf_t *buf, ci_dns_rr_t *rr,
                                         size_t rdlength)
{
  struct in_addr addr;
  ci_status_t  status;

  (void)rdlength; /* Not needed */

  status = ci_buf_fetch_bytes(buf, (unsigned char *)&addr, sizeof(addr));
  if (status != CI_SUCCESS) {
    return status;
  }

  return ci_dns_rr_set_addr(rr, CI_RR_A_ADDR, &addr);
}

static ci_status_t ci_dns_parse_rr_ns(ci_buf_t *buf, ci_dns_rr_t *rr,
                                          size_t rdlength)
{
  (void)rdlength; /* Not needed */

  return ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr,
                                         CI_RR_NS_NSDNAME);
}

static ci_status_t ci_dns_parse_rr_cname(ci_buf_t *buf, ci_dns_rr_t *rr,
                                             size_t rdlength)
{
  (void)rdlength; /* Not needed */

  return ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr,
                                         CI_RR_CNAME_CNAME);
}

static ci_status_t ci_dns_parse_rr_soa(ci_buf_t *buf, ci_dns_rr_t *rr,
                                           size_t rdlength)
{
  ci_status_t status;

  (void)rdlength; /* Not needed */

  /* MNAME */
  status =
    ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr, CI_RR_SOA_MNAME);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* RNAME */
  status =
    ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr, CI_RR_SOA_RNAME);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* SERIAL */
  status = ci_dns_parse_and_set_be32(buf, rr, CI_RR_SOA_SERIAL);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* REFRESH */
  status = ci_dns_parse_and_set_be32(buf, rr, CI_RR_SOA_REFRESH);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* RETRY */
  status = ci_dns_parse_and_set_be32(buf, rr, CI_RR_SOA_RETRY);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* EXPIRE */
  status = ci_dns_parse_and_set_be32(buf, rr, CI_RR_SOA_EXPIRE);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* MINIMUM */
  return ci_dns_parse_and_set_be32(buf, rr, CI_RR_SOA_MINIMUM);
}

static ci_status_t ci_dns_parse_rr_ptr(ci_buf_t *buf, ci_dns_rr_t *rr,
                                           size_t rdlength)
{
  (void)rdlength; /* Not needed */

  return ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr,
                                         CI_RR_PTR_DNAME);
}

static ci_status_t ci_dns_parse_rr_hinfo(ci_buf_t *buf, ci_dns_rr_t *rr,
                                             size_t rdlength)
{
  ci_status_t status;
  size_t        orig_len = ci_buf_len(buf);

  (void)rdlength; /* Not needed */

  /* CPU */
  status = ci_dns_parse_and_set_dns_str(
    buf, ci_dns_rr_remaining_len(buf, orig_len, rdlength), rr,
    CI_RR_HINFO_CPU, CI_TRUE);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* OS */
  status = ci_dns_parse_and_set_dns_str(
    buf, ci_dns_rr_remaining_len(buf, orig_len, rdlength), rr,
    CI_RR_HINFO_OS, CI_TRUE);

  return status;
}

static ci_status_t ci_dns_parse_rr_mx(ci_buf_t *buf, ci_dns_rr_t *rr,
                                          size_t rdlength)
{
  ci_status_t status;

  (void)rdlength; /* Not needed */

  /* PREFERENCE */
  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_MX_PREFERENCE);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* EXCHANGE */
  return ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr,
                                         CI_RR_MX_EXCHANGE);
}

static ci_status_t ci_dns_parse_rr_txt(ci_buf_t *buf, ci_dns_rr_t *rr,
                                           size_t rdlength)
{
  return ci_dns_parse_and_set_dns_abin(buf, rdlength, rr, CI_RR_TXT_DATA,
                                         CI_FALSE);
}

static ci_status_t ci_dns_parse_rr_sig(ci_buf_t *buf, ci_dns_rr_t *rr,
                                           size_t rdlength)
{
  ci_status_t  status;
  size_t         orig_len = ci_buf_len(buf);
  size_t         len;
  unsigned char *data;

  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_SIG_TYPE_COVERED);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_parse_and_set_u8(buf, rr, CI_RR_SIG_ALGORITHM);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_parse_and_set_u8(buf, rr, CI_RR_SIG_LABELS);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_parse_and_set_be32(buf, rr, CI_RR_SIG_ORIGINAL_TTL);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_parse_and_set_be32(buf, rr, CI_RR_SIG_EXPIRATION);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_parse_and_set_be32(buf, rr, CI_RR_SIG_INCEPTION);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_SIG_KEY_TAG);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr,
                                           CI_RR_SIG_SIGNERS_NAME);
  if (status != CI_SUCCESS) {
    return status;
  }

  len = ci_dns_rr_remaining_len(buf, orig_len, rdlength);
  if (len == 0) {
    return CI_EBADRESP;
  }

  status = ci_buf_fetch_bytes_dup(buf, len, CI_FALSE, &data);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_rr_set_bin_own(rr, CI_RR_SIG_SIGNATURE, data, len);
  if (status != CI_SUCCESS) {
    ci_free(data);
    return status;
  }

  return CI_SUCCESS;
}

static ci_status_t ci_dns_parse_rr_aaaa(ci_buf_t *buf, ci_dns_rr_t *rr,
                                            size_t rdlength)
{
  struct ci_in6_addr addr;
  ci_status_t        status;

  (void)rdlength; /* Not needed */

  status = ci_buf_fetch_bytes(buf, (unsigned char *)&addr, sizeof(addr));
  if (status != CI_SUCCESS) {
    return status;
  }

  return ci_dns_rr_set_addr6(rr, CI_RR_AAAA_ADDR, &addr);
}

static ci_status_t ci_dns_parse_rr_srv(ci_buf_t *buf, ci_dns_rr_t *rr,
                                           size_t rdlength)
{
  ci_status_t status;

  (void)rdlength; /* Not needed */

  /* PRIORITY */
  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_SRV_PRIORITY);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* WEIGHT */
  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_SRV_WEIGHT);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* PORT */
  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_SRV_PORT);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* TARGET */
  return ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr,
                                         CI_RR_SRV_TARGET);
}

static ci_status_t ci_dns_parse_rr_naptr(ci_buf_t *buf, ci_dns_rr_t *rr,
                                             size_t rdlength)
{
  ci_status_t status;
  size_t        orig_len = ci_buf_len(buf);

  /* ORDER */
  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_NAPTR_ORDER);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* PREFERENCE */
  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_NAPTR_PREFERENCE);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* FLAGS */
  status = ci_dns_parse_and_set_dns_str(
    buf, ci_dns_rr_remaining_len(buf, orig_len, rdlength), rr,
    CI_RR_NAPTR_FLAGS, CI_TRUE);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* SERVICES */
  status = ci_dns_parse_and_set_dns_str(
    buf, ci_dns_rr_remaining_len(buf, orig_len, rdlength), rr,
    CI_RR_NAPTR_SERVICES, CI_TRUE);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* REGEXP */
  status = ci_dns_parse_and_set_dns_str(
    buf, ci_dns_rr_remaining_len(buf, orig_len, rdlength), rr,
    CI_RR_NAPTR_REGEXP, CI_TRUE);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* REPLACEMENT */
  return ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr,
                                         CI_RR_NAPTR_REPLACEMENT);
}

static ci_status_t ci_dns_parse_rr_opt(ci_buf_t *buf, ci_dns_rr_t *rr,
                                           size_t         rdlength,
                                           unsigned short raw_class,
                                           unsigned int   raw_ttl)
{
  ci_status_t  status;
  size_t         orig_len = ci_buf_len(buf);
  unsigned short rcode_high;

  status = ci_dns_rr_set_u16(rr, CI_RR_OPT_UDP_SIZE, raw_class);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* First 8 bits of TTL are an extended RCODE, and they go in the higher order
   * after the original 4-bit rcode */
  rcode_high             = (unsigned short)((raw_ttl >> 20) & 0x0FF0);
  rr->parent->raw_rcode |= rcode_high;

  status = ci_dns_rr_set_u8(rr, CI_RR_OPT_VERSION,
                              (unsigned char)(raw_ttl >> 16) & 0xFF);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_rr_set_u16(rr, CI_RR_OPT_FLAGS,
                               (unsigned short)(raw_ttl & 0xFFFF));
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Parse options */
  while (ci_dns_rr_remaining_len(buf, orig_len, rdlength)) {
    unsigned short opt = 0;
    unsigned short len = 0;
    unsigned char *val = NULL;

    /* Fetch be16 option */
    status = ci_buf_fetch_be16(buf, &opt);
    if (status != CI_SUCCESS) {
      return status;
    }

    /* Fetch be16 length */
    status = ci_buf_fetch_be16(buf, &len);
    if (status != CI_SUCCESS) {
      return status;
    }

    if (len) {
      status = ci_buf_fetch_bytes_dup(buf, len, CI_TRUE, &val);
      if (status != CI_SUCCESS) {
        return status;
      }
    }

    status = ci_dns_rr_set_opt_own(rr, CI_RR_OPT_OPTIONS, opt, val, len);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  return CI_SUCCESS;
}

static ci_status_t ci_dns_parse_rr_tlsa(ci_buf_t *buf, ci_dns_rr_t *rr,
                                            size_t rdlength)
{
  ci_status_t  status;
  size_t         orig_len = ci_buf_len(buf);
  size_t         len;
  unsigned char *data;

  status = ci_dns_parse_and_set_u8(buf, rr, CI_RR_TLSA_CERT_USAGE);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_parse_and_set_u8(buf, rr, CI_RR_TLSA_SELECTOR);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_parse_and_set_u8(buf, rr, CI_RR_TLSA_MATCH);
  if (status != CI_SUCCESS) {
    return status;
  }

  len = ci_dns_rr_remaining_len(buf, orig_len, rdlength);
  if (len == 0) {
    return CI_EBADRESP;
  }

  status = ci_buf_fetch_bytes_dup(buf, len, CI_FALSE, &data);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_rr_set_bin_own(rr, CI_RR_TLSA_DATA, data, len);
  if (status != CI_SUCCESS) {
    ci_free(data);
    return status;
  }

  return CI_SUCCESS;
}

static ci_status_t ci_dns_parse_rr_svcb(ci_buf_t *buf, ci_dns_rr_t *rr,
                                            size_t rdlength)
{
  ci_status_t status;
  size_t        orig_len = ci_buf_len(buf);

  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_SVCB_PRIORITY);
  if (status != CI_SUCCESS) {
    return status;
  }

  status =
    ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr, CI_RR_SVCB_TARGET);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Parse params */
  while (ci_dns_rr_remaining_len(buf, orig_len, rdlength)) {
    unsigned short opt = 0;
    unsigned short len = 0;
    unsigned char *val = NULL;

    /* Fetch be16 option */
    status = ci_buf_fetch_be16(buf, &opt);
    if (status != CI_SUCCESS) {
      return status;
    }

    /* Fetch be16 length */
    status = ci_buf_fetch_be16(buf, &len);
    if (status != CI_SUCCESS) {
      return status;
    }

    if (len) {
      status = ci_buf_fetch_bytes_dup(buf, len, CI_TRUE, &val);
      if (status != CI_SUCCESS) {
        return status;
      }
    }

    status = ci_dns_rr_set_opt_own(rr, CI_RR_SVCB_PARAMS, opt, val, len);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  return CI_SUCCESS;
}

static ci_status_t ci_dns_parse_rr_https(ci_buf_t *buf, ci_dns_rr_t *rr,
                                             size_t rdlength)
{
  ci_status_t status;
  size_t        orig_len = ci_buf_len(buf);

  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_HTTPS_PRIORITY);
  if (status != CI_SUCCESS) {
    return status;
  }

  status =
    ci_dns_parse_and_set_dns_name(buf, CI_FALSE, rr, CI_RR_HTTPS_TARGET);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Parse params */
  while (ci_dns_rr_remaining_len(buf, orig_len, rdlength)) {
    unsigned short opt = 0;
    unsigned short len = 0;
    unsigned char *val = NULL;

    /* Fetch be16 option */
    status = ci_buf_fetch_be16(buf, &opt);
    if (status != CI_SUCCESS) {
      return status;
    }

    /* Fetch be16 length */
    status = ci_buf_fetch_be16(buf, &len);
    if (status != CI_SUCCESS) {
      return status;
    }

    if (len) {
      status = ci_buf_fetch_bytes_dup(buf, len, CI_TRUE, &val);
      if (status != CI_SUCCESS) {
        return status;
      }
    }

    status = ci_dns_rr_set_opt_own(rr, CI_RR_HTTPS_PARAMS, opt, val, len);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  return CI_SUCCESS;
}

static ci_status_t ci_dns_parse_rr_uri(ci_buf_t *buf, ci_dns_rr_t *rr,
                                           size_t rdlength)
{
  char         *name = NULL;
  ci_status_t status;
  size_t        orig_len = ci_buf_len(buf);
  size_t        remaining_len;

  /* PRIORITY */
  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_URI_PRIORITY);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* WEIGHT */
  status = ci_dns_parse_and_set_be16(buf, rr, CI_RR_URI_WEIGHT);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* TARGET -- not in string format, rest of buffer, required to be
   * non-zero length */
  remaining_len = ci_dns_rr_remaining_len(buf, orig_len, rdlength);
  if (remaining_len == 0) {
    status = CI_EBADRESP;
    return status;
  }

  /* NOTE: Not in DNS string format */
  status = ci_buf_fetch_str_dup(buf, remaining_len, &name);
  if (status != CI_SUCCESS) {
    return status;
  }

  if (!ci_str_isprint(name, remaining_len)) {
    ci_free(name);
    return CI_EBADRESP;
  }

  status = ci_dns_rr_set_str_own(rr, CI_RR_URI_TARGET, name);
  if (status != CI_SUCCESS) {
    ci_free(name);
    return status;
  }
  name = NULL;

  return CI_SUCCESS;
}

static ci_status_t ci_dns_parse_rr_caa(ci_buf_t *buf, ci_dns_rr_t *rr,
                                           size_t rdlength)
{
  unsigned char *data     = NULL;
  size_t         data_len = 0;
  ci_status_t  status;
  size_t         orig_len = ci_buf_len(buf);

  /* CRITICAL */
  status = ci_dns_parse_and_set_u8(buf, rr, CI_RR_CAA_CRITICAL);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Tag */
  status = ci_dns_parse_and_set_dns_str(
    buf, ci_dns_rr_remaining_len(buf, orig_len, rdlength), rr,
    CI_RR_CAA_TAG, CI_FALSE);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Value - binary! (remaining buffer */
  data_len = ci_dns_rr_remaining_len(buf, orig_len, rdlength);
  if (data_len == 0) {
    status = CI_EBADRESP;
    return status;
  }
  status = ci_buf_fetch_bytes_dup(buf, data_len, CI_TRUE, &data);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_rr_set_bin_own(rr, CI_RR_CAA_VALUE, data, data_len);
  if (status != CI_SUCCESS) {
    ci_free(data);
    return status;
  }
  data = NULL;

  return CI_SUCCESS;
}

static ci_status_t ci_dns_parse_rr_raw_rr(ci_buf_t    *buf,
                                              ci_dns_rr_t *rr,
                                              size_t         rdlength,
                                              unsigned short raw_type)
{
  ci_status_t  status;
  unsigned char *bytes = NULL;

  if (rdlength == 0) {
    return CI_SUCCESS;
  }

  status = ci_buf_fetch_bytes_dup(buf, rdlength, CI_FALSE, &bytes);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Can't fail */
  status = ci_dns_rr_set_u16(rr, CI_RR_RAW_RR_TYPE, raw_type);
  if (status != CI_SUCCESS) {
    ci_free(bytes);
    return status;
  }

  status = ci_dns_rr_set_bin_own(rr, CI_RR_RAW_RR_DATA, bytes, rdlength);
  if (status != CI_SUCCESS) {
    ci_free(bytes);
    return status;
  }

  return CI_SUCCESS;
}

static ci_status_t ci_dns_parse_header(ci_buf_t *buf, unsigned int flags,
                                           ci_dns_record_t **dnsrec,
                                           unsigned short     *qdcount,
                                           unsigned short     *ancount,
                                           unsigned short     *nscount,
                                           unsigned short     *arcount)
{
  ci_status_t     status = CI_EBADRESP;
  unsigned short    u16;
  unsigned short    id;
  unsigned short    dns_flags = 0;
  ci_dns_opcode_t opcode;
  unsigned short    rcode;

  (void)flags; /* currently unused */

  if (buf == NULL || dnsrec == NULL || qdcount == NULL || ancount == NULL ||
      nscount == NULL || arcount == NULL) {
    return CI_EFORMERR;
  }

  *dnsrec = NULL;

  /*
   *  RFC 1035 4.1.1. Header section format.
   *  and Updated by RFC 2065 to add AD and CD bits.
   *                                  1  1  1  1  1  1
   *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *  |                      ID                       |
   *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *  |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
   *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *  |                    QDCOUNT                    |
   *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *  |                    ANCOUNT                    |
   *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *  |                    NSCOUNT                    |
   *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   *  |                    ARCOUNT                    |
   *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */

  /* ID */
  status = ci_buf_fetch_be16(buf, &id);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  /* Flags */
  status = ci_buf_fetch_be16(buf, &u16);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  /* QR */
  if (u16 & 0x8000) {
    dns_flags |= CI_FLAG_QR;
  }

  /* OPCODE */
  opcode = (u16 >> 11) & 0xf;

  /* AA */
  if (u16 & 0x400) {
    dns_flags |= CI_FLAG_AA;
  }

  /* TC */
  if (u16 & 0x200) {
    dns_flags |= CI_FLAG_TC;
  }

  /* RD */
  if (u16 & 0x100) {
    dns_flags |= CI_FLAG_RD;
  }

  /* RA */
  if (u16 & 0x80) {
    dns_flags |= CI_FLAG_RA;
  }

  /* Z -- unused */

  /* AD */
  if (u16 & 0x20) {
    dns_flags |= CI_FLAG_AD;
  }

  /* CD */
  if (u16 & 0x10) {
    dns_flags |= CI_FLAG_CD;
  }

  /* RCODE */
  rcode = u16 & 0xf;

  /* QDCOUNT */
  status = ci_buf_fetch_be16(buf, qdcount);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  /* ANCOUNT */
  status = ci_buf_fetch_be16(buf, ancount);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  /* NSCOUNT */
  status = ci_buf_fetch_be16(buf, nscount);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  /* ARCOUNT */
  status = ci_buf_fetch_be16(buf, arcount);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  status = ci_dns_record_create(dnsrec, id, dns_flags, opcode,
                                  CI_RCODE_NOERROR /* Temporary */);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  (*dnsrec)->raw_rcode = rcode;

  if (*ancount > 0) {
    status =
      ci_dns_record_rr_prealloc(*dnsrec, CI_SECTION_ANSWER, *ancount);
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  if (*nscount > 0) {
    status =
      ci_dns_record_rr_prealloc(*dnsrec, CI_SECTION_AUTHORITY, *nscount);
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  if (*arcount > 0) {
    status =
      ci_dns_record_rr_prealloc(*dnsrec, CI_SECTION_ADDITIONAL, *arcount);
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  return CI_SUCCESS;

fail:
  ci_dns_record_destroy(*dnsrec);
  *dnsrec  = NULL;
  *qdcount = 0;
  *ancount = 0;
  *nscount = 0;
  *arcount = 0;

  return status;
}

static ci_status_t
  ci_dns_parse_rr_data(ci_buf_t *buf, size_t rdlength, ci_dns_rr_t *rr,
                         ci_dns_rec_type_t type, unsigned short raw_type,
                         unsigned short raw_class, unsigned int raw_ttl)
{
  switch (type) {
    case CI_REC_TYPE_A:
      return ci_dns_parse_rr_a(buf, rr, rdlength);
    case CI_REC_TYPE_NS:
      return ci_dns_parse_rr_ns(buf, rr, rdlength);
    case CI_REC_TYPE_CNAME:
      return ci_dns_parse_rr_cname(buf, rr, rdlength);
    case CI_REC_TYPE_SOA:
      return ci_dns_parse_rr_soa(buf, rr, rdlength);
    case CI_REC_TYPE_PTR:
      return ci_dns_parse_rr_ptr(buf, rr, rdlength);
    case CI_REC_TYPE_HINFO:
      return ci_dns_parse_rr_hinfo(buf, rr, rdlength);
    case CI_REC_TYPE_MX:
      return ci_dns_parse_rr_mx(buf, rr, rdlength);
    case CI_REC_TYPE_TXT:
      return ci_dns_parse_rr_txt(buf, rr, rdlength);
    case CI_REC_TYPE_SIG:
      return ci_dns_parse_rr_sig(buf, rr, rdlength);
    case CI_REC_TYPE_AAAA:
      return ci_dns_parse_rr_aaaa(buf, rr, rdlength);
    case CI_REC_TYPE_SRV:
      return ci_dns_parse_rr_srv(buf, rr, rdlength);
    case CI_REC_TYPE_NAPTR:
      return ci_dns_parse_rr_naptr(buf, rr, rdlength);
    case CI_REC_TYPE_ANY:
      return CI_EBADRESP;
    case CI_REC_TYPE_OPT:
      return ci_dns_parse_rr_opt(buf, rr, rdlength, raw_class, raw_ttl);
    case CI_REC_TYPE_TLSA:
      return ci_dns_parse_rr_tlsa(buf, rr, rdlength);
    case CI_REC_TYPE_SVCB:
      return ci_dns_parse_rr_svcb(buf, rr, rdlength);
    case CI_REC_TYPE_HTTPS:
      return ci_dns_parse_rr_https(buf, rr, rdlength);
    case CI_REC_TYPE_URI:
      return ci_dns_parse_rr_uri(buf, rr, rdlength);
    case CI_REC_TYPE_CAA:
      return ci_dns_parse_rr_caa(buf, rr, rdlength);
    case CI_REC_TYPE_RAW_RR:
      return ci_dns_parse_rr_raw_rr(buf, rr, rdlength, raw_type);
  }
  return CI_EFORMERR;
}

static ci_status_t ci_dns_parse_qd(ci_buf_t        *buf,
                                       ci_dns_record_t *dnsrec)
{
  char               *name = NULL;
  unsigned short      u16;
  ci_status_t       status;
  ci_dns_rec_type_t type;
  ci_dns_class_t    qclass;
  /* The question section is used to carry the "question" in most queries,
   * i.e., the parameters that define what is being asked.  The section
   * contains QDCOUNT (usually 1) entries, each of the following format:
   *                                 1  1  1  1  1  1
   *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                                               |
   * /                     QNAME                     /
   * /                                               /
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                     QTYPE                     |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                     QCLASS                    |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */

  /* Name */
  status = ci_dns_name_parse(buf, &name, CI_FALSE);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Type */
  status = ci_buf_fetch_be16(buf, &u16);
  if (status != CI_SUCCESS) {
    goto done;
  }
  type = u16;

  /* Class */
  status = ci_buf_fetch_be16(buf, &u16);
  if (status != CI_SUCCESS) {
    goto done;
  }
  qclass = u16;

  /* Add question */
  status = ci_dns_record_query_add(dnsrec, name, type, qclass);
  if (status != CI_SUCCESS) {
    goto done;
  }

done:
  ci_free(name);
  return status;
}

static ci_status_t ci_dns_parse_rr(ci_buf_t *buf, unsigned int flags,
                                       ci_dns_section_t sect,
                                       ci_dns_record_t *dnsrec)
{
  char               *name = NULL;
  unsigned short      u16;
  unsigned short      raw_type;
  ci_status_t       status;
  ci_dns_rec_type_t type;
  ci_dns_class_t    qclass;
  unsigned int        ttl;
  size_t              rdlength;
  ci_dns_rr_t      *rr            = NULL;
  size_t              remaining_len = 0;
  size_t              processed_len = 0;
  ci_bool_t         namecomp;

  /* All RRs have the same top level format shown below:
   *                                 1  1  1  1  1  1
   *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                                               |
   * /                                               /
   * /                      NAME                     /
   * |                                               |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                      TYPE                     |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                     CLASS                     |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                      TTL                      |
   * |                                               |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                   RDLENGTH                    |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
   * /                     RDATA                     /
   * /                                               /
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */

  /* Name */
  status = ci_dns_name_parse(buf, &name, CI_FALSE);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Type */
  status = ci_buf_fetch_be16(buf, &u16);
  if (status != CI_SUCCESS) {
    goto done;
  }
  type     = u16;
  raw_type = u16; /* Only used for raw rr data */

  /* Class */
  status = ci_buf_fetch_be16(buf, &u16);
  if (status != CI_SUCCESS) {
    goto done;
  }
  qclass = u16;

  /* TTL */
  status = ci_buf_fetch_be32(buf, &ttl);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Length */
  status = ci_buf_fetch_be16(buf, &u16);
  if (status != CI_SUCCESS) {
    goto done;
  }
  rdlength = u16;

  if (!ci_dns_rec_type_isvalid(type, CI_FALSE)) {
    type = CI_REC_TYPE_RAW_RR;
  }

  namecomp = ci_dns_rec_allow_name_comp(type);
  if (sect == CI_SECTION_ANSWER &&
      (flags &
       (namecomp ? CI_DNS_PARSE_AN_BASE_RAW : CI_DNS_PARSE_AN_EXT_RAW))) {
    type = CI_REC_TYPE_RAW_RR;
  }
  if (sect == CI_SECTION_AUTHORITY &&
      (flags &
       (namecomp ? CI_DNS_PARSE_NS_BASE_RAW : CI_DNS_PARSE_NS_EXT_RAW))) {
    type = CI_REC_TYPE_RAW_RR;
  }
  if (sect == CI_SECTION_ADDITIONAL &&
      (flags &
       (namecomp ? CI_DNS_PARSE_AR_BASE_RAW : CI_DNS_PARSE_AR_EXT_RAW))) {
    type = CI_REC_TYPE_RAW_RR;
  }

  /* Pull into another buffer for safety */
  if (rdlength > ci_buf_len(buf)) {
    status = CI_EBADRESP;
    goto done;
  }

  /* Add the base rr */
  status =
    ci_dns_record_rr_add(&rr, dnsrec, sect, name, type,
                           type == CI_REC_TYPE_OPT ? CI_CLASS_IN : qclass,
                           type == CI_REC_TYPE_OPT ? 0 : ttl);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Record the current remaining length in the buffer so we can tell how
   * much was processed */
  remaining_len = ci_buf_len(buf);

  /* Fill in the data for the rr */
  status = ci_dns_parse_rr_data(buf, rdlength, rr, type, raw_type,
                                  (unsigned short)qclass, ttl);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Determine how many bytes were processed */
  processed_len = remaining_len - ci_buf_len(buf);

  /* If too many bytes were processed, error! */
  if (processed_len > rdlength) {
    status = CI_EBADRESP;
    goto done;
  }

  /* If too few bytes were processed, consume the unprocessed data for this
   * record as the parser may not have wanted/needed to use it */
  if (processed_len < rdlength) {
    ci_buf_consume(buf, rdlength - processed_len);
  }


done:
  ci_free(name);
  return status;
}

static ci_status_t ci_dns_parse_buf(ci_buf_t *buf, unsigned int flags,
                                        ci_dns_record_t **dnsrec)
{
  ci_status_t  status;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short nscount;
  unsigned short arcount;
  unsigned short i;

  if (buf == NULL || dnsrec == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* Maximum DNS packet size is 64k, even over TCP */
  if (ci_buf_len(buf) > 0xFFFF) {
    return CI_EFORMERR;
  }

  /* All communications inside of the domain protocol are carried in a single
   * format called a message.  The top level format of message is divided
   * into 5 sections (some of which are empty in certain cases) shown below:
   *
   * +---------------------+
   * |        Header       |
   * +---------------------+
   * |       Question      | the question for the name server
   * +---------------------+
   * |        Answer       | RRs answering the question
   * +---------------------+
   * |      Authority      | RRs pointing toward an authority
   * +---------------------+
   * |      Additional     | RRs holding additional information
   * +---------------------+
   */

  /* Parse header */
  status = ci_dns_parse_header(buf, flags, dnsrec, &qdcount, &ancount,
                                 &nscount, &arcount);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  /* Must have questions */
  if (qdcount == 0) {
    status = CI_EBADRESP;
    goto fail;
  }

  /* XXX: this should be controlled by a flag in case we want to allow
   *      multiple questions.  I think mDNS allows this */
  if (qdcount > 1) {
    status = CI_EBADRESP;
    goto fail;
  }

  /* Parse questions */
  for (i = 0; i < qdcount; i++) {
    status = ci_dns_parse_qd(buf, *dnsrec);
    if (status != CI_SUCCESS) {
      goto fail;
    }
  }

  /* Parse Answers */
  for (i = 0; i < ancount; i++) {
    status = ci_dns_parse_rr(buf, flags, CI_SECTION_ANSWER, *dnsrec);
    if (status != CI_SUCCESS) {
      goto fail;
    }
  }

  /* Parse Authority */
  for (i = 0; i < nscount; i++) {
    status = ci_dns_parse_rr(buf, flags, CI_SECTION_AUTHORITY, *dnsrec);
    if (status != CI_SUCCESS) {
      goto fail;
    }
  }

  /* Parse Additional */
  for (i = 0; i < arcount; i++) {
    status = ci_dns_parse_rr(buf, flags, CI_SECTION_ADDITIONAL, *dnsrec);
    if (status != CI_SUCCESS) {
      goto fail;
    }
  }

  /* Finalize rcode now that if we have OPT it is processed */
  if (!ci_dns_rcode_isvalid((*dnsrec)->raw_rcode)) {
    (*dnsrec)->rcode = CI_RCODE_SERVFAIL;
  } else {
    (*dnsrec)->rcode = (ci_dns_rcode_t)(*dnsrec)->raw_rcode;
  }

  return CI_SUCCESS;

fail:
  ci_dns_record_destroy(*dnsrec);
  *dnsrec = NULL;
  return status;
}

ci_status_t ci_dns_parse(const unsigned char *buf, size_t buf_len,
                             unsigned int flags, ci_dns_record_t **dnsrec)
{
  ci_buf_t   *parser = NULL;
  ci_status_t status;

  if (buf == NULL || buf_len == 0 || dnsrec == NULL) {
    return CI_EFORMERR;
  }

  parser = ci_buf_create_const(buf, buf_len);
  if (parser == NULL) {
    return CI_ENOMEM;
  }

  status = ci_dns_parse_buf(parser, flags, dnsrec);
  ci_buf_destroy(parser);

  return status;
}
