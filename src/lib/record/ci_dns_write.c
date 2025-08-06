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


static ci_status_t ci_dns_write_header(const ci_dns_record_t *dnsrec,
                                           ci_buf_t              *buf)
{
  unsigned short u16;
  unsigned short opcode;
  unsigned short rcode;

  ci_status_t  status;

  /* ID */
  status = ci_buf_append_be16(buf, dnsrec->id);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* Flags */
  u16 = 0;

  /* QR */
  if (dnsrec->flags & CI_FLAG_QR) {
    u16 |= 0x8000;
  }

  /* OPCODE */
  opcode   = (unsigned short)(dnsrec->opcode & 0xF);
  opcode <<= 11;
  u16     |= opcode;

  /* AA */
  if (dnsrec->flags & CI_FLAG_AA) {
    u16 |= 0x400;
  }

  /* TC */
  if (dnsrec->flags & CI_FLAG_TC) {
    u16 |= 0x200;
  }

  /* RD */
  if (dnsrec->flags & CI_FLAG_RD) {
    u16 |= 0x100;
  }

  /* RA */
  if (dnsrec->flags & CI_FLAG_RA) {
    u16 |= 0x80;
  }

  /* Z -- unused */

  /* AD */
  if (dnsrec->flags & CI_FLAG_AD) {
    u16 |= 0x20;
  }

  /* CD */
  if (dnsrec->flags & CI_FLAG_CD) {
    u16 |= 0x10;
  }

  /* RCODE */
  if (dnsrec->rcode > 15 && ci_dns_get_opt_rr_const(dnsrec) == NULL) {
    /* Must have OPT RR in order to write extended error codes */
    rcode = CI_RCODE_SERVFAIL;
  } else {
    rcode = (unsigned short)(dnsrec->rcode & 0xF);
  }
  u16 |= rcode;

  status = ci_buf_append_be16(buf, u16);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* QDCOUNT */
  status = ci_buf_append_be16(
    buf, (unsigned short)ci_dns_record_query_cnt(dnsrec));
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* ANCOUNT */
  status = ci_buf_append_be16(
    buf, (unsigned short)ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER));
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* NSCOUNT */
  status = ci_buf_append_be16(buf, (unsigned short)ci_dns_record_rr_cnt(
                                       dnsrec, CI_SECTION_AUTHORITY));
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* ARCOUNT */
  status = ci_buf_append_be16(buf, (unsigned short)ci_dns_record_rr_cnt(
                                       dnsrec, CI_SECTION_ADDITIONAL));
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  return CI_SUCCESS;
}

static ci_status_t ci_dns_write_questions(const ci_dns_record_t *dnsrec,
                                              ci_llist_t           **namelist,
                                              ci_buf_t              *buf)
{
  size_t i;

  for (i = 0; i < ci_dns_record_query_cnt(dnsrec); i++) {
    ci_status_t       status;
    const char         *name = NULL;
    ci_dns_rec_type_t qtype;
    ci_dns_class_t    qclass;

    status = ci_dns_record_query_get(dnsrec, i, &name, &qtype, &qclass);
    if (status != CI_SUCCESS) {
      return status;
    }

    /* Name */
    status = ci_dns_name_write(buf, namelist, CI_TRUE, name);
    if (status != CI_SUCCESS) {
      return status;
    }

    /* Type */
    status = ci_buf_append_be16(buf, (unsigned short)qtype);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* Class */
    status = ci_buf_append_be16(buf, (unsigned short)qclass);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  return CI_SUCCESS;
}

static ci_status_t ci_dns_write_rr_name(ci_buf_t          *buf,
                                            const ci_dns_rr_t *rr,
                                            ci_llist_t       **namelist,
                                            ci_bool_t       validate_hostname,
                                            ci_dns_rr_key_t key)
{
  const char *name;

  name = ci_dns_rr_get_str(rr, key);
  if (name == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  return ci_dns_name_write(buf, namelist, validate_hostname, name);
}

static ci_status_t ci_dns_write_rr_str(ci_buf_t          *buf,
                                           const ci_dns_rr_t *rr,
                                           ci_dns_rr_key_t    key)
{
  const char   *str;
  size_t        len;
  ci_status_t status;

  str = ci_dns_rr_get_str(rr, key);
  if (str == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  len = ci_strlen(str);
  if (len > 255) {
    return CI_EFORMERR;
  }

  /* Write 1 byte length */
  status = ci_buf_append_byte(buf, (unsigned char)(len & 0xFF));
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (len == 0) {
    return CI_SUCCESS;
  }

  /* Write string */
  return ci_buf_append(buf, (const unsigned char *)str, len);
}

static ci_status_t ci_dns_write_binstr(ci_buf_t          *buf,
                                           const unsigned char *bin,
                                           size_t               bin_len)
{
  const unsigned char *ptr;
  size_t               ptr_len;
  ci_status_t        status;

  /* split into possible multiple 255-byte or less length strings */
  ptr     = bin;
  ptr_len = bin_len;
  do {
    size_t len = ptr_len;
    if (len > 255) {
      len = 255;
    }

    /* Length */
    status = ci_buf_append_byte(buf, (unsigned char)(len & 0xFF));
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* String */
    if (len) {
      status = ci_buf_append(buf, ptr, len);
      if (status != CI_SUCCESS) {
        return status; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }

    ptr     += len;
    ptr_len -= len;
  } while (ptr_len > 0);

  return CI_SUCCESS;
}

static ci_status_t ci_dns_write_rr_abin(ci_buf_t          *buf,
                                            const ci_dns_rr_t *rr,
                                            ci_dns_rr_key_t    key)
{
  ci_status_t status = CI_EFORMERR;
  size_t        i;
  size_t        cnt = ci_dns_rr_get_abin_cnt(rr, key);

  if (cnt == 0) {
    return CI_EFORMERR;
  }

  for (i = 0; i < cnt; i++) {
    const unsigned char *bin;
    size_t               bin_len;

    bin = ci_dns_rr_get_abin(rr, key, i, &bin_len);

    status = ci_dns_write_binstr(buf, bin, bin_len);
    if (status != CI_SUCCESS) {
      break;
    }
  }

  return status;
}

static ci_status_t ci_dns_write_rr_be32(ci_buf_t          *buf,
                                            const ci_dns_rr_t *rr,
                                            ci_dns_rr_key_t    key)
{
  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_U32) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }
  return ci_buf_append_be32(buf, ci_dns_rr_get_u32(rr, key));
}

static ci_status_t ci_dns_write_rr_be16(ci_buf_t          *buf,
                                            const ci_dns_rr_t *rr,
                                            ci_dns_rr_key_t    key)
{
  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_U16) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }
  return ci_buf_append_be16(buf, ci_dns_rr_get_u16(rr, key));
}

static ci_status_t ci_dns_write_rr_u8(ci_buf_t          *buf,
                                          const ci_dns_rr_t *rr,
                                          ci_dns_rr_key_t    key)
{
  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_U8) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }
  return ci_buf_append_byte(buf, ci_dns_rr_get_u8(rr, key));
}

static ci_status_t ci_dns_write_rr_a(ci_buf_t          *buf,
                                         const ci_dns_rr_t *rr,
                                         ci_llist_t       **namelist)
{
  const struct in_addr *addr;
  (void)namelist;

  addr = ci_dns_rr_get_addr(rr, CI_RR_A_ADDR);
  if (addr == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  return ci_buf_append(buf, (const unsigned char *)addr, sizeof(*addr));
}

static ci_status_t ci_dns_write_rr_ns(ci_buf_t          *buf,
                                          const ci_dns_rr_t *rr,
                                          ci_llist_t       **namelist)
{
  return ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE,
                                CI_RR_NS_NSDNAME);
}

static ci_status_t ci_dns_write_rr_cname(ci_buf_t          *buf,
                                             const ci_dns_rr_t *rr,
                                             ci_llist_t       **namelist)
{
  return ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE,
                                CI_RR_CNAME_CNAME);
}

static ci_status_t ci_dns_write_rr_soa(ci_buf_t          *buf,
                                           const ci_dns_rr_t *rr,
                                           ci_llist_t       **namelist)
{
  ci_status_t status;

  /* MNAME */
  status =
    ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE, CI_RR_SOA_MNAME);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* RNAME */
  status =
    ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE, CI_RR_SOA_RNAME);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* SERIAL */
  status = ci_dns_write_rr_be32(buf, rr, CI_RR_SOA_SERIAL);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* REFRESH */
  status = ci_dns_write_rr_be32(buf, rr, CI_RR_SOA_REFRESH);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* RETRY */
  status = ci_dns_write_rr_be32(buf, rr, CI_RR_SOA_RETRY);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* EXPIRE */
  status = ci_dns_write_rr_be32(buf, rr, CI_RR_SOA_EXPIRE);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* MINIMUM */
  return ci_dns_write_rr_be32(buf, rr, CI_RR_SOA_MINIMUM);
}

static ci_status_t ci_dns_write_rr_ptr(ci_buf_t          *buf,
                                           const ci_dns_rr_t *rr,
                                           ci_llist_t       **namelist)
{
  return ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE,
                                CI_RR_PTR_DNAME);
}

static ci_status_t ci_dns_write_rr_hinfo(ci_buf_t          *buf,
                                             const ci_dns_rr_t *rr,
                                             ci_llist_t       **namelist)
{
  ci_status_t status;

  (void)namelist;

  /* CPU */
  status = ci_dns_write_rr_str(buf, rr, CI_RR_HINFO_CPU);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* OS */
  return ci_dns_write_rr_str(buf, rr, CI_RR_HINFO_OS);
}

static ci_status_t ci_dns_write_rr_mx(ci_buf_t          *buf,
                                          const ci_dns_rr_t *rr,
                                          ci_llist_t       **namelist)
{
  ci_status_t status;

  /* PREFERENCE */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_MX_PREFERENCE);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* EXCHANGE */
  return ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE,
                                CI_RR_MX_EXCHANGE);
}

static ci_status_t ci_dns_write_rr_txt(ci_buf_t          *buf,
                                           const ci_dns_rr_t *rr,
                                           ci_llist_t       **namelist)
{
  (void)namelist;
  return ci_dns_write_rr_abin(buf, rr, CI_RR_TXT_DATA);
}

static ci_status_t ci_dns_write_rr_sig(ci_buf_t          *buf,
                                           const ci_dns_rr_t *rr,
                                           ci_llist_t       **namelist)
{
  ci_status_t        status;
  const unsigned char *data;
  size_t               len = 0;

  (void)namelist;

  /* TYPE COVERED */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_SIG_TYPE_COVERED);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* ALGORITHM */
  status = ci_dns_write_rr_u8(buf, rr, CI_RR_SIG_ALGORITHM);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* LABELS */
  status = ci_dns_write_rr_u8(buf, rr, CI_RR_SIG_LABELS);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* ORIGINAL TTL */
  status = ci_dns_write_rr_be32(buf, rr, CI_RR_SIG_ORIGINAL_TTL);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* EXPIRATION */
  status = ci_dns_write_rr_be32(buf, rr, CI_RR_SIG_EXPIRATION);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* INCEPTION */
  status = ci_dns_write_rr_be32(buf, rr, CI_RR_SIG_INCEPTION);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* KEY TAG */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_SIG_KEY_TAG);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* SIGNERS NAME */
  status = ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE,
                                  CI_RR_SIG_SIGNERS_NAME);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* SIGNATURE -- binary, rest of buffer, required to be non-zero length */
  data = ci_dns_rr_get_bin(rr, CI_RR_SIG_SIGNATURE, &len);
  if (data == NULL || len == 0) {
    return CI_EFORMERR;
  }

  return ci_buf_append(buf, data, len);
}

static ci_status_t ci_dns_write_rr_aaaa(ci_buf_t          *buf,
                                            const ci_dns_rr_t *rr,
                                            ci_llist_t       **namelist)
{
  const struct ci_in6_addr *addr;
  (void)namelist;

  addr = ci_dns_rr_get_addr6(rr, CI_RR_AAAA_ADDR);
  if (addr == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  return ci_buf_append(buf, (const unsigned char *)addr, sizeof(*addr));
}

static ci_status_t ci_dns_write_rr_srv(ci_buf_t          *buf,
                                           const ci_dns_rr_t *rr,
                                           ci_llist_t       **namelist)
{
  ci_status_t status;

  /* PRIORITY */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_SRV_PRIORITY);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* WEIGHT */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_SRV_WEIGHT);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* PORT */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_SRV_PORT);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* TARGET */
  return ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE,
                                CI_RR_SRV_TARGET);
}

static ci_status_t ci_dns_write_rr_naptr(ci_buf_t          *buf,
                                             const ci_dns_rr_t *rr,
                                             ci_llist_t       **namelist)
{
  ci_status_t status;

  /* ORDER */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_NAPTR_ORDER);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* PREFERENCE */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_NAPTR_PREFERENCE);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* FLAGS */
  status = ci_dns_write_rr_str(buf, rr, CI_RR_NAPTR_FLAGS);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* SERVICES */
  status = ci_dns_write_rr_str(buf, rr, CI_RR_NAPTR_SERVICES);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* REGEXP */
  status = ci_dns_write_rr_str(buf, rr, CI_RR_NAPTR_REGEXP);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* REPLACEMENT */
  return ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE,
                                CI_RR_NAPTR_REPLACEMENT);
}

static ci_status_t ci_dns_write_rr_opt(ci_buf_t          *buf,
                                           const ci_dns_rr_t *rr,
                                           ci_llist_t       **namelist)
{
  size_t         len = ci_buf_len(buf);
  ci_status_t  status;
  unsigned int   ttl = 0;
  size_t         i;
  unsigned short rcode = (unsigned short)((rr->parent->rcode >> 4) & 0xFF);

  (void)namelist;

  /* Coverity reports on this even though its not possible when taken
   * into context */
  if (len == 0) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* We need to go back and overwrite the class and ttl that were emitted as
   * the OPT record overloads them for its own use (yes, very strange!) */
  status = ci_buf_set_length(buf, len - 2 /* RDLENGTH */
                                      - 4   /* TTL */
                                      - 2 /* CLASS */);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Class -> UDP Size */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_OPT_UDP_SIZE);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* TTL -> rcode (u8) << 24 | version (u8) << 16 | flags (u16) */
  ttl |= (unsigned int)rcode << 24;
  ttl |= (unsigned int)ci_dns_rr_get_u8(rr, CI_RR_OPT_VERSION) << 16;
  ttl |= (unsigned int)ci_dns_rr_get_u16(rr, CI_RR_OPT_FLAGS);

  status = ci_buf_append_be32(buf, ttl);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* Now go back to real end */
  status = ci_buf_set_length(buf, len);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Append Options */
  for (i = 0; i < ci_dns_rr_get_opt_cnt(rr, CI_RR_OPT_OPTIONS); i++) {
    unsigned short       opt;
    size_t               val_len;
    const unsigned char *val;

    opt = ci_dns_rr_get_opt(rr, CI_RR_OPT_OPTIONS, i, &val, &val_len);

    /* BE16 option */
    status = ci_buf_append_be16(buf, opt);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* BE16 length */
    status = ci_buf_append_be16(buf, (unsigned short)(val_len & 0xFFFF));
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* Value */
    if (val && val_len) {
      status = ci_buf_append(buf, val, val_len);
      if (status != CI_SUCCESS) {
        return status; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  return CI_SUCCESS;
}

static ci_status_t ci_dns_write_rr_tlsa(ci_buf_t          *buf,
                                            const ci_dns_rr_t *rr,
                                            ci_llist_t       **namelist)
{
  ci_status_t        status;
  const unsigned char *data;
  size_t               len = 0;

  (void)namelist;

  /* CERT_USAGE */
  status = ci_dns_write_rr_u8(buf, rr, CI_RR_TLSA_CERT_USAGE);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* SELECTOR */
  status = ci_dns_write_rr_u8(buf, rr, CI_RR_TLSA_SELECTOR);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* MATCH */
  status = ci_dns_write_rr_u8(buf, rr, CI_RR_TLSA_MATCH);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* DATA -- binary, rest of buffer, required to be non-zero length */
  data = ci_dns_rr_get_bin(rr, CI_RR_TLSA_DATA, &len);
  if (data == NULL || len == 0) {
    return CI_EFORMERR;
  }

  return ci_buf_append(buf, data, len);
}

static ci_status_t ci_dns_write_rr_svcb(ci_buf_t          *buf,
                                            const ci_dns_rr_t *rr,
                                            ci_llist_t       **namelist)
{
  ci_status_t status;
  size_t        i;

  /* PRIORITY */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_SVCB_PRIORITY);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* TARGET */
  status =
    ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE, CI_RR_SVCB_TARGET);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Append Params */
  for (i = 0; i < ci_dns_rr_get_opt_cnt(rr, CI_RR_SVCB_PARAMS); i++) {
    unsigned short       opt;
    size_t               val_len;
    const unsigned char *val;

    opt = ci_dns_rr_get_opt(rr, CI_RR_SVCB_PARAMS, i, &val, &val_len);

    /* BE16 option */
    status = ci_buf_append_be16(buf, opt);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* BE16 length */
    status = ci_buf_append_be16(buf, (unsigned short)(val_len & 0xFFFF));
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* Value */
    if (val && val_len) {
      status = ci_buf_append(buf, val, val_len);
      if (status != CI_SUCCESS) {
        return status; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }
  return CI_SUCCESS;
}

static ci_status_t ci_dns_write_rr_https(ci_buf_t          *buf,
                                             const ci_dns_rr_t *rr,
                                             ci_llist_t       **namelist)
{
  ci_status_t status;
  size_t        i;

  /* PRIORITY */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_HTTPS_PRIORITY);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* TARGET */
  status =
    ci_dns_write_rr_name(buf, rr, namelist, CI_FALSE, CI_RR_HTTPS_TARGET);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Append Params */
  for (i = 0; i < ci_dns_rr_get_opt_cnt(rr, CI_RR_HTTPS_PARAMS); i++) {
    unsigned short       opt;
    size_t               val_len;
    const unsigned char *val;

    opt = ci_dns_rr_get_opt(rr, CI_RR_HTTPS_PARAMS, i, &val, &val_len);

    /* BE16 option */
    status = ci_buf_append_be16(buf, opt);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* BE16 length */
    status = ci_buf_append_be16(buf, (unsigned short)(val_len & 0xFFFF));
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* Value */
    if (val && val_len) {
      status = ci_buf_append(buf, val, val_len);
      if (status != CI_SUCCESS) {
        return status; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }
  return CI_SUCCESS;
}

static ci_status_t ci_dns_write_rr_uri(ci_buf_t          *buf,
                                           const ci_dns_rr_t *rr,
                                           ci_llist_t       **namelist)
{
  ci_status_t status;
  const char   *target;

  (void)namelist;

  /* PRIORITY */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_URI_PRIORITY);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* WEIGHT */
  status = ci_dns_write_rr_be16(buf, rr, CI_RR_URI_WEIGHT);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* TARGET -- not in DNS string format, rest of buffer, required to be
   * non-zero length */
  target = ci_dns_rr_get_str(rr, CI_RR_URI_TARGET);
  if (target == NULL || ci_strlen(target) == 0) {
    return CI_EFORMERR;
  }

  return ci_buf_append(buf, (const unsigned char *)target,
                         ci_strlen(target));
}

static ci_status_t ci_dns_write_rr_caa(ci_buf_t          *buf,
                                           const ci_dns_rr_t *rr,
                                           ci_llist_t       **namelist)
{
  const unsigned char *data     = NULL;
  size_t               data_len = 0;
  ci_status_t        status;

  (void)namelist;

  /* CRITICAL */
  status = ci_dns_write_rr_u8(buf, rr, CI_RR_CAA_CRITICAL);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* Tag */
  status = ci_dns_write_rr_str(buf, rr, CI_RR_CAA_TAG);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* Value - binary! (remaining buffer */
  data = ci_dns_rr_get_bin(rr, CI_RR_CAA_VALUE, &data_len);
  if (data == NULL || data_len == 0) {
    return CI_EFORMERR;
  }

  return ci_buf_append(buf, data, data_len);
}

static ci_status_t ci_dns_write_rr_raw_rr(ci_buf_t          *buf,
                                              const ci_dns_rr_t *rr,
                                              ci_llist_t       **namelist)
{
  size_t               len = ci_buf_len(buf);
  ci_status_t        status;
  const unsigned char *data     = NULL;
  size_t               data_len = 0;

  (void)namelist;

  /* Coverity reports on this even though its not possible when taken
   * into context */
  if (len == 0) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* We need to go back and overwrite the type that was emitted by the parent
   * function */
  status = ci_buf_set_length(buf, len - 2 /* RDLENGTH */
                                      - 4   /* TTL */
                                      - 2   /* CLASS */
                                      - 2 /* TYPE */);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_write_rr_be16(buf, rr, CI_RR_RAW_RR_TYPE);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* Now go back to real end */
  status = ci_buf_set_length(buf, len);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Output raw data */
  data = ci_dns_rr_get_bin(rr, CI_RR_RAW_RR_DATA, &data_len);
  if (data == NULL) {
    return CI_EFORMERR;
  }

  if (data_len == 0) {
    return CI_SUCCESS;
  }

  return ci_buf_append(buf, data, data_len);
}

static ci_status_t ci_dns_write_rr(const ci_dns_record_t *dnsrec,
                                       ci_llist_t           **namelist,
                                       ci_dns_section_t       section,
                                       ci_buf_t              *buf)
{
  size_t i;

  for (i = 0; i < ci_dns_record_rr_cnt(dnsrec, section); i++) {
    const ci_dns_rr_t *rr;
    ci_dns_rec_type_t  type;
    ci_bool_t          allow_compress;
    ci_llist_t       **namelistptr = NULL;
    size_t               pos_len;
    ci_status_t        status;
    size_t               rdlength;
    size_t               end_length;
    unsigned int         ttl;

    rr = ci_dns_record_rr_get_const(dnsrec, section, i);
    if (rr == NULL) {
      return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    type           = ci_dns_rr_get_type(rr);
    allow_compress = ci_dns_rec_allow_name_comp(type);
    if (allow_compress) {
      namelistptr = namelist;
    }

    /* Name */
    status =
      ci_dns_name_write(buf, namelist, CI_TRUE, ci_dns_rr_get_name(rr));
    if (status != CI_SUCCESS) {
      return status;
    }

    /* Type */
    status = ci_buf_append_be16(buf, (unsigned short)type);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* Class */
    status =
      ci_buf_append_be16(buf, (unsigned short)ci_dns_rr_get_class(rr));
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* TTL */
    ttl = ci_dns_rr_get_ttl(rr);
    if (rr->parent->ttl_decrement > ttl) {
      ttl = 0;
    } else {
      ttl -= rr->parent->ttl_decrement;
    }
    status = ci_buf_append_be32(buf, ttl);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* Length */
    pos_len = ci_buf_len(buf); /* Save to write real length later */
    status  = ci_buf_append_be16(buf, 0);
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* Data */
    switch (type) {
      case CI_REC_TYPE_A:
        status = ci_dns_write_rr_a(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_NS:
        status = ci_dns_write_rr_ns(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_CNAME:
        status = ci_dns_write_rr_cname(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_SOA:
        status = ci_dns_write_rr_soa(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_PTR:
        status = ci_dns_write_rr_ptr(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_HINFO:
        status = ci_dns_write_rr_hinfo(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_MX:
        status = ci_dns_write_rr_mx(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_TXT:
        status = ci_dns_write_rr_txt(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_SIG:
        status = ci_dns_write_rr_sig(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_AAAA:
        status = ci_dns_write_rr_aaaa(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_SRV:
        status = ci_dns_write_rr_srv(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_NAPTR:
        status = ci_dns_write_rr_naptr(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_ANY:
        status = CI_EFORMERR;
        break;
      case CI_REC_TYPE_OPT:
        status = ci_dns_write_rr_opt(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_TLSA:
        status = ci_dns_write_rr_tlsa(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_SVCB:
        status = ci_dns_write_rr_svcb(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_HTTPS:
        status = ci_dns_write_rr_https(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_URI:
        status = ci_dns_write_rr_uri(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_CAA:
        status = ci_dns_write_rr_caa(buf, rr, namelistptr);
        break;
      case CI_REC_TYPE_RAW_RR:
        status = ci_dns_write_rr_raw_rr(buf, rr, namelistptr);
        break;
    }

    if (status != CI_SUCCESS) {
      return status;
    }

    /* Back off write pointer, write real length, then go back to proper
     * position */
    end_length = ci_buf_len(buf);
    rdlength   = end_length - pos_len - 2;

    status = ci_buf_set_length(buf, pos_len);
    if (status != CI_SUCCESS) {
      return status;
    }

    status = ci_buf_append_be16(buf, (unsigned short)(rdlength & 0xFFFF));
    if (status != CI_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    status = ci_buf_set_length(buf, end_length);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  return CI_SUCCESS;
}

ci_status_t ci_dns_write_buf(const ci_dns_record_t *dnsrec,
                                 ci_buf_t              *buf)
{
  ci_llist_t *namelist = NULL;
  size_t        orig_len;
  ci_status_t status;

  if (dnsrec == NULL || buf == NULL) {
    return CI_EFORMERR;
  }

  orig_len = ci_buf_len(buf);

  status = ci_dns_write_header(dnsrec, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_dns_write_questions(dnsrec, &namelist, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_dns_write_rr(dnsrec, &namelist, CI_SECTION_ANSWER, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_dns_write_rr(dnsrec, &namelist, CI_SECTION_AUTHORITY, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_dns_write_rr(dnsrec, &namelist, CI_SECTION_ADDITIONAL, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

done:
  ci_llist_destroy(namelist);
  if (status != CI_SUCCESS) {
    ci_buf_set_length(buf, orig_len);
  }

  return status;
}

ci_status_t ci_dns_write_buf_tcp(const ci_dns_record_t *dnsrec,
                                     ci_buf_t              *buf)
{
  ci_status_t status;
  size_t        orig_len;
  size_t        msg_len;
  size_t        len;

  if (dnsrec == NULL || buf == NULL) {
    return CI_EFORMERR;
  }

  orig_len = ci_buf_len(buf);

  /* Write placeholder for length */
  status = ci_buf_append_be16(buf, 0);
  if (status != CI_SUCCESS) {
    goto done; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* Write message */
  status = ci_dns_write_buf(dnsrec, buf);
  if (status != CI_SUCCESS) {
    goto done; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  len     = ci_buf_len(buf);
  msg_len = len - orig_len - 2;
  if (msg_len > 65535) {
    status = CI_EBADQUERY;
    goto done;
  }

  /* Now we need to overwrite the length, so we jump back to the original
   * message length, overwrite the section and jump back */
  ci_buf_set_length(buf, orig_len);
  status = ci_buf_append_be16(buf, (unsigned short)(msg_len & 0xFFFF));
  if (status != CI_SUCCESS) {
    goto done; /* LCOV_EXCL_LINE: UntestablePath */
  }
  ci_buf_set_length(buf, len);

done:
  if (status != CI_SUCCESS) {
    ci_buf_set_length(buf, orig_len);
  }
  return status;
}

ci_status_t ci_dns_write(const ci_dns_record_t *dnsrec,
                             unsigned char **buf, size_t *buf_len)
{
  ci_buf_t   *b = NULL;
  ci_status_t status;

  if (buf == NULL || buf_len == NULL || dnsrec == NULL) {
    return CI_EFORMERR;
  }

  *buf     = NULL;
  *buf_len = 0;

  b = ci_buf_create();
  if (b == NULL) {
    return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  status = ci_dns_write_buf(dnsrec, b);

  if (status != CI_SUCCESS) {
    ci_buf_destroy(b);
    return status;
  }

  *buf = ci_buf_finish_bin(b, buf_len);
  return status;
}

void ci_dns_record_ttl_decrement(ci_dns_record_t *dnsrec,
                                   unsigned int       ttl_decrement)
{
  if (dnsrec == NULL) {
    return;
  }
  dnsrec->ttl_decrement = ttl_decrement;
}
