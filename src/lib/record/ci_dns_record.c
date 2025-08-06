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

static void ci_dns_rr_free(ci_dns_rr_t *rr);

static void ci_dns_qd_free_cb(void *arg)
{
  ci_dns_qd_t *qd = arg;
  if (qd == NULL) {
    return;
  }
  ci_free(qd->name);
}

static void ci_dns_rr_free_cb(void *arg)
{
  ci_dns_rr_t *rr = arg;
  if (rr == NULL) {
    return;
  }
  ci_dns_rr_free(rr);
}

ci_status_t ci_dns_record_create(ci_dns_record_t **dnsrec,
                                     unsigned short id, unsigned short flags,
                                     ci_dns_opcode_t opcode,
                                     ci_dns_rcode_t  rcode)
{
  if (dnsrec == NULL) {
    return CI_EFORMERR;
  }

  *dnsrec = NULL;

  if (!ci_dns_opcode_isvalid(opcode) || !ci_dns_rcode_isvalid(rcode) ||
      !ci_dns_flags_arevalid(flags)) {
    return CI_EFORMERR;
  }

  *dnsrec = ci_malloc_zero(sizeof(**dnsrec));
  if (*dnsrec == NULL) {
    return CI_ENOMEM;
  }

  (*dnsrec)->id     = id;
  (*dnsrec)->flags  = flags;
  (*dnsrec)->opcode = opcode;
  (*dnsrec)->rcode  = rcode;
  (*dnsrec)->qd = ci_array_create(sizeof(ci_dns_qd_t), ci_dns_qd_free_cb);
  (*dnsrec)->an = ci_array_create(sizeof(ci_dns_rr_t), ci_dns_rr_free_cb);
  (*dnsrec)->ns = ci_array_create(sizeof(ci_dns_rr_t), ci_dns_rr_free_cb);
  (*dnsrec)->ar = ci_array_create(sizeof(ci_dns_rr_t), ci_dns_rr_free_cb);

  if ((*dnsrec)->qd == NULL || (*dnsrec)->an == NULL || (*dnsrec)->ns == NULL ||
      (*dnsrec)->ar == NULL) {
    ci_dns_record_destroy(*dnsrec);
    *dnsrec = NULL;
    return CI_ENOMEM;
  }

  return CI_SUCCESS;
}

unsigned short ci_dns_record_get_id(const ci_dns_record_t *dnsrec)
{
  if (dnsrec == NULL) {
    return 0;
  }
  return dnsrec->id;
}

ci_bool_t ci_dns_record_set_id(ci_dns_record_t *dnsrec, unsigned short id)
{
  if (dnsrec == NULL) {
    return CI_FALSE;
  }
  dnsrec->id = id;
  return CI_TRUE;
}

unsigned short ci_dns_record_get_flags(const ci_dns_record_t *dnsrec)
{
  if (dnsrec == NULL) {
    return 0;
  }
  return dnsrec->flags;
}

ci_dns_opcode_t ci_dns_record_get_opcode(const ci_dns_record_t *dnsrec)
{
  if (dnsrec == NULL) {
    return 0;
  }
  return dnsrec->opcode;
}

ci_dns_rcode_t ci_dns_record_get_rcode(const ci_dns_record_t *dnsrec)
{
  if (dnsrec == NULL) {
    return 0;
  }
  return dnsrec->rcode;
}

static void ci_dns_rr_free(ci_dns_rr_t *rr)
{
  ci_free(rr->name);

  switch (rr->type) {
    case CI_REC_TYPE_A:
    case CI_REC_TYPE_AAAA:
    case CI_REC_TYPE_ANY:
      /* Nothing to free */
      break;

    case CI_REC_TYPE_NS:
      ci_free(rr->r.ns.nsdname);
      break;

    case CI_REC_TYPE_CNAME:
      ci_free(rr->r.cname.cname);
      break;

    case CI_REC_TYPE_SOA:
      ci_free(rr->r.soa.mname);
      ci_free(rr->r.soa.rname);
      break;

    case CI_REC_TYPE_PTR:
      ci_free(rr->r.ptr.dname);
      break;

    case CI_REC_TYPE_HINFO:
      ci_free(rr->r.hinfo.cpu);
      ci_free(rr->r.hinfo.os);
      break;

    case CI_REC_TYPE_MX:
      ci_free(rr->r.mx.exchange);
      break;

    case CI_REC_TYPE_TXT:
      ci_dns_multistring_destroy(rr->r.txt.strs);
      break;

    case CI_REC_TYPE_SIG:
      ci_free(rr->r.sig.signers_name);
      ci_free(rr->r.sig.signature);
      break;

    case CI_REC_TYPE_SRV:
      ci_free(rr->r.srv.target);
      break;

    case CI_REC_TYPE_NAPTR:
      ci_free(rr->r.naptr.flags);
      ci_free(rr->r.naptr.services);
      ci_free(rr->r.naptr.regexp);
      ci_free(rr->r.naptr.replacement);
      break;

    case CI_REC_TYPE_OPT:
      ci_array_destroy(rr->r.opt.options);
      break;

    case CI_REC_TYPE_TLSA:
      ci_free(rr->r.tlsa.data);
      break;

    case CI_REC_TYPE_SVCB:
      ci_free(rr->r.svcb.target);
      ci_array_destroy(rr->r.svcb.params);
      break;

    case CI_REC_TYPE_HTTPS:
      ci_free(rr->r.https.target);
      ci_array_destroy(rr->r.https.params);
      break;

    case CI_REC_TYPE_URI:
      ci_free(rr->r.uri.target);
      break;

    case CI_REC_TYPE_CAA:
      ci_free(rr->r.caa.tag);
      ci_free(rr->r.caa.value);
      break;

    case CI_REC_TYPE_RAW_RR:
      ci_free(rr->r.raw_rr.data);
      break;
  }
}

void ci_dns_record_destroy(ci_dns_record_t *dnsrec)
{
  if (dnsrec == NULL) {
    return;
  }

  /* Free questions */
  ci_array_destroy(dnsrec->qd);

  /* Free answers */
  ci_array_destroy(dnsrec->an);

  /* Free authority */
  ci_array_destroy(dnsrec->ns);

  /* Free additional */
  ci_array_destroy(dnsrec->ar);

  ci_free(dnsrec);
}

size_t ci_dns_record_query_cnt(const ci_dns_record_t *dnsrec)
{
  if (dnsrec == NULL) {
    return 0;
  }
  return ci_array_len(dnsrec->qd);
}

ci_status_t ci_dns_record_query_add(ci_dns_record_t  *dnsrec,
                                        const char         *name,
                                        ci_dns_rec_type_t qtype,
                                        ci_dns_class_t    qclass)
{
  size_t         idx;
  ci_dns_qd_t *qd;
  ci_status_t  status;

  if (dnsrec == NULL || name == NULL ||
      !ci_dns_rec_type_isvalid(qtype, CI_TRUE) ||
      !ci_dns_class_isvalid(qclass, qtype, CI_TRUE)) {
    return CI_EFORMERR;
  }

  idx    = ci_array_len(dnsrec->qd);
  status = ci_array_insert_last((void **)&qd, dnsrec->qd);
  if (status != CI_SUCCESS) {
    return status;
  }

  qd->name = ci_strdup(name);
  if (qd->name == NULL) {
    ci_array_remove_at(dnsrec->qd, idx);
    return CI_ENOMEM;
  }
  qd->qtype  = qtype;
  qd->qclass = qclass;
  return CI_SUCCESS;
}

ci_status_t ci_dns_record_query_set_name(ci_dns_record_t *dnsrec,
                                             size_t idx, const char *name)
{
  char          *orig_name = NULL;
  ci_dns_qd_t *qd;

  if (dnsrec == NULL || idx >= ci_array_len(dnsrec->qd) || name == NULL) {
    return CI_EFORMERR;
  }

  qd = ci_array_at(dnsrec->qd, idx);

  orig_name = qd->name;
  qd->name  = ci_strdup(name);
  if (qd->name == NULL) {
    qd->name = orig_name; /* LCOV_EXCL_LINE: OutOfMemory */
    return CI_ENOMEM;   /* LCOV_EXCL_LINE: OutOfMemory */
  }

  ci_free(orig_name);
  return CI_SUCCESS;
}

ci_status_t ci_dns_record_query_set_type(ci_dns_record_t  *dnsrec,
                                             size_t              idx,
                                             ci_dns_rec_type_t qtype)
{
  ci_dns_qd_t *qd;

  if (dnsrec == NULL || idx >= ci_array_len(dnsrec->qd) ||
      !ci_dns_rec_type_isvalid(qtype, CI_TRUE)) {
    return CI_EFORMERR;
  }

  qd        = ci_array_at(dnsrec->qd, idx);
  qd->qtype = qtype;

  return CI_SUCCESS;
}

ci_status_t ci_dns_record_query_get(const ci_dns_record_t *dnsrec,
                                        size_t idx, const char **name,
                                        ci_dns_rec_type_t *qtype,
                                        ci_dns_class_t    *qclass)
{
  const ci_dns_qd_t *qd;
  if (dnsrec == NULL || idx >= ci_array_len(dnsrec->qd)) {
    return CI_EFORMERR;
  }

  qd = ci_array_at(dnsrec->qd, idx);
  if (name != NULL) {
    *name = qd->name;
  }

  if (qtype != NULL) {
    *qtype = qd->qtype;
  }

  if (qclass != NULL) {
    *qclass = qd->qclass;
  }

  return CI_SUCCESS;
}

size_t ci_dns_record_rr_cnt(const ci_dns_record_t *dnsrec,
                              ci_dns_section_t       sect)
{
  if (dnsrec == NULL || !ci_dns_section_isvalid(sect)) {
    return 0;
  }

  switch (sect) {
    case CI_SECTION_ANSWER:
      return ci_array_len(dnsrec->an);
    case CI_SECTION_AUTHORITY:
      return ci_array_len(dnsrec->ns);
    case CI_SECTION_ADDITIONAL:
      return ci_array_len(dnsrec->ar);
  }

  return 0; /* LCOV_EXCL_LINE: DefensiveCoding */
}

ci_status_t ci_dns_record_rr_prealloc(ci_dns_record_t *dnsrec,
                                          ci_dns_section_t sect, size_t cnt)
{
  ci_array_t *arr = NULL;

  if (dnsrec == NULL || !ci_dns_section_isvalid(sect)) {
    return CI_EFORMERR;
  }

  switch (sect) {
    case CI_SECTION_ANSWER:
      arr = dnsrec->an;
      break;
    case CI_SECTION_AUTHORITY:
      arr = dnsrec->ns;
      break;
    case CI_SECTION_ADDITIONAL:
      arr = dnsrec->ar;
      break;
  }

  if (cnt < ci_array_len(arr)) {
    return CI_EFORMERR;
  }

  return ci_array_set_size(arr, cnt);
}

ci_status_t ci_dns_record_rr_add(ci_dns_rr_t    **rr_out,
                                     ci_dns_record_t *dnsrec,
                                     ci_dns_section_t sect, const char *name,
                                     ci_dns_rec_type_t type,
                                     ci_dns_class_t rclass, unsigned int ttl)
{
  ci_dns_rr_t *rr  = NULL;
  ci_array_t  *arr = NULL;
  ci_status_t  status;
  size_t         idx;

  if (dnsrec == NULL || name == NULL || rr_out == NULL ||
      !ci_dns_section_isvalid(sect) ||
      !ci_dns_rec_type_isvalid(type, CI_FALSE) ||
      !ci_dns_class_isvalid(rclass, type, CI_FALSE)) {
    return CI_EFORMERR;
  }

  *rr_out = NULL;

  switch (sect) {
    case CI_SECTION_ANSWER:
      arr = dnsrec->an;
      break;
    case CI_SECTION_AUTHORITY:
      arr = dnsrec->ns;
      break;
    case CI_SECTION_ADDITIONAL:
      arr = dnsrec->ar;
      break;
  }

  idx    = ci_array_len(arr);
  status = ci_array_insert_last((void **)&rr, arr);
  if (status != CI_SUCCESS) {
    return status; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  rr->name = ci_strdup(name);
  if (rr->name == NULL) {
    ci_array_remove_at(arr, idx);
    return CI_ENOMEM;
  }

  rr->parent = dnsrec;
  rr->type   = type;
  rr->rclass = rclass;
  rr->ttl    = ttl;

  *rr_out = rr;

  return CI_SUCCESS;
}

ci_status_t ci_dns_record_rr_del(ci_dns_record_t *dnsrec,
                                     ci_dns_section_t sect, size_t idx)
{
  ci_array_t *arr = NULL;

  if (dnsrec == NULL || !ci_dns_section_isvalid(sect)) {
    return CI_EFORMERR;
  }

  switch (sect) {
    case CI_SECTION_ANSWER:
      arr = dnsrec->an;
      break;
    case CI_SECTION_AUTHORITY:
      arr = dnsrec->ns;
      break;
    case CI_SECTION_ADDITIONAL:
      arr = dnsrec->ar;
      break;
  }

  return ci_array_remove_at(arr, idx);
}

ci_dns_rr_t *ci_dns_record_rr_get(ci_dns_record_t *dnsrec,
                                      ci_dns_section_t sect, size_t idx)
{
  ci_array_t *arr = NULL;

  if (dnsrec == NULL || !ci_dns_section_isvalid(sect)) {
    return NULL;
  }

  switch (sect) {
    case CI_SECTION_ANSWER:
      arr = dnsrec->an;
      break;
    case CI_SECTION_AUTHORITY:
      arr = dnsrec->ns;
      break;
    case CI_SECTION_ADDITIONAL:
      arr = dnsrec->ar;
      break;
  }

  return ci_array_at(arr, idx);
}

const ci_dns_rr_t *
  ci_dns_record_rr_get_const(const ci_dns_record_t *dnsrec,
                               ci_dns_section_t sect, size_t idx)
{
  return ci_dns_record_rr_get((void *)((size_t)dnsrec), sect, idx);
}

const char *ci_dns_rr_get_name(const ci_dns_rr_t *rr)
{
  if (rr == NULL) {
    return NULL;
  }
  return rr->name;
}

ci_dns_rec_type_t ci_dns_rr_get_type(const ci_dns_rr_t *rr)
{
  if (rr == NULL) {
    return 0;
  }
  return rr->type;
}

ci_dns_class_t ci_dns_rr_get_class(const ci_dns_rr_t *rr)
{
  if (rr == NULL) {
    return 0;
  }
  return rr->rclass;
}

unsigned int ci_dns_rr_get_ttl(const ci_dns_rr_t *rr)
{
  if (rr == NULL) {
    return 0;
  }
  return rr->ttl;
}

static void *ci_dns_rr_data_ptr(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                                  size_t **lenptr)
{
  if (dns_rr == NULL || dns_rr->type != ci_dns_rr_key_to_rec_type(key)) {
    return NULL; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  switch (key) {
    case CI_RR_A_ADDR:
      return &dns_rr->r.a.addr;

    case CI_RR_NS_NSDNAME:
      return &dns_rr->r.ns.nsdname;

    case CI_RR_CNAME_CNAME:
      return &dns_rr->r.cname.cname;

    case CI_RR_SOA_MNAME:
      return &dns_rr->r.soa.mname;

    case CI_RR_SOA_RNAME:
      return &dns_rr->r.soa.rname;

    case CI_RR_SOA_SERIAL:
      return &dns_rr->r.soa.serial;

    case CI_RR_SOA_REFRESH:
      return &dns_rr->r.soa.refresh;

    case CI_RR_SOA_RETRY:
      return &dns_rr->r.soa.retry;

    case CI_RR_SOA_EXPIRE:
      return &dns_rr->r.soa.expire;

    case CI_RR_SOA_MINIMUM:
      return &dns_rr->r.soa.minimum;

    case CI_RR_PTR_DNAME:
      return &dns_rr->r.ptr.dname;

    case CI_RR_AAAA_ADDR:
      return &dns_rr->r.aaaa.addr;

    case CI_RR_HINFO_CPU:
      return &dns_rr->r.hinfo.cpu;

    case CI_RR_HINFO_OS:
      return &dns_rr->r.hinfo.os;

    case CI_RR_MX_PREFERENCE:
      return &dns_rr->r.mx.preference;

    case CI_RR_MX_EXCHANGE:
      return &dns_rr->r.mx.exchange;

    case CI_RR_SIG_TYPE_COVERED:
      return &dns_rr->r.sig.type_covered;

    case CI_RR_SIG_ALGORITHM:
      return &dns_rr->r.sig.algorithm;

    case CI_RR_SIG_LABELS:
      return &dns_rr->r.sig.labels;

    case CI_RR_SIG_ORIGINAL_TTL:
      return &dns_rr->r.sig.original_ttl;

    case CI_RR_SIG_EXPIRATION:
      return &dns_rr->r.sig.expiration;

    case CI_RR_SIG_INCEPTION:
      return &dns_rr->r.sig.inception;

    case CI_RR_SIG_KEY_TAG:
      return &dns_rr->r.sig.key_tag;

    case CI_RR_SIG_SIGNERS_NAME:
      return &dns_rr->r.sig.signers_name;

    case CI_RR_SIG_SIGNATURE:
      if (lenptr == NULL) {
        return NULL;
      }
      *lenptr = &dns_rr->r.sig.signature_len;
      return &dns_rr->r.sig.signature;

    case CI_RR_TXT_DATA:
      return &dns_rr->r.txt.strs;

    case CI_RR_SRV_PRIORITY:
      return &dns_rr->r.srv.priority;

    case CI_RR_SRV_WEIGHT:
      return &dns_rr->r.srv.weight;

    case CI_RR_SRV_PORT:
      return &dns_rr->r.srv.port;

    case CI_RR_SRV_TARGET:
      return &dns_rr->r.srv.target;

    case CI_RR_NAPTR_ORDER:
      return &dns_rr->r.naptr.order;

    case CI_RR_NAPTR_PREFERENCE:
      return &dns_rr->r.naptr.preference;

    case CI_RR_NAPTR_FLAGS:
      return &dns_rr->r.naptr.flags;

    case CI_RR_NAPTR_SERVICES:
      return &dns_rr->r.naptr.services;

    case CI_RR_NAPTR_REGEXP:
      return &dns_rr->r.naptr.regexp;

    case CI_RR_NAPTR_REPLACEMENT:
      return &dns_rr->r.naptr.replacement;

    case CI_RR_OPT_UDP_SIZE:
      return &dns_rr->r.opt.udp_size;

    case CI_RR_OPT_VERSION:
      return &dns_rr->r.opt.version;

    case CI_RR_OPT_FLAGS:
      return &dns_rr->r.opt.flags;

    case CI_RR_OPT_OPTIONS:
      return &dns_rr->r.opt.options;

    case CI_RR_TLSA_CERT_USAGE:
      return &dns_rr->r.tlsa.cert_usage;

    case CI_RR_TLSA_SELECTOR:
      return &dns_rr->r.tlsa.selector;

    case CI_RR_TLSA_MATCH:
      return &dns_rr->r.tlsa.match;

    case CI_RR_TLSA_DATA:
      if (lenptr == NULL) {
        return NULL;
      }
      *lenptr = &dns_rr->r.tlsa.data_len;
      return &dns_rr->r.tlsa.data;

    case CI_RR_SVCB_PRIORITY:
      return &dns_rr->r.svcb.priority;

    case CI_RR_SVCB_TARGET:
      return &dns_rr->r.svcb.target;

    case CI_RR_SVCB_PARAMS:
      return &dns_rr->r.svcb.params;

    case CI_RR_HTTPS_PRIORITY:
      return &dns_rr->r.https.priority;

    case CI_RR_HTTPS_TARGET:
      return &dns_rr->r.https.target;

    case CI_RR_HTTPS_PARAMS:
      return &dns_rr->r.https.params;

    case CI_RR_URI_PRIORITY:
      return &dns_rr->r.uri.priority;

    case CI_RR_URI_WEIGHT:
      return &dns_rr->r.uri.weight;

    case CI_RR_URI_TARGET:
      return &dns_rr->r.uri.target;

    case CI_RR_CAA_CRITICAL:
      return &dns_rr->r.caa.critical;

    case CI_RR_CAA_TAG:
      return &dns_rr->r.caa.tag;

    case CI_RR_CAA_VALUE:
      if (lenptr == NULL) {
        return NULL;
      }
      *lenptr = &dns_rr->r.caa.value_len;
      return &dns_rr->r.caa.value;

    case CI_RR_RAW_RR_TYPE:
      return &dns_rr->r.raw_rr.type;

    case CI_RR_RAW_RR_DATA:
      if (lenptr == NULL) {
        return NULL;
      }
      *lenptr = &dns_rr->r.raw_rr.length;
      return &dns_rr->r.raw_rr.data;
  }

  return NULL;
}

static const void *ci_dns_rr_data_ptr_const(const ci_dns_rr_t *dns_rr,
                                              ci_dns_rr_key_t    key,
                                              const size_t       **lenptr)
{
  /* We're going to cast off the const */
  return ci_dns_rr_data_ptr((void *)((size_t)dns_rr), key,
                              (void *)((size_t)lenptr));
}

const struct in_addr *ci_dns_rr_get_addr(const ci_dns_rr_t *dns_rr,
                                           ci_dns_rr_key_t    key)
{
  const struct in_addr *addr;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_INADDR) {
    return NULL;
  }

  addr = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (addr == NULL) {
    return NULL;
  }

  return addr;
}

const struct ci_in6_addr *ci_dns_rr_get_addr6(const ci_dns_rr_t *dns_rr,
                                                  ci_dns_rr_key_t    key)
{
  const struct ci_in6_addr *addr;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_INADDR6) {
    return NULL;
  }

  addr = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (addr == NULL) {
    return NULL;
  }

  return addr;
}

unsigned char ci_dns_rr_get_u8(const ci_dns_rr_t *dns_rr,
                                 ci_dns_rr_key_t    key)
{
  const unsigned char *u8;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_U8) {
    return 0;
  }

  u8 = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (u8 == NULL) {
    return 0;
  }

  return *u8;
}

unsigned short ci_dns_rr_get_u16(const ci_dns_rr_t *dns_rr,
                                   ci_dns_rr_key_t    key)
{
  const unsigned short *u16;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_U16) {
    return 0;
  }

  u16 = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (u16 == NULL) {
    return 0;
  }

  return *u16;
}

unsigned int ci_dns_rr_get_u32(const ci_dns_rr_t *dns_rr,
                                 ci_dns_rr_key_t    key)
{
  const unsigned int *u32;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_U32) {
    return 0;
  }

  u32 = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (u32 == NULL) {
    return 0;
  }

  return *u32;
}

const unsigned char *ci_dns_rr_get_bin(const ci_dns_rr_t *dns_rr,
                                         ci_dns_rr_key_t key, size_t *len)
{
  unsigned char * const *bin     = NULL;
  size_t const          *bin_len = NULL;

  if ((ci_dns_rr_key_datatype(key) != CI_DATATYPE_BIN &&
       ci_dns_rr_key_datatype(key) != CI_DATATYPE_BINP &&
       ci_dns_rr_key_datatype(key) != CI_DATATYPE_ABINP) ||
      len == NULL) {
    return NULL;
  }

  /* Array of strings, return concatenated version */
  if (ci_dns_rr_key_datatype(key) == CI_DATATYPE_ABINP) {
    ci_dns_multistring_t * const *strs =
      ci_dns_rr_data_ptr_const(dns_rr, key, NULL);

    if (strs == NULL) {
      return NULL;
    }

    return ci_dns_multistring_combined(*strs, len);
  }

  /* Not a multi-string, just straight binary data */
  bin = ci_dns_rr_data_ptr_const(dns_rr, key, &bin_len);
  if (bin == NULL) {
    return NULL;
  }

  /* Shouldn't be possible */
  if (bin_len == NULL) {
    return NULL;
  }
  *len = *bin_len;

  return *bin;
}

size_t ci_dns_rr_get_abin_cnt(const ci_dns_rr_t *dns_rr,
                                ci_dns_rr_key_t    key)
{
  ci_dns_multistring_t * const *strs;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_ABINP) {
    return 0;
  }

  strs = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (strs == NULL) {
    return 0;
  }

  return ci_dns_multistring_cnt(*strs);
}

const unsigned char *ci_dns_rr_get_abin(const ci_dns_rr_t *dns_rr,
                                          ci_dns_rr_key_t key, size_t idx,
                                          size_t *len)
{
  ci_dns_multistring_t * const *strs;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_ABINP) {
    return NULL;
  }

  strs = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (strs == NULL) {
    return NULL;
  }

  return ci_dns_multistring_get(*strs, idx, len);
}

ci_status_t ci_dns_rr_del_abin(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                                   size_t idx)
{
  ci_dns_multistring_t **strs;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_ABINP) {
    return CI_EFORMERR;
  }

  strs = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (strs == NULL) {
    return CI_EFORMERR;
  }

  return ci_dns_multistring_del(*strs, idx);
}

ci_status_t ci_dns_rr_add_abin(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                                   const unsigned char *val, size_t len)
{
  ci_status_t       status;
  ci_dns_datatype_t datatype = ci_dns_rr_key_datatype(key);
  ci_bool_t         is_nullterm =
    (datatype == CI_DATATYPE_ABINP) ? CI_TRUE : CI_FALSE;
  size_t                   alloclen = is_nullterm ? len + 1 : len;
  unsigned char           *temp;
  ci_dns_multistring_t **strs;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_ABINP) {
    return CI_EFORMERR;
  }

  strs = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (strs == NULL) {
    return CI_EFORMERR;
  }

  if (*strs == NULL) {
    *strs = ci_dns_multistring_create();
    if (*strs == NULL) {
      return CI_ENOMEM;
    }
  }

  temp = ci_malloc(alloclen);
  if (temp == NULL) {
    return CI_ENOMEM;
  }

  memcpy(temp, val, len);

  /* NULL-term ABINP */
  if (is_nullterm) {
    temp[len] = 0;
  }

  status = ci_dns_multistring_add_own(*strs, temp, len);
  if (status != CI_SUCCESS) {
    ci_free(temp);
  }

  return status;
}

const char *ci_dns_rr_get_str(const ci_dns_rr_t *dns_rr,
                                ci_dns_rr_key_t    key)
{
  char * const *str;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_STR &&
      ci_dns_rr_key_datatype(key) != CI_DATATYPE_NAME) {
    return NULL;
  }

  str = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (str == NULL) {
    return NULL;
  }

  return *str;
}

size_t ci_dns_rr_get_opt_cnt(const ci_dns_rr_t *dns_rr,
                               ci_dns_rr_key_t    key)
{
  ci_array_t * const *opts;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_OPT) {
    return 0;
  }

  opts = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (opts == NULL || *opts == NULL) {
    return 0;
  }

  return ci_array_len(*opts);
}

unsigned short ci_dns_rr_get_opt(const ci_dns_rr_t *dns_rr,
                                   ci_dns_rr_key_t key, size_t idx,
                                   const unsigned char **val, size_t *val_len)
{
  ci_array_t * const    *opts;
  const ci_dns_optval_t *opt;

  if (val) {
    *val = NULL;
  }
  if (val_len) {
    *val_len = 0;
  }

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_OPT) {
    return 65535;
  }

  opts = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (opts == NULL || *opts == NULL) {
    return 65535;
  }

  opt = ci_array_at(*opts, idx);
  if (opt == NULL) {
    return 65535;
  }

  if (val) {
    *val = opt->val;
  }
  if (val_len) {
    *val_len = opt->val_len;
  }

  return opt->opt;
}

ci_bool_t ci_dns_rr_get_opt_byid(const ci_dns_rr_t *dns_rr,
                                     ci_dns_rr_key_t key, unsigned short opt,
                                     const unsigned char **val, size_t *val_len)
{
  ci_array_t * const    *opts;
  size_t                   i;
  size_t                   cnt;
  const ci_dns_optval_t *optptr = NULL;

  if (val) {
    *val = NULL;
  }
  if (val_len) {
    *val_len = 0;
  }

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_OPT) {
    return CI_FALSE;
  }

  opts = ci_dns_rr_data_ptr_const(dns_rr, key, NULL);
  if (opts == NULL || *opts == NULL) {
    return CI_FALSE;
  }

  cnt = ci_array_len(*opts);
  for (i = 0; i < cnt; i++) {
    optptr = ci_array_at(*opts, i);
    if (optptr == NULL) {
      return CI_FALSE;
    }
    if (optptr->opt == opt) {
      break;
    }
  }

  if (i >= cnt || optptr == NULL) {
    return CI_FALSE;
  }

  if (val) {
    *val = optptr->val;
  }
  if (val_len) {
    *val_len = optptr->val_len;
  }
  return CI_TRUE;
}

ci_status_t ci_dns_rr_set_addr(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                                   const struct in_addr *addr)
{
  struct in_addr *a;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_INADDR || addr == NULL) {
    return CI_EFORMERR;
  }

  a = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (a == NULL) {
    return CI_EFORMERR;
  }

  memcpy(a, addr, sizeof(*a));
  return CI_SUCCESS;
}

ci_status_t ci_dns_rr_set_addr6(ci_dns_rr_t              *dns_rr,
                                    ci_dns_rr_key_t           key,
                                    const struct ci_in6_addr *addr)
{
  struct ci_in6_addr *a;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_INADDR6 || addr == NULL) {
    return CI_EFORMERR;
  }

  a = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (a == NULL) {
    return CI_EFORMERR;
  }

  memcpy(a, addr, sizeof(*a));
  return CI_SUCCESS;
}

ci_status_t ci_dns_rr_set_u8(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                                 unsigned char val)
{
  unsigned char *u8;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_U8) {
    return CI_EFORMERR;
  }

  u8 = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (u8 == NULL) {
    return CI_EFORMERR;
  }

  *u8 = val;
  return CI_SUCCESS;
}

ci_status_t ci_dns_rr_set_u16(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                                  unsigned short val)
{
  unsigned short *u16;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_U16) {
    return CI_EFORMERR;
  }

  u16 = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (u16 == NULL) {
    return CI_EFORMERR;
  }

  *u16 = val;
  return CI_SUCCESS;
}

ci_status_t ci_dns_rr_set_u32(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                                  unsigned int val)
{
  unsigned int *u32;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_U32) {
    return CI_EFORMERR;
  }

  u32 = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (u32 == NULL) {
    return CI_EFORMERR;
  }

  *u32 = val;
  return CI_SUCCESS;
}

ci_status_t ci_dns_rr_set_bin_own(ci_dns_rr_t    *dns_rr,
                                      ci_dns_rr_key_t key, unsigned char *val,
                                      size_t len)
{
  unsigned char **bin;
  size_t         *bin_len = NULL;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_BIN &&
      ci_dns_rr_key_datatype(key) != CI_DATATYPE_BINP &&
      ci_dns_rr_key_datatype(key) != CI_DATATYPE_ABINP) {
    return CI_EFORMERR;
  }

  if (ci_dns_rr_key_datatype(key) == CI_DATATYPE_ABINP) {
    ci_dns_multistring_t **strs = ci_dns_rr_data_ptr(dns_rr, key, NULL);
    if (strs == NULL) {
      return CI_EFORMERR;
    }

    if (*strs == NULL) {
      *strs = ci_dns_multistring_create();
      if (*strs == NULL) {
        return CI_ENOMEM;
      }
    }

    /* Clear all existing entries as this is an override */
    ci_dns_multistring_clear(*strs);

    return ci_dns_multistring_add_own(*strs, val, len);
  }

  bin = ci_dns_rr_data_ptr(dns_rr, key, &bin_len);
  if (bin == NULL || bin_len == NULL) {
    return CI_EFORMERR;
  }

  if (*bin) {
    ci_free(*bin);
  }
  *bin     = val;
  *bin_len = len;

  return CI_SUCCESS;
}

ci_status_t ci_dns_rr_set_bin(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                                  const unsigned char *val, size_t len)
{
  ci_status_t       status;
  ci_dns_datatype_t datatype = ci_dns_rr_key_datatype(key);
  ci_bool_t         is_nullterm =
    (datatype == CI_DATATYPE_BINP || datatype == CI_DATATYPE_ABINP)
              ? CI_TRUE
              : CI_FALSE;
  size_t         alloclen = is_nullterm ? len + 1 : len;
  unsigned char *temp     = ci_malloc(alloclen);

  if (temp == NULL) {
    return CI_ENOMEM;
  }

  memcpy(temp, val, len);

  /* NULL-term BINP */
  if (is_nullterm) {
    temp[len] = 0;
  }

  status = ci_dns_rr_set_bin_own(dns_rr, key, temp, len);
  if (status != CI_SUCCESS) {
    ci_free(temp);
  }

  return status;
}

ci_status_t ci_dns_rr_set_str_own(ci_dns_rr_t    *dns_rr,
                                      ci_dns_rr_key_t key, char *val)
{
  char **str;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_STR &&
      ci_dns_rr_key_datatype(key) != CI_DATATYPE_NAME) {
    return CI_EFORMERR;
  }

  str = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (str == NULL) {
    return CI_EFORMERR;
  }

  if (*str) {
    ci_free(*str);
  }
  *str = val;

  return CI_SUCCESS;
}

ci_status_t ci_dns_rr_set_str(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                                  const char *val)
{
  ci_status_t status;
  char         *temp = NULL;

  if (val != NULL) {
    temp = ci_strdup(val);
    if (temp == NULL) {
      return CI_ENOMEM;
    }
  }

  status = ci_dns_rr_set_str_own(dns_rr, key, temp);
  if (status != CI_SUCCESS) {
    ci_free(temp);
  }

  return status;
}

ci_status_t ci_dns_rr_set_abin_own(ci_dns_rr_t          *dns_rr,
                                       ci_dns_rr_key_t       key,
                                       ci_dns_multistring_t *strs)
{
  ci_dns_multistring_t **strs_ptr;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_ABINP) {
    return CI_EFORMERR;
  }

  strs_ptr = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (strs_ptr == NULL) {
    return CI_EFORMERR;
  }

  if (*strs_ptr != NULL) {
    ci_dns_multistring_destroy(*strs_ptr);
  }
  *strs_ptr = strs;

  return CI_SUCCESS;
}

static void ci_dns_opt_free_cb(void *arg)
{
  ci_dns_optval_t *opt = arg;
  if (opt == NULL) {
    return;
  }
  ci_free(opt->val);
}

ci_status_t ci_dns_rr_set_opt_own(ci_dns_rr_t    *dns_rr,
                                      ci_dns_rr_key_t key, unsigned short opt,
                                      unsigned char *val, size_t val_len)
{
  ci_array_t     **options;
  ci_dns_optval_t *optptr = NULL;
  size_t             idx;
  size_t             cnt;
  ci_status_t      status;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_OPT) {
    return CI_EFORMERR;
  }

  options = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (options == NULL) {
    return CI_EFORMERR;
  }

  if (*options == NULL) {
    *options =
      ci_array_create(sizeof(ci_dns_optval_t), ci_dns_opt_free_cb);
  }
  if (*options == NULL) {
    return CI_ENOMEM;
  }

  cnt = ci_array_len(*options);
  for (idx = 0; idx < cnt; idx++) {
    optptr = ci_array_at(*options, idx);
    if (optptr == NULL) {
      return CI_EFORMERR;
    }
    if (optptr->opt == opt) {
      break;
    }
  }

  /* Duplicate entry, replace */
  if (idx != cnt && optptr != NULL) {
    goto done;
  }

  status = ci_array_insert_last((void **)&optptr, *options);
  if (status != CI_SUCCESS) {
    return status;
  }

done:
  ci_free(optptr->val);
  optptr->opt     = opt;
  optptr->val     = val;
  optptr->val_len = val_len;

  return CI_SUCCESS;
}

ci_status_t ci_dns_rr_set_opt(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                                  unsigned short opt, const unsigned char *val,
                                  size_t val_len)
{
  unsigned char *temp = NULL;
  ci_status_t  status;

  if (val != NULL) {
    temp = ci_malloc(val_len + 1);
    if (temp == NULL) {
      return CI_ENOMEM;
    }
    memcpy(temp, val, val_len);
    temp[val_len] = 0;
  }

  status = ci_dns_rr_set_opt_own(dns_rr, key, opt, temp, val_len);
  if (status != CI_SUCCESS) {
    ci_free(temp);
  }

  return status;
}

ci_status_t ci_dns_rr_del_opt_byid(ci_dns_rr_t    *dns_rr,
                                       ci_dns_rr_key_t key,
                                       unsigned short    opt)
{
  ci_array_t           **options;
  const ci_dns_optval_t *optptr;
  size_t                   idx;
  size_t                   cnt;

  if (ci_dns_rr_key_datatype(key) != CI_DATATYPE_OPT) {
    return CI_EFORMERR;
  }

  options = ci_dns_rr_data_ptr(dns_rr, key, NULL);
  if (options == NULL) {
    return CI_EFORMERR;
  }

  /* No options */
  if (*options == NULL) {
    return CI_SUCCESS;
  }

  cnt = ci_array_len(*options);
  for (idx = 0; idx < cnt; idx++) {
    optptr = ci_array_at_const(*options, idx);
    if (optptr == NULL) {
      return CI_ENOTFOUND;
    }
    if (optptr->opt == opt) {
      return ci_array_remove_at(*options, idx);
    }
  }

  return CI_ENOTFOUND;
}

char *ci_dns_addr_to_ptr(const struct ci_addr *addr)
{
  ci_buf_t                *buf     = NULL;
  const unsigned char       *ptr     = NULL;
  size_t                     ptr_len = 0;
  size_t                     i;
  ci_status_t              status;
  static const unsigned char hexbytes[] = "0123456789abcdef";

  if (addr->family != AF_INET && addr->family != AF_INET6) {
    goto fail;
  }

  buf = ci_buf_create();
  if (buf == NULL) {
    goto fail;
  }

  if (addr->family == AF_INET) {
    ptr     = (const unsigned char *)&addr->addr.addr4;
    ptr_len = 4;
  } else {
    ptr     = (const unsigned char *)&addr->addr.addr6;
    ptr_len = 16;
  }

  for (i = ptr_len; i > 0; i--) {
    if (addr->family == AF_INET) {
      status = ci_buf_append_num_dec(buf, (size_t)ptr[i - 1], 0);
    } else {
      unsigned char c;

      c      = ptr[i - 1] & 0xF;
      status = ci_buf_append_byte(buf, hexbytes[c]);
      if (status != CI_SUCCESS) {
        goto fail;
      }

      status = ci_buf_append_byte(buf, '.');
      if (status != CI_SUCCESS) {
        goto fail;
      }

      c      = (ptr[i - 1] >> 4) & 0xF;
      status = ci_buf_append_byte(buf, hexbytes[c]);
    }
    if (status != CI_SUCCESS) {
      goto fail;
    }

    status = ci_buf_append_byte(buf, '.');
    if (status != CI_SUCCESS) {
      goto fail;
    }
  }

  if (addr->family == AF_INET) {
    status = ci_buf_append(buf, (const unsigned char *)"in-addr.arpa", 12);
  } else {
    status = ci_buf_append(buf, (const unsigned char *)"ip6.arpa", 8);
  }
  if (status != CI_SUCCESS) {
    goto fail;
  }

  return ci_buf_finish_str(buf, NULL);

fail:
  ci_buf_destroy(buf);
  return NULL;
}

ci_dns_rr_t *ci_dns_get_opt_rr(ci_dns_record_t *rec)
{
  size_t i;
  for (i = 0; i < ci_dns_record_rr_cnt(rec, CI_SECTION_ADDITIONAL); i++) {
    ci_dns_rr_t *rr = ci_dns_record_rr_get(rec, CI_SECTION_ADDITIONAL, i);

    if (ci_dns_rr_get_type(rr) == CI_REC_TYPE_OPT) {
      return rr;
    }
  }
  return NULL;
}

const ci_dns_rr_t *ci_dns_get_opt_rr_const(const ci_dns_record_t *rec)
{
  size_t i;
  for (i = 0; i < ci_dns_record_rr_cnt(rec, CI_SECTION_ADDITIONAL); i++) {
    const ci_dns_rr_t *rr =
      ci_dns_record_rr_get_const(rec, CI_SECTION_ADDITIONAL, i);

    if (ci_dns_rr_get_type(rr) == CI_REC_TYPE_OPT) {
      return rr;
    }
  }
  return NULL;
}

/* Construct a DNS record for a name with given class and type. Used internally
 * by ci_search() and ci_create_query().
 */
ci_status_t
  ci_dns_record_create_query(ci_dns_record_t **dnsrec, const char *name,
                               ci_dns_class_t    dnsclass,
                               ci_dns_rec_type_t type, unsigned short id,
                               ci_dns_flags_t flags, size_t max_udp_size)
{
  ci_status_t  status;
  ci_dns_rr_t *rr = NULL;

  if (dnsrec == NULL) {
    return CI_EFORMERR;
  }

  *dnsrec = NULL;

  /* Per RFC 7686, reject queries for ".onion" domain names with NXDOMAIN */
  if (ci_is_onion_domain(name)) {
    status = CI_ENOTFOUND;
    goto done;
  }

  status = ci_dns_record_create(dnsrec, id, (unsigned short)flags,
                                  CI_OPCODE_QUERY, CI_RCODE_NOERROR);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_dns_record_query_add(*dnsrec, name, type, dnsclass);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* max_udp_size > 0 indicates EDNS, so send OPT RR as an additional record */
  if (max_udp_size > 0) {
    /* max_udp_size must fit into a 16 bit unsigned integer field on the OPT
     * RR, so check here that it fits
     */
    if (max_udp_size > 65535) {
      status = CI_EFORMERR;
      goto done;
    }

    status = ci_dns_record_rr_add(&rr, *dnsrec, CI_SECTION_ADDITIONAL, "",
                                    CI_REC_TYPE_OPT, CI_CLASS_IN, 0);
    if (status != CI_SUCCESS) {
      goto done;
    }

    status = ci_dns_rr_set_u16(rr, CI_RR_OPT_UDP_SIZE,
                                 (unsigned short)max_udp_size);
    if (status != CI_SUCCESS) {
      goto done;
    }

    status = ci_dns_rr_set_u8(rr, CI_RR_OPT_VERSION, 0);
    if (status != CI_SUCCESS) {
      goto done;
    }

    status = ci_dns_rr_set_u16(rr, CI_RR_OPT_FLAGS, 0);
    if (status != CI_SUCCESS) {
      goto done;
    }
  }

done:
  if (status != CI_SUCCESS) {
    ci_dns_record_destroy(*dnsrec);
    *dnsrec = NULL;
  }
  return status;
}

ci_status_t ci_dns_record_duplicate_ex(ci_dns_record_t      **dest,
                                           const ci_dns_record_t *src)
{
  unsigned char *data     = NULL;
  size_t         data_len = 0;
  ci_status_t  status;

  if (dest == NULL || src == NULL) {
    return CI_EFORMERR;
  }

  *dest = NULL;

  status = ci_dns_write(src, &data, &data_len);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_dns_parse(data, data_len, 0, dest);
  ci_free(data);

  return status;
}

ci_dns_record_t *ci_dns_record_duplicate(const ci_dns_record_t *dnsrec)
{
  ci_dns_record_t *dest = NULL;

  ci_dns_record_duplicate_ex(&dest, dnsrec);
  return dest;
}
