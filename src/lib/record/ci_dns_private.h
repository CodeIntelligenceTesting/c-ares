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
#ifndef __CI_DNS_PRIVATE_H
#define __CI_DNS_PRIVATE_H

ci_status_t        ci_dns_record_duplicate_ex(ci_dns_record_t      **dest,
                                                  const ci_dns_record_t *src);
ci_bool_t          ci_dns_rec_allow_name_comp(ci_dns_rec_type_t type);
ci_bool_t          ci_dns_opcode_isvalid(ci_dns_opcode_t opcode);
ci_bool_t          ci_dns_rcode_isvalid(ci_dns_rcode_t rcode);
ci_bool_t          ci_dns_flags_arevalid(unsigned short flags);
ci_bool_t          ci_dns_rec_type_isvalid(ci_dns_rec_type_t type,
                                               ci_bool_t         is_query);
ci_bool_t          ci_dns_class_isvalid(ci_dns_class_t    qclass,
                                            ci_dns_rec_type_t type,
                                            ci_bool_t         is_query);
ci_bool_t          ci_dns_section_isvalid(ci_dns_section_t sect);
ci_status_t        ci_dns_rr_set_str_own(ci_dns_rr_t    *dns_rr,
                                             ci_dns_rr_key_t key, char *val);
ci_status_t        ci_dns_rr_set_bin_own(ci_dns_rr_t    *dns_rr,
                                             ci_dns_rr_key_t key, unsigned char *val,
                                             size_t len);
ci_status_t        ci_dns_rr_set_abin_own(ci_dns_rr_t          *dns_rr,
                                              ci_dns_rr_key_t       key,
                                              ci_dns_multistring_t *strs);
ci_status_t        ci_dns_rr_set_opt_own(ci_dns_rr_t    *dns_rr,
                                             ci_dns_rr_key_t key, unsigned short opt,
                                             unsigned char *val, size_t val_len);
ci_status_t        ci_dns_record_rr_prealloc(ci_dns_record_t *dnsrec,
                                                 ci_dns_section_t sect, size_t cnt);
ci_dns_rr_t       *ci_dns_get_opt_rr(ci_dns_record_t *rec);
const ci_dns_rr_t *ci_dns_get_opt_rr_const(const ci_dns_record_t *rec);
void                 ci_dns_record_ttl_decrement(ci_dns_record_t *dnsrec,
                                                   unsigned int       ttl_decrement);

/* Same as ci_dns_write() but appends to an existing buffer object */
ci_status_t        ci_dns_write_buf(const ci_dns_record_t *dnsrec,
                                        ci_buf_t              *buf);

/* Same as ci_dns_write_buf(), but prepends a 16bit length */
ci_status_t        ci_dns_write_buf_tcp(const ci_dns_record_t *dnsrec,
                                            ci_buf_t              *buf);

/*! Create a DNS record object for a query. The arguments are the same as
 *  those for ci_create_query().
 *
 *  \param[out] dnsrec       DNS record object to create.
 *  \param[in]  name         NUL-terminated name for the query.
 *  \param[in]  dnsclass     Class for the query.
 *  \param[in]  type         Type for the query.
 *  \param[in]  id           Identifier for the query.
 *  \param[in]  flags        Flags for the query.
 *  \param[in]  max_udp_size Maximum size of a UDP packet for EDNS.
 *  \return CI_SUCCESS on success, otherwise an error code.
 */
ci_status_t
  ci_dns_record_create_query(ci_dns_record_t **dnsrec, const char *name,
                               ci_dns_class_t    dnsclass,
                               ci_dns_rec_type_t type, unsigned short id,
                               ci_dns_flags_t flags, size_t max_udp_size);

/*! Convert the RCODE and ANCOUNT from a DNS query reply into a status code.
 *
 *  \param[in] rcode   The RCODE from the reply.
 *  \param[in] ancount The ANCOUNT from the reply.
 *  \return An appropriate status code.
 */
ci_status_t ci_dns_query_reply_tostatus(ci_dns_rcode_t rcode,
                                            size_t           ancount);

struct ci_dns_qd {
  char               *name;
  ci_dns_rec_type_t qtype;
  ci_dns_class_t    qclass;
};

typedef struct {
  struct in_addr addr;
} ci_dns_a_t;

typedef struct {
  char *nsdname;
} ci_dns_ns_t;

typedef struct {
  char *cname;
} ci_dns_cname_t;

typedef struct {
  char        *mname;
  char        *rname;
  unsigned int serial;
  unsigned int refresh;
  unsigned int retry;
  unsigned int expire;
  unsigned int minimum;
} ci_dns_soa_t;

typedef struct {
  char *dname;
} ci_dns_ptr_t;

typedef struct {
  char *cpu;
  char *os;
} ci_dns_hinfo_t;

typedef struct {
  unsigned short preference;
  char          *exchange;
} ci_dns_mx_t;

typedef struct {
  ci_dns_multistring_t *strs;
} ci_dns_txt_t;

typedef struct {
  unsigned short type_covered;
  unsigned char  algorithm;
  unsigned char  labels;
  unsigned int   original_ttl;
  unsigned int   expiration;
  unsigned int   inception;
  unsigned short key_tag;
  char          *signers_name;
  unsigned char *signature;
  size_t         signature_len;
} ci_dns_sig_t;

typedef struct {
  struct ci_in6_addr addr;
} ci_dns_aaaa_t;

typedef struct {
  unsigned short priority;
  unsigned short weight;
  unsigned short port;
  char          *target;
} ci_dns_srv_t;

typedef struct {
  unsigned short order;
  unsigned short preference;
  char          *flags;
  char          *services;
  char          *regexp;
  char          *replacement;
} ci_dns_naptr_t;

typedef struct {
  unsigned short opt;
  unsigned char *val;
  size_t         val_len;
} ci_dns_optval_t;

typedef struct {
  unsigned short udp_size; /*!< taken from class */
  unsigned char  version;  /*!< taken from bits 8-16 of ttl */
  unsigned short flags;    /*!< Flags, remaining 16 bits, though only
                            *   1 currently defined */
  ci_array_t  *options;  /*!< Type is ci_dns_optval_t */
} ci_dns_opt_t;

typedef struct {
  unsigned char  cert_usage;
  unsigned char  selector;
  unsigned char  match;
  unsigned char *data;
  size_t         data_len;
} ci_dns_tlsa_t;

typedef struct {
  unsigned short priority;
  char          *target;
  ci_array_t  *params; /*!< Type is ci_dns_optval_t */
} ci_dns_svcb_t;

typedef struct {
  unsigned short priority;
  unsigned short weight;
  char          *target;
} ci_dns_uri_t;

typedef struct {
  unsigned char  critical;
  char          *tag;
  unsigned char *value;
  size_t         value_len;
} ci_dns_caa_t;

/*! Raw, unparsed RR data */
typedef struct {
  unsigned short type;   /*!< Not ci_rec_type_t because it likely isn't one
                          *   of those values since it wasn't parsed */
  unsigned char *data;   /*!< Raw RR data */
  size_t         length; /*!< Length of raw RR data */
} ci_dns_raw_rr_t;

/*! DNS RR data structure */
struct ci_dns_rr {
  ci_dns_record_t  *parent;
  char               *name;
  ci_dns_rec_type_t type;
  ci_dns_class_t    rclass;
  unsigned int        ttl;

  union {
    ci_dns_a_t      a;
    ci_dns_ns_t     ns;
    ci_dns_cname_t  cname;
    ci_dns_soa_t    soa;
    ci_dns_ptr_t    ptr;
    ci_dns_hinfo_t  hinfo;
    ci_dns_mx_t     mx;
    ci_dns_txt_t    txt;
    ci_dns_sig_t    sig;
    ci_dns_aaaa_t   aaaa;
    ci_dns_srv_t    srv;
    ci_dns_naptr_t  naptr;
    ci_dns_opt_t    opt;
    ci_dns_tlsa_t   tlsa;
    ci_dns_svcb_t   svcb;
    ci_dns_svcb_t   https; /*!< https is a type of svcb, so this is right */
    ci_dns_uri_t    uri;
    ci_dns_caa_t    caa;
    ci_dns_raw_rr_t raw_rr;
  } r;
};

/*! DNS data structure */
struct ci_dns_record {
  unsigned short    id;            /*!< DNS query id */
  unsigned short    flags;         /*!< One or more ci_dns_flags_t */
  ci_dns_opcode_t opcode;        /*!< DNS Opcode */
  ci_dns_rcode_t  rcode;         /*!< DNS RCODE */
  unsigned short    raw_rcode;     /*!< Raw rcode, used to ultimately form real
                                    *   rcode after reading OPT record if it
                                    *   exists */
  unsigned int      ttl_decrement; /*!< Special case to apply to writing out
                                    *   this record, where it will decrement
                                    *   the ttl of any resource records by
                                    *   this amount.  Used for cache */

  ci_array_t     *qd;            /*!< Type is ci_dns_qd_t */
  ci_array_t     *an;            /*!< Type is ci_dns_rr_t */
  ci_array_t     *ns;            /*!< Type is ci_dns_rr_t */
  ci_array_t     *ar;            /*!< Type is ci_dns_rr_t */
};

#endif
