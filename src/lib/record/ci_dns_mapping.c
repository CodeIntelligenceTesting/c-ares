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

ci_bool_t ci_dns_opcode_isvalid(ci_dns_opcode_t opcode)
{
  switch (opcode) {
    case CI_OPCODE_QUERY:
    case CI_OPCODE_IQUERY:
    case CI_OPCODE_STATUS:
    case CI_OPCODE_NOTIFY:
    case CI_OPCODE_UPDATE:
      return CI_TRUE;
  }
  return CI_FALSE;
}

ci_bool_t ci_dns_rcode_isvalid(ci_dns_rcode_t rcode)
{
  switch (rcode) {
    case CI_RCODE_NOERROR:
    case CI_RCODE_FORMERR:
    case CI_RCODE_SERVFAIL:
    case CI_RCODE_NXDOMAIN:
    case CI_RCODE_NOTIMP:
    case CI_RCODE_REFUSED:
    case CI_RCODE_YXDOMAIN:
    case CI_RCODE_YXRRSET:
    case CI_RCODE_NXRRSET:
    case CI_RCODE_NOTAUTH:
    case CI_RCODE_NOTZONE:
    case CI_RCODE_DSOTYPEI:
    case CI_RCODE_BADSIG:
    case CI_RCODE_BADKEY:
    case CI_RCODE_BADTIME:
    case CI_RCODE_BADMODE:
    case CI_RCODE_BADNAME:
    case CI_RCODE_BADALG:
    case CI_RCODE_BADTRUNC:
    case CI_RCODE_BADCOOKIE:
      return CI_TRUE;
  }
  return CI_FALSE;
}

ci_bool_t ci_dns_flags_arevalid(unsigned short flags)
{
  unsigned short allflags = CI_FLAG_QR | CI_FLAG_AA | CI_FLAG_TC |
                            CI_FLAG_RD | CI_FLAG_RA | CI_FLAG_AD |
                            CI_FLAG_CD;

  if (flags & ~allflags) {
    return CI_FALSE;
  }

  return CI_TRUE;
}

ci_bool_t ci_dns_rec_type_isvalid(ci_dns_rec_type_t type,
                                      ci_bool_t         is_query)
{
  switch (type) {
    case CI_REC_TYPE_A:
    case CI_REC_TYPE_NS:
    case CI_REC_TYPE_CNAME:
    case CI_REC_TYPE_SOA:
    case CI_REC_TYPE_PTR:
    case CI_REC_TYPE_HINFO:
    case CI_REC_TYPE_MX:
    case CI_REC_TYPE_TXT:
    case CI_REC_TYPE_SIG:
    case CI_REC_TYPE_AAAA:
    case CI_REC_TYPE_SRV:
    case CI_REC_TYPE_NAPTR:
    case CI_REC_TYPE_OPT:
    case CI_REC_TYPE_TLSA:
    case CI_REC_TYPE_SVCB:
    case CI_REC_TYPE_HTTPS:
    case CI_REC_TYPE_ANY:
    case CI_REC_TYPE_URI:
    case CI_REC_TYPE_CAA:
      return CI_TRUE;
    case CI_REC_TYPE_RAW_RR:
      return is_query ? CI_FALSE : CI_TRUE;
    default:
      break;
  }
  return is_query ? CI_TRUE : CI_FALSE;
}

ci_bool_t ci_dns_rec_allow_name_comp(ci_dns_rec_type_t type)
{
  /* Only record types defined in RFC1035 allow name compression within the
   * RDATA.  Otherwise nameservers that don't understand an RR may not be
   * able to pass along the RR in a proper manner */
  switch (type) {
    case CI_REC_TYPE_A:
    case CI_REC_TYPE_NS:
    case CI_REC_TYPE_CNAME:
    case CI_REC_TYPE_SOA:
    case CI_REC_TYPE_PTR:
    case CI_REC_TYPE_HINFO:
    case CI_REC_TYPE_MX:
    case CI_REC_TYPE_TXT:
      return CI_TRUE;
    default:
      break;
  }
  return CI_FALSE;
}

ci_bool_t ci_dns_class_isvalid(ci_dns_class_t    qclass,
                                   ci_dns_rec_type_t type,
                                   ci_bool_t         is_query)
{
  /* If we don't understand the record type, we shouldn't validate the class
   * as there are some instances like on RFC 2391 (SIG RR) the class is
   * meaningless, but since we didn't support that record type, we didn't
   * know it shouldn't be validated */
  if (type == CI_REC_TYPE_RAW_RR) {
    return CI_TRUE;
  }

  switch (qclass) {
    case CI_CLASS_IN:
    case CI_CLASS_CHAOS:
    case CI_CLASS_HESOID:
    case CI_CLASS_NONE:
      return CI_TRUE;
    case CI_CLASS_ANY:
      if (type == CI_REC_TYPE_SIG) {
        return CI_TRUE;
      }
      if (is_query) {
        return CI_TRUE;
      }
      return CI_FALSE;
  }
  return CI_FALSE;
}

ci_bool_t ci_dns_section_isvalid(ci_dns_section_t sect)
{
  switch (sect) {
    case CI_SECTION_ANSWER:
    case CI_SECTION_AUTHORITY:
    case CI_SECTION_ADDITIONAL:
      return CI_TRUE;
  }
  return CI_FALSE;
}

ci_dns_rec_type_t ci_dns_rr_key_to_rec_type(ci_dns_rr_key_t key)
{
  /* NOTE: due to the way we've numerated the keys, we can simply divide by
   *       100 to get the type rather than having to do a huge switch
   *       statement.  That said, we do then validate the type returned is
   *       valid in case something completely bogus is passed in */
  ci_dns_rec_type_t type = key / 100;
  if (!ci_dns_rec_type_isvalid(type, CI_FALSE)) {
    return 0;
  }
  return type;
}

const char *ci_dns_rec_type_tostr(ci_dns_rec_type_t type)
{
  switch (type) {
    case CI_REC_TYPE_A:
      return "A";
    case CI_REC_TYPE_NS:
      return "NS";
    case CI_REC_TYPE_CNAME:
      return "CNAME";
    case CI_REC_TYPE_SOA:
      return "SOA";
    case CI_REC_TYPE_PTR:
      return "PTR";
    case CI_REC_TYPE_HINFO:
      return "HINFO";
    case CI_REC_TYPE_MX:
      return "MX";
    case CI_REC_TYPE_TXT:
      return "TXT";
    case CI_REC_TYPE_SIG:
      return "SIG";
    case CI_REC_TYPE_AAAA:
      return "AAAA";
    case CI_REC_TYPE_SRV:
      return "SRV";
    case CI_REC_TYPE_NAPTR:
      return "NAPTR";
    case CI_REC_TYPE_OPT:
      return "OPT";
    case CI_REC_TYPE_TLSA:
      return "TLSA";
    case CI_REC_TYPE_SVCB:
      return "SVCB";
    case CI_REC_TYPE_HTTPS:
      return "HTTPS";
    case CI_REC_TYPE_ANY:
      return "ANY";
    case CI_REC_TYPE_URI:
      return "URI";
    case CI_REC_TYPE_CAA:
      return "CAA";
    case CI_REC_TYPE_RAW_RR:
      return "RAWRR";
  }
  return "UNKNOWN";
}

const char *ci_dns_class_tostr(ci_dns_class_t qclass)
{
  switch (qclass) {
    case CI_CLASS_IN:
      return "IN";
    case CI_CLASS_CHAOS:
      return "CH";
    case CI_CLASS_HESOID:
      return "HS";
    case CI_CLASS_ANY:
      return "ANY";
    case CI_CLASS_NONE:
      return "NONE";
  }
  return "UNKNOWN";
}

const char *ci_dns_opcode_tostr(ci_dns_opcode_t opcode)
{
  switch (opcode) {
    case CI_OPCODE_QUERY:
      return "QUERY";
    case CI_OPCODE_IQUERY:
      return "IQUERY";
    case CI_OPCODE_STATUS:
      return "STATUS";
    case CI_OPCODE_NOTIFY:
      return "NOTIFY";
    case CI_OPCODE_UPDATE:
      return "UPDATE";
  }
  return "UNKNOWN";
}

const char *ci_dns_rr_key_tostr(ci_dns_rr_key_t key)
{
  switch (key) {
    case CI_RR_A_ADDR:
      return "ADDR";

    case CI_RR_NS_NSDNAME:
      return "NSDNAME";

    case CI_RR_CNAME_CNAME:
      return "CNAME";

    case CI_RR_SOA_MNAME:
      return "MNAME";

    case CI_RR_SOA_RNAME:
      return "RNAME";

    case CI_RR_SOA_SERIAL:
      return "SERIAL";

    case CI_RR_SOA_REFRESH:
      return "REFRESH";

    case CI_RR_SOA_RETRY:
      return "RETRY";

    case CI_RR_SOA_EXPIRE:
      return "EXPIRE";

    case CI_RR_SOA_MINIMUM:
      return "MINIMUM";

    case CI_RR_PTR_DNAME:
      return "DNAME";

    case CI_RR_AAAA_ADDR:
      return "ADDR";

    case CI_RR_HINFO_CPU:
      return "CPU";

    case CI_RR_HINFO_OS:
      return "OS";

    case CI_RR_MX_PREFERENCE:
      return "PREFERENCE";

    case CI_RR_MX_EXCHANGE:
      return "EXCHANGE";

    case CI_RR_TXT_DATA:
      return "DATA";

    case CI_RR_SIG_TYPE_COVERED:
      return "TYPE_COVERED";

    case CI_RR_SIG_ALGORITHM:
      return "ALGORITHM";

    case CI_RR_SIG_LABELS:
      return "LABELS";

    case CI_RR_SIG_ORIGINAL_TTL:
      return "ORIGINAL_TTL";

    case CI_RR_SIG_EXPIRATION:
      return "EXPIRATION";

    case CI_RR_SIG_INCEPTION:
      return "INCEPTION";

    case CI_RR_SIG_KEY_TAG:
      return "KEY_TAG";

    case CI_RR_SIG_SIGNERS_NAME:
      return "SIGNERS_NAME";

    case CI_RR_SIG_SIGNATURE:
      return "SIGNATURE";

    case CI_RR_SRV_PRIORITY:
      return "PRIORITY";

    case CI_RR_SRV_WEIGHT:
      return "WEIGHT";

    case CI_RR_SRV_PORT:
      return "PORT";

    case CI_RR_SRV_TARGET:
      return "TARGET";

    case CI_RR_NAPTR_ORDER:
      return "ORDER";

    case CI_RR_NAPTR_PREFERENCE:
      return "PREFERENCE";

    case CI_RR_NAPTR_FLAGS:
      return "FLAGS";

    case CI_RR_NAPTR_SERVICES:
      return "SERVICES";

    case CI_RR_NAPTR_REGEXP:
      return "REGEXP";

    case CI_RR_NAPTR_REPLACEMENT:
      return "REPLACEMENT";

    case CI_RR_OPT_UDP_SIZE:
      return "UDP_SIZE";

    case CI_RR_OPT_VERSION:
      return "VERSION";

    case CI_RR_OPT_FLAGS:
      return "FLAGS";

    case CI_RR_OPT_OPTIONS:
      return "OPTIONS";

    case CI_RR_TLSA_CERT_USAGE:
      return "CERT_USAGE";

    case CI_RR_TLSA_SELECTOR:
      return "SELECTOR";

    case CI_RR_TLSA_MATCH:
      return "MATCH";

    case CI_RR_TLSA_DATA:
      return "DATA";

    case CI_RR_SVCB_PRIORITY:
      return "PRIORITY";

    case CI_RR_SVCB_TARGET:
      return "TARGET";

    case CI_RR_SVCB_PARAMS:
      return "PARAMS";

    case CI_RR_HTTPS_PRIORITY:
      return "PRIORITY";

    case CI_RR_HTTPS_TARGET:
      return "TARGET";

    case CI_RR_HTTPS_PARAMS:
      return "PARAMS";

    case CI_RR_URI_PRIORITY:
      return "PRIORITY";

    case CI_RR_URI_WEIGHT:
      return "WEIGHT";

    case CI_RR_URI_TARGET:
      return "TARGET";

    case CI_RR_CAA_CRITICAL:
      return "CRITICAL";

    case CI_RR_CAA_TAG:
      return "TAG";

    case CI_RR_CAA_VALUE:
      return "VALUE";

    case CI_RR_RAW_RR_TYPE:
      return "TYPE";

    case CI_RR_RAW_RR_DATA:
      return "DATA";
  }

  return "UNKNOWN";
}

ci_dns_datatype_t ci_dns_rr_key_datatype(ci_dns_rr_key_t key)
{
  switch (key) {
    case CI_RR_A_ADDR:
      return CI_DATATYPE_INADDR;

    case CI_RR_AAAA_ADDR:
      return CI_DATATYPE_INADDR6;

    case CI_RR_NS_NSDNAME:
    case CI_RR_CNAME_CNAME:
    case CI_RR_SOA_MNAME:
    case CI_RR_SOA_RNAME:
    case CI_RR_PTR_DNAME:
    case CI_RR_MX_EXCHANGE:
    case CI_RR_SIG_SIGNERS_NAME:
    case CI_RR_SRV_TARGET:
    case CI_RR_SVCB_TARGET:
    case CI_RR_HTTPS_TARGET:
    case CI_RR_NAPTR_REPLACEMENT:
    case CI_RR_URI_TARGET:
      return CI_DATATYPE_NAME;

    case CI_RR_HINFO_CPU:
    case CI_RR_HINFO_OS:
    case CI_RR_NAPTR_FLAGS:
    case CI_RR_NAPTR_SERVICES:
    case CI_RR_NAPTR_REGEXP:
    case CI_RR_CAA_TAG:
      return CI_DATATYPE_STR;

    case CI_RR_SOA_SERIAL:
    case CI_RR_SOA_REFRESH:
    case CI_RR_SOA_RETRY:
    case CI_RR_SOA_EXPIRE:
    case CI_RR_SOA_MINIMUM:
    case CI_RR_SIG_ORIGINAL_TTL:
    case CI_RR_SIG_EXPIRATION:
    case CI_RR_SIG_INCEPTION:
      return CI_DATATYPE_U32;

    case CI_RR_MX_PREFERENCE:
    case CI_RR_SIG_TYPE_COVERED:
    case CI_RR_SIG_KEY_TAG:
    case CI_RR_SRV_PRIORITY:
    case CI_RR_SRV_WEIGHT:
    case CI_RR_SRV_PORT:
    case CI_RR_NAPTR_ORDER:
    case CI_RR_NAPTR_PREFERENCE:
    case CI_RR_OPT_UDP_SIZE:
    case CI_RR_OPT_FLAGS:
    case CI_RR_SVCB_PRIORITY:
    case CI_RR_HTTPS_PRIORITY:
    case CI_RR_URI_PRIORITY:
    case CI_RR_URI_WEIGHT:
    case CI_RR_RAW_RR_TYPE:
      return CI_DATATYPE_U16;

    case CI_RR_SIG_ALGORITHM:
    case CI_RR_SIG_LABELS:
    case CI_RR_OPT_VERSION:
    case CI_RR_TLSA_CERT_USAGE:
    case CI_RR_TLSA_SELECTOR:
    case CI_RR_TLSA_MATCH:
    case CI_RR_CAA_CRITICAL:
      return CI_DATATYPE_U8;

    case CI_RR_CAA_VALUE:
      return CI_DATATYPE_BINP;

    case CI_RR_TXT_DATA:
      return CI_DATATYPE_ABINP;

    case CI_RR_SIG_SIGNATURE:
    case CI_RR_TLSA_DATA:
    case CI_RR_RAW_RR_DATA:
      return CI_DATATYPE_BIN;

    case CI_RR_OPT_OPTIONS:
    case CI_RR_SVCB_PARAMS:
    case CI_RR_HTTPS_PARAMS:
      return CI_DATATYPE_OPT;
  }

  return 0;
}

static const ci_dns_rr_key_t rr_a_keys[]     = { CI_RR_A_ADDR };
static const ci_dns_rr_key_t rr_ns_keys[]    = { CI_RR_NS_NSDNAME };
static const ci_dns_rr_key_t rr_cname_keys[] = { CI_RR_CNAME_CNAME };
static const ci_dns_rr_key_t rr_soa_keys[]   = {
  CI_RR_SOA_MNAME,   CI_RR_SOA_RNAME, CI_RR_SOA_SERIAL,
  CI_RR_SOA_REFRESH, CI_RR_SOA_RETRY, CI_RR_SOA_EXPIRE,
  CI_RR_SOA_MINIMUM
};
static const ci_dns_rr_key_t rr_ptr_keys[]   = { CI_RR_PTR_DNAME };
static const ci_dns_rr_key_t rr_hinfo_keys[] = { CI_RR_HINFO_CPU,
                                                   CI_RR_HINFO_OS };
static const ci_dns_rr_key_t rr_mx_keys[]    = { CI_RR_MX_PREFERENCE,
                                                   CI_RR_MX_EXCHANGE };
static const ci_dns_rr_key_t rr_sig_keys[]   = {
  CI_RR_SIG_TYPE_COVERED, CI_RR_SIG_ALGORITHM,    CI_RR_SIG_LABELS,
  CI_RR_SIG_ORIGINAL_TTL, CI_RR_SIG_EXPIRATION,   CI_RR_SIG_INCEPTION,
  CI_RR_SIG_KEY_TAG,      CI_RR_SIG_SIGNERS_NAME, CI_RR_SIG_SIGNATURE
};
static const ci_dns_rr_key_t rr_txt_keys[]  = { CI_RR_TXT_DATA };
static const ci_dns_rr_key_t rr_aaaa_keys[] = { CI_RR_AAAA_ADDR };
static const ci_dns_rr_key_t rr_srv_keys[]  = {
  CI_RR_SRV_PRIORITY, CI_RR_SRV_WEIGHT, CI_RR_SRV_PORT, CI_RR_SRV_TARGET
};
static const ci_dns_rr_key_t rr_naptr_keys[] = {
  CI_RR_NAPTR_ORDER,    CI_RR_NAPTR_PREFERENCE, CI_RR_NAPTR_FLAGS,
  CI_RR_NAPTR_SERVICES, CI_RR_NAPTR_REGEXP,     CI_RR_NAPTR_REPLACEMENT
};
static const ci_dns_rr_key_t rr_opt_keys[]    = { CI_RR_OPT_UDP_SIZE,
                                                    CI_RR_OPT_VERSION,
                                                    CI_RR_OPT_FLAGS,
                                                    CI_RR_OPT_OPTIONS };
static const ci_dns_rr_key_t rr_tlsa_keys[]   = { CI_RR_TLSA_CERT_USAGE,
                                                    CI_RR_TLSA_SELECTOR,
                                                    CI_RR_TLSA_MATCH,
                                                    CI_RR_TLSA_DATA };
static const ci_dns_rr_key_t rr_svcb_keys[]   = { CI_RR_SVCB_PRIORITY,
                                                    CI_RR_SVCB_TARGET,
                                                    CI_RR_SVCB_PARAMS };
static const ci_dns_rr_key_t rr_https_keys[]  = { CI_RR_HTTPS_PRIORITY,
                                                    CI_RR_HTTPS_TARGET,
                                                    CI_RR_HTTPS_PARAMS };
static const ci_dns_rr_key_t rr_uri_keys[]    = { CI_RR_URI_PRIORITY,
                                                    CI_RR_URI_WEIGHT,
                                                    CI_RR_URI_TARGET };
static const ci_dns_rr_key_t rr_caa_keys[]    = { CI_RR_CAA_CRITICAL,
                                                    CI_RR_CAA_TAG,
                                                    CI_RR_CAA_VALUE };
static const ci_dns_rr_key_t rr_raw_rr_keys[] = { CI_RR_RAW_RR_TYPE,
                                                    CI_RR_RAW_RR_DATA };

const ci_dns_rr_key_t       *ci_dns_rr_get_keys(ci_dns_rec_type_t type,
                                                    size_t             *cnt)
{
  if (cnt == NULL) {
    return NULL;
  }

  *cnt = 0;

  switch (type) {
    case CI_REC_TYPE_A:
      *cnt = sizeof(rr_a_keys) / sizeof(*rr_a_keys);
      return rr_a_keys;
    case CI_REC_TYPE_NS:
      *cnt = sizeof(rr_ns_keys) / sizeof(*rr_ns_keys);
      return rr_ns_keys;
    case CI_REC_TYPE_CNAME:
      *cnt = sizeof(rr_cname_keys) / sizeof(*rr_cname_keys);
      return rr_cname_keys;
    case CI_REC_TYPE_SOA:
      *cnt = sizeof(rr_soa_keys) / sizeof(*rr_soa_keys);
      return rr_soa_keys;
    case CI_REC_TYPE_PTR:
      *cnt = sizeof(rr_ptr_keys) / sizeof(*rr_ptr_keys);
      return rr_ptr_keys;
    case CI_REC_TYPE_HINFO:
      *cnt = sizeof(rr_hinfo_keys) / sizeof(*rr_hinfo_keys);
      return rr_hinfo_keys;
    case CI_REC_TYPE_MX:
      *cnt = sizeof(rr_mx_keys) / sizeof(*rr_mx_keys);
      return rr_mx_keys;
    case CI_REC_TYPE_TXT:
      *cnt = sizeof(rr_txt_keys) / sizeof(*rr_txt_keys);
      return rr_txt_keys;
    case CI_REC_TYPE_SIG:
      *cnt = sizeof(rr_sig_keys) / sizeof(*rr_sig_keys);
      return rr_sig_keys;
    case CI_REC_TYPE_AAAA:
      *cnt = sizeof(rr_aaaa_keys) / sizeof(*rr_aaaa_keys);
      return rr_aaaa_keys;
    case CI_REC_TYPE_SRV:
      *cnt = sizeof(rr_srv_keys) / sizeof(*rr_srv_keys);
      return rr_srv_keys;
    case CI_REC_TYPE_NAPTR:
      *cnt = sizeof(rr_naptr_keys) / sizeof(*rr_naptr_keys);
      return rr_naptr_keys;
    case CI_REC_TYPE_OPT:
      *cnt = sizeof(rr_opt_keys) / sizeof(*rr_opt_keys);
      return rr_opt_keys;
    case CI_REC_TYPE_TLSA:
      *cnt = sizeof(rr_tlsa_keys) / sizeof(*rr_tlsa_keys);
      return rr_tlsa_keys;
    case CI_REC_TYPE_SVCB:
      *cnt = sizeof(rr_svcb_keys) / sizeof(*rr_svcb_keys);
      return rr_svcb_keys;
    case CI_REC_TYPE_HTTPS:
      *cnt = sizeof(rr_https_keys) / sizeof(*rr_https_keys);
      return rr_https_keys;
    case CI_REC_TYPE_ANY:
      /* Not real */
      break;
    case CI_REC_TYPE_URI:
      *cnt = sizeof(rr_uri_keys) / sizeof(*rr_uri_keys);
      return rr_uri_keys;
    case CI_REC_TYPE_CAA:
      *cnt = sizeof(rr_caa_keys) / sizeof(*rr_caa_keys);
      return rr_caa_keys;
    case CI_REC_TYPE_RAW_RR:
      *cnt = sizeof(rr_raw_rr_keys) / sizeof(*rr_raw_rr_keys);
      return rr_raw_rr_keys;
  }

  return NULL;
}

ci_bool_t ci_dns_class_fromstr(ci_dns_class_t *qclass, const char *str)
{
  size_t i;

  static const struct {
    const char      *name;
    ci_dns_class_t qclass;
  } list[] = {
    { "IN",   CI_CLASS_IN     },
    { "CH",   CI_CLASS_CHAOS  },
    { "HS",   CI_CLASS_HESOID },
    { "NONE", CI_CLASS_NONE   },
    { "ANY",  CI_CLASS_ANY    },
    { NULL,   0                 }
  };

  if (qclass == NULL || str == NULL) {
    return CI_FALSE;
  }

  for (i = 0; list[i].name != NULL; i++) {
    if (ci_strcaseeq(list[i].name, str)) {
      *qclass = list[i].qclass;
      return CI_TRUE;
    }
  }
  return CI_FALSE;
}

ci_bool_t ci_dns_rec_type_fromstr(ci_dns_rec_type_t *qtype,
                                      const char          *str)
{
  size_t i;

  static const struct {
    const char         *name;
    ci_dns_rec_type_t type;
  } list[] = {
    { "A",      CI_REC_TYPE_A      },
    { "NS",     CI_REC_TYPE_NS     },
    { "CNAME",  CI_REC_TYPE_CNAME  },
    { "SOA",    CI_REC_TYPE_SOA    },
    { "PTR",    CI_REC_TYPE_PTR    },
    { "HINFO",  CI_REC_TYPE_HINFO  },
    { "MX",     CI_REC_TYPE_MX     },
    { "TXT",    CI_REC_TYPE_TXT    },
    { "SIG",    CI_REC_TYPE_SIG    },
    { "AAAA",   CI_REC_TYPE_AAAA   },
    { "SRV",    CI_REC_TYPE_SRV    },
    { "NAPTR",  CI_REC_TYPE_NAPTR  },
    { "OPT",    CI_REC_TYPE_OPT    },
    { "TLSA",   CI_REC_TYPE_TLSA   },
    { "SVCB",   CI_REC_TYPE_SVCB   },
    { "HTTPS",  CI_REC_TYPE_HTTPS  },
    { "ANY",    CI_REC_TYPE_ANY    },
    { "URI",    CI_REC_TYPE_URI    },
    { "CAA",    CI_REC_TYPE_CAA    },
    { "RAW_RR", CI_REC_TYPE_RAW_RR },
    { NULL,     0                    }
  };

  if (qtype == NULL || str == NULL) {
    return CI_FALSE;
  }

  for (i = 0; list[i].name != NULL; i++) {
    if (ci_strcaseeq(list[i].name, str)) {
      *qtype = list[i].type;
      return CI_TRUE;
    }
  }
  return CI_FALSE;
}

const char *ci_dns_section_tostr(ci_dns_section_t section)
{
  switch (section) {
    case CI_SECTION_ANSWER:
      return "ANSWER";
    case CI_SECTION_AUTHORITY:
      return "AUTHORITY";
    case CI_SECTION_ADDITIONAL:
      return "ADDITIONAL";
  }
  return "UNKNOWN";
}

static ci_dns_opt_datatype_t ci_dns_opt_get_type_opt(unsigned short opt)
{
  ci_opt_param_t param = (ci_opt_param_t)opt;
  switch (param) {
    case CI_OPT_PARAM_LLQ:
      /* Really it is u16 version, u16 opcode, u16 error, u64 id, u32 lease */
      return CI_OPT_DATATYPE_BIN;
    case CI_OPT_PARAM_UL:
      return CI_OPT_DATATYPE_U32;
    case CI_OPT_PARAM_NSID:
      return CI_OPT_DATATYPE_BIN;
    case CI_OPT_PARAM_DAU:
      return CI_OPT_DATATYPE_U8_LIST;
    case CI_OPT_PARAM_DHU:
      return CI_OPT_DATATYPE_U8_LIST;
    case CI_OPT_PARAM_N3U:
      return CI_OPT_DATATYPE_U8_LIST;
    case CI_OPT_PARAM_EDNS_CLIENT_SUBNET:
      /* Really it is a u16 address family, u8 source prefix length,
       * u8 scope prefix length, address */
      return CI_OPT_DATATYPE_BIN;
    case CI_OPT_PARAM_EDNS_EXPIRE:
      return CI_OPT_DATATYPE_U32;
    case CI_OPT_PARAM_COOKIE:
      /* 8 bytes for client, 16-40 bytes for server */
      return CI_OPT_DATATYPE_BIN;
    case CI_OPT_PARAM_EDNS_TCP_KEEPALIVE:
      /* Timeout in 100ms intervals */
      return CI_OPT_DATATYPE_U16;
    case CI_OPT_PARAM_PADDING:
      /* Arbitrary padding */
      return CI_OPT_DATATYPE_BIN;
    case CI_OPT_PARAM_CHAIN:
      return CI_OPT_DATATYPE_NAME;
    case CI_OPT_PARAM_EDNS_KEY_TAG:
      return CI_OPT_DATATYPE_U16_LIST;
    case CI_OPT_PARAM_EXTENDED_DNS_ERROR:
      /* Really 16bit code followed by textual message */
      return CI_OPT_DATATYPE_BIN;
  }
  return CI_OPT_DATATYPE_BIN;
}

static ci_dns_opt_datatype_t ci_dns_opt_get_type_svcb(unsigned short opt)
{
  ci_svcb_param_t param = (ci_svcb_param_t)opt;
  switch (param) {
    case CI_SVCB_PARAM_NO_DEFAULT_ALPN:
      return CI_OPT_DATATYPE_NONE;
    case CI_SVCB_PARAM_ECH:
      return CI_OPT_DATATYPE_BIN;
    case CI_SVCB_PARAM_MANDATORY:
      return CI_OPT_DATATYPE_U16_LIST;
    case CI_SVCB_PARAM_ALPN:
      return CI_OPT_DATATYPE_STR_LIST;
    case CI_SVCB_PARAM_PORT:
      return CI_OPT_DATATYPE_U16;
    case CI_SVCB_PARAM_IPV4HINT:
      return CI_OPT_DATATYPE_INADDR4_LIST;
    case CI_SVCB_PARAM_IPV6HINT:
      return CI_OPT_DATATYPE_INADDR6_LIST;
  }
  return CI_OPT_DATATYPE_BIN;
}

ci_dns_opt_datatype_t ci_dns_opt_get_datatype(ci_dns_rr_key_t key,
                                                  unsigned short    opt)
{
  switch (key) {
    case CI_RR_OPT_OPTIONS:
      return ci_dns_opt_get_type_opt(opt);
    case CI_RR_SVCB_PARAMS:
    case CI_RR_HTTPS_PARAMS:
      return ci_dns_opt_get_type_svcb(opt);
    default:
      break;
  }
  return CI_OPT_DATATYPE_BIN;
}

static const char *ci_dns_opt_get_name_opt(unsigned short opt)
{
  ci_opt_param_t param = (ci_opt_param_t)opt;
  switch (param) {
    case CI_OPT_PARAM_LLQ:
      return "LLQ";
    case CI_OPT_PARAM_UL:
      return "UL";
    case CI_OPT_PARAM_NSID:
      return "NSID";
    case CI_OPT_PARAM_DAU:
      return "DAU";
    case CI_OPT_PARAM_DHU:
      return "DHU";
    case CI_OPT_PARAM_N3U:
      return "N3U";
    case CI_OPT_PARAM_EDNS_CLIENT_SUBNET:
      return "edns-client-subnet";
    case CI_OPT_PARAM_EDNS_EXPIRE:
      return "edns-expire";
    case CI_OPT_PARAM_COOKIE:
      return "COOKIE";
    case CI_OPT_PARAM_EDNS_TCP_KEEPALIVE:
      return "edns-tcp-keepalive";
    case CI_OPT_PARAM_PADDING:
      return "Padding";
    case CI_OPT_PARAM_CHAIN:
      return "CHAIN";
    case CI_OPT_PARAM_EDNS_KEY_TAG:
      return "edns-key-tag";
    case CI_OPT_PARAM_EXTENDED_DNS_ERROR:
      return "extended-dns-error";
  }
  return NULL;
}

static const char *ci_dns_opt_get_name_svcb(unsigned short opt)
{
  ci_svcb_param_t param = (ci_svcb_param_t)opt;
  switch (param) {
    case CI_SVCB_PARAM_NO_DEFAULT_ALPN:
      return "no-default-alpn";
    case CI_SVCB_PARAM_ECH:
      return "ech";
    case CI_SVCB_PARAM_MANDATORY:
      return "mandatory";
    case CI_SVCB_PARAM_ALPN:
      return "alpn";
    case CI_SVCB_PARAM_PORT:
      return "port";
    case CI_SVCB_PARAM_IPV4HINT:
      return "ipv4hint";
    case CI_SVCB_PARAM_IPV6HINT:
      return "ipv6hint";
  }
  return NULL;
}

const char *ci_dns_opt_get_name(ci_dns_rr_key_t key, unsigned short opt)
{
  switch (key) {
    case CI_RR_OPT_OPTIONS:
      return ci_dns_opt_get_name_opt(opt);
    case CI_RR_SVCB_PARAMS:
    case CI_RR_HTTPS_PARAMS:
      return ci_dns_opt_get_name_svcb(opt);
    default:
      break;
  }
  return NULL;
}

const char *ci_dns_rcode_tostr(ci_dns_rcode_t rcode)
{
  switch (rcode) {
    case CI_RCODE_NOERROR:
      return "NOERROR";
    case CI_RCODE_FORMERR:
      return "FORMERR";
    case CI_RCODE_SERVFAIL:
      return "SERVFAIL";
    case CI_RCODE_NXDOMAIN:
      return "NXDOMAIN";
    case CI_RCODE_NOTIMP:
      return "NOTIMP";
    case CI_RCODE_REFUSED:
      return "REFUSED";
    case CI_RCODE_YXDOMAIN:
      return "YXDOMAIN";
    case CI_RCODE_YXRRSET:
      return "YXRRSET";
    case CI_RCODE_NXRRSET:
      return "NXRRSET";
    case CI_RCODE_NOTAUTH:
      return "NOTAUTH";
    case CI_RCODE_NOTZONE:
      return "NOTZONE";
    case CI_RCODE_DSOTYPEI:
      return "DSOTYPEI";
    case CI_RCODE_BADSIG:
      return "BADSIG";
    case CI_RCODE_BADKEY:
      return "BADKEY";
    case CI_RCODE_BADTIME:
      return "BADTIME";
    case CI_RCODE_BADMODE:
      return "BADMODE";
    case CI_RCODE_BADNAME:
      return "BADNAME";
    case CI_RCODE_BADALG:
      return "BADALG";
    case CI_RCODE_BADTRUNC:
      return "BADTRUNC";
    case CI_RCODE_BADCOOKIE:
      return "BADCOOKIE";
  }

  return "UNKNOWN";
}

/* Convert an rcode and ancount from a query reply into an ci_status_t
 * value. Used internally by ci_search() and ci_query().
 */
ci_status_t ci_dns_query_reply_tostatus(ci_dns_rcode_t rcode,
                                            size_t           ancount)
{
  ci_status_t status = CI_SUCCESS;

  switch (rcode) {
    case CI_RCODE_NOERROR:
      status = (ancount > 0) ? CI_SUCCESS : CI_ENODATA;
      break;
    case CI_RCODE_FORMERR:
      status = CI_EFORMERR;
      break;
    case CI_RCODE_SERVFAIL:
      status = CI_ESERVFAIL;
      break;
    case CI_RCODE_NXDOMAIN:
      status = CI_ENOTFOUND;
      break;
    case CI_RCODE_NOTIMP:
      status = CI_ENOTIMP;
      break;
    case CI_RCODE_REFUSED:
      status = CI_EREFUSED;
      break;
    default:
      break;
  }

  return status;
}
