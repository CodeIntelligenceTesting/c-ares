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
#ifndef __CI_DNS_RECORD_H
#define __CI_DNS_RECORD_H

/* Include ci.h, not this file directly */

#ifdef __cplusplus
extern "C" {
#endif

/*! \addtogroup ci_dns_record DNS Record Handling
 *
 * This is a set of functions to create and manipulate DNS records.
 *
 * @{
 */

/*! DNS Record types handled by c-ci.  Some record types may only be valid
 *  on requests (e.g. CI_REC_TYPE_ANY), and some may only be valid on
 *  responses */
typedef enum {
  CI_REC_TYPE_A     = 1,     /*!< Host address. */
  CI_REC_TYPE_NS    = 2,     /*!< Authoritative server. */
  CI_REC_TYPE_CNAME = 5,     /*!< Canonical name. */
  CI_REC_TYPE_SOA   = 6,     /*!< Start of authority zone. */
  CI_REC_TYPE_PTR   = 12,    /*!< Domain name pointer. */
  CI_REC_TYPE_HINFO = 13,    /*!< Host information. */
  CI_REC_TYPE_MX    = 15,    /*!< Mail routing information. */
  CI_REC_TYPE_TXT   = 16,    /*!< Text strings. */
  CI_REC_TYPE_SIG   = 24,    /*!< RFC 2535 / RFC 2931. SIG Record */
  CI_REC_TYPE_AAAA  = 28,    /*!< RFC 3596. Ip6 Address. */
  CI_REC_TYPE_SRV   = 33,    /*!< RFC 2782. Server Selection. */
  CI_REC_TYPE_NAPTR = 35,    /*!< RFC 3403. Naming Authority Pointer */
  CI_REC_TYPE_OPT   = 41,    /*!< RFC 6891. EDNS0 option (meta-RR) */

  CI_REC_TYPE_TLSA = 52,     /*!< RFC 6698. DNS-Based Authentication of Named
                                *   Entities (DANE) Transport Layer Security
                                *   (TLS) Protocol: TLSA */
  CI_REC_TYPE_SVCB  = 64,    /*!< RFC 9460. General Purpose Service Binding */
  CI_REC_TYPE_HTTPS = 65,    /*!< RFC 9460. Service Binding type for use with
                                *   HTTPS */
  CI_REC_TYPE_ANY = 255,     /*!< Wildcard match.  Not response RR. */
  CI_REC_TYPE_URI = 256,     /*!< RFC 7553. Uniform Resource Identifier */
  CI_REC_TYPE_CAA = 257,     /*!< RFC 6844. Certification Authority
                                *   Authorization. */
  CI_REC_TYPE_RAW_RR = 65536 /*!< Used as an indicator that the RR record
                                *   is not parsed, but provided in wire
                                *   format */
} ci_dns_rec_type_t;

/*! DNS Classes for requests and responses.  */
typedef enum {
  CI_CLASS_IN     = 1,   /*!< Internet */
  CI_CLASS_CHAOS  = 3,   /*!< CHAOS */
  CI_CLASS_HESOID = 4,   /*!< Hesoid [Dyer 87] */
  CI_CLASS_NONE   = 254, /*!< RFC 2136 */
  CI_CLASS_ANY    = 255  /*!< Any class (requests only) */
} ci_dns_class_t;

/*! DNS RR Section type */
typedef enum {
  CI_SECTION_ANSWER     = 1, /*!< Answer section */
  CI_SECTION_AUTHORITY  = 2, /*!< Authority section */
  CI_SECTION_ADDITIONAL = 3  /*!< Additional information section */
} ci_dns_section_t;

/*! DNS Header opcodes */
typedef enum {
  CI_OPCODE_QUERY  = 0, /*!< Standard query */
  CI_OPCODE_IQUERY = 1, /*!< Inverse query. Obsolete. */
  CI_OPCODE_STATUS = 2, /*!< Name server status query */
  CI_OPCODE_NOTIFY = 4, /*!< Zone change notification (RFC 1996) */
  CI_OPCODE_UPDATE = 5  /*!< Zone update message (RFC2136) */
} ci_dns_opcode_t;

/*! DNS Header flags */
typedef enum {
  CI_FLAG_QR = 1 << 0, /*!< QR. If set, is a response */
  CI_FLAG_AA = 1 << 1, /*!< Authoritative Answer. If set, is authoritative */
  CI_FLAG_TC = 1 << 2, /*!< Truncation. If set, is truncated response */
  CI_FLAG_RD = 1 << 3, /*!< Recursion Desired. If set, recursion is desired */
  CI_FLAG_RA = 1 << 4, /*!< Recursion Available. If set, server supports
                          *   recursion */
  CI_FLAG_AD = 1 << 5, /*!< RFC 2065. Authentic Data bit indicates in a
                          * response that the data included has been verified by
                          * the server providing it */
  CI_FLAG_CD = 1 << 6  /*!< RFC 2065. Checking Disabled bit indicates in a
                          * query that non-verified data is acceptable to the
                          * resolver sending the query. */
} ci_dns_flags_t;

/*! DNS Response Codes from server */
typedef enum {
  CI_RCODE_NOERROR = 0,    /*!< Success */
  CI_RCODE_FORMERR = 1,    /*!< Format error. The name server was unable
                              *   to interpret the query. */
  CI_RCODE_SERVFAIL = 2,   /*!< Server Failure. The name server was
                              *   unable to process this query due to a
                              *   problem with the nameserver */
  CI_RCODE_NXDOMAIN = 3,   /*!< Name Error.  Meaningful only for
                              *   responses from an authoritative name
                              *   server, this code signifies that the
                              *   domain name referenced in the query does
                              *   not exist. */
  CI_RCODE_NOTIMP = 4,     /*!< Not implemented.  The name server does
                              *   not support the requested kind of
                              *   query */
  CI_RCODE_REFUSED = 5,    /*!< Refused. The name server refuses to
                              *   perform the specified operation for
                              *   policy reasons. */
  CI_RCODE_YXDOMAIN = 6,   /*!< RFC 2136. Some name that ought not to
                              *   exist, does exist. */
  CI_RCODE_YXRRSET = 7,    /*!< RFC 2136. Some RRset that ought to not
                              *   exist, does exist. */
  CI_RCODE_NXRRSET = 8,    /*!< RFC 2136. Some RRset that ought to exist,
                              *   does not exist. */
  CI_RCODE_NOTAUTH = 9,    /*!< RFC 2136. The server is not authoritative
                              *   for the zone named in the Zone section.
                              */
  CI_RCODE_NOTZONE = 10,   /*!< RFC 2136. A name used in the Prerequisite
                              *   or Update Section is not within the zone
                              *   denoted by the Zone Section. */
  CI_RCODE_DSOTYPEI  = 11, /*!< RFC 8409. DSO-TYPE Not implemented */
  CI_RCODE_BADSIG    = 16, /*!< RFC 8945. TSIG Signature Failure */
  CI_RCODE_BADKEY    = 17, /*!< RFC 8945. Key not recognized. */
  CI_RCODE_BADTIME   = 18, /*!< RFC 8945. Signature out of time window. */
  CI_RCODE_BADMODE   = 19, /*!< RFC 2930. Bad TKEY Mode */
  CI_RCODE_BADNAME   = 20, /*!< RFC 2930. Duplicate Key Name */
  CI_RCODE_BADALG    = 21, /*!< RFC 2930. Algorithm not supported */
  CI_RCODE_BADTRUNC  = 22, /*!< RFC 8945. Bad Truncation */
  CI_RCODE_BADCOOKIE = 23  /*!< RFC 7873. Bad/missing Server Cookie */
} ci_dns_rcode_t;

/*! Data types used */
typedef enum {
  CI_DATATYPE_INADDR  = 1, /*!< struct in_addr * type */
  CI_DATATYPE_INADDR6 = 2, /*!< struct ci_in6_addr * type */
  CI_DATATYPE_U8      = 3, /*!< 8bit unsigned integer */
  CI_DATATYPE_U16     = 4, /*!< 16bit unsigned integer */
  CI_DATATYPE_U32     = 5, /*!< 32bit unsigned integer */
  CI_DATATYPE_NAME    = 6, /*!< Null-terminated string of a domain name */
  CI_DATATYPE_STR     = 7, /*!< Null-terminated string */
  CI_DATATYPE_BIN     = 8, /*!< Binary data */
  CI_DATATYPE_BINP    = 9, /*!< Officially defined as binary data, but likely
                              *   printable. Guaranteed to have a NULL
                              *   terminator for convenience (not included in
                              *   length) */
  CI_DATATYPE_OPT = 10,    /*!< Array of options.  16bit identifier, BIN
                              *   data. */
  CI_DATATYPE_ABINP = 11   /*!< Array of binary data, likely printable.
                              *   Guaranteed to have a NULL terminator for
                              *   convenience (not included in length) */
} ci_dns_datatype_t;

/*! Keys used for all RR Types.  We take the record type and multiply by 100
 *  to ensure we have a proper offset between keys so we can keep these sorted
 */
typedef enum {
  /*! A Record. Address. Datatype: INADDR */
  CI_RR_A_ADDR = (CI_REC_TYPE_A * 100) + 1,
  /*! NS Record. Name. Datatype: NAME */
  CI_RR_NS_NSDNAME = (CI_REC_TYPE_NS * 100) + 1,
  /*! CNAME Record. CName. Datatype: NAME */
  CI_RR_CNAME_CNAME = (CI_REC_TYPE_CNAME * 100) + 1,
  /*! SOA Record. MNAME, Primary Source of Data. Datatype: NAME */
  CI_RR_SOA_MNAME = (CI_REC_TYPE_SOA * 100) + 1,
  /*! SOA Record. RNAME, Mailbox of person responsible. Datatype: NAME */
  CI_RR_SOA_RNAME = (CI_REC_TYPE_SOA * 100) + 2,
  /*! SOA Record. Serial, version. Datatype: U32 */
  CI_RR_SOA_SERIAL = (CI_REC_TYPE_SOA * 100) + 3,
  /*! SOA Record. Refresh, zone refersh interval. Datatype: U32 */
  CI_RR_SOA_REFRESH = (CI_REC_TYPE_SOA * 100) + 4,
  /*! SOA Record. Retry, failed refresh retry interval. Datatype: U32 */
  CI_RR_SOA_RETRY = (CI_REC_TYPE_SOA * 100) + 5,
  /*! SOA Record. Expire, upper limit on authority. Datatype: U32 */
  CI_RR_SOA_EXPIRE = (CI_REC_TYPE_SOA * 100) + 6,
  /*! SOA Record. Minimum, RR TTL. Datatype: U32 */
  CI_RR_SOA_MINIMUM = (CI_REC_TYPE_SOA * 100) + 7,
  /*! PTR Record. DNAME, pointer domain. Datatype: NAME */
  CI_RR_PTR_DNAME = (CI_REC_TYPE_PTR * 100) + 1,
  /*! HINFO Record. CPU. Datatype: STR */
  CI_RR_HINFO_CPU = (CI_REC_TYPE_HINFO * 100) + 1,
  /*! HINFO Record. OS. Datatype: STR */
  CI_RR_HINFO_OS = (CI_REC_TYPE_HINFO * 100) + 2,
  /*! MX Record. Preference. Datatype: U16 */
  CI_RR_MX_PREFERENCE = (CI_REC_TYPE_MX * 100) + 1,
  /*! MX Record. Exchange, domain. Datatype: NAME */
  CI_RR_MX_EXCHANGE = (CI_REC_TYPE_MX * 100) + 2,
  /*! TXT Record. Data. Datatype: ABINP */
  CI_RR_TXT_DATA = (CI_REC_TYPE_TXT * 100) + 1,
  /*! SIG Record. Type Covered. Datatype: U16 */
  CI_RR_SIG_TYPE_COVERED = (CI_REC_TYPE_SIG * 100) + 1,
  /*! SIG Record. Algorithm. Datatype: U8 */
  CI_RR_SIG_ALGORITHM = (CI_REC_TYPE_SIG * 100) + 2,
  /*! SIG Record. Labels. Datatype: U8 */
  CI_RR_SIG_LABELS = (CI_REC_TYPE_SIG * 100) + 3,
  /*! SIG Record. Original TTL. Datatype: U32 */
  CI_RR_SIG_ORIGINAL_TTL = (CI_REC_TYPE_SIG * 100) + 4,
  /*! SIG Record. Signature Expiration. Datatype: U32 */
  CI_RR_SIG_EXPIRATION = (CI_REC_TYPE_SIG * 100) + 5,
  /*! SIG Record. Signature Inception. Datatype: U32 */
  CI_RR_SIG_INCEPTION = (CI_REC_TYPE_SIG * 100) + 6,
  /*! SIG Record. Key Tag. Datatype: U16 */
  CI_RR_SIG_KEY_TAG = (CI_REC_TYPE_SIG * 100) + 7,
  /*! SIG Record. Signers Name. Datatype: NAME */
  CI_RR_SIG_SIGNERS_NAME = (CI_REC_TYPE_SIG * 100) + 8,
  /*! SIG Record. Signature. Datatype: BIN */
  CI_RR_SIG_SIGNATURE = (CI_REC_TYPE_SIG * 100) + 9,
  /*! AAAA Record. Address. Datatype: INADDR6 */
  CI_RR_AAAA_ADDR = (CI_REC_TYPE_AAAA * 100) + 1,
  /*! SRV Record. Priority. Datatype: U16 */
  CI_RR_SRV_PRIORITY = (CI_REC_TYPE_SRV * 100) + 2,
  /*! SRV Record. Weight. Datatype: U16 */
  CI_RR_SRV_WEIGHT = (CI_REC_TYPE_SRV * 100) + 3,
  /*! SRV Record. Port. Datatype: U16 */
  CI_RR_SRV_PORT = (CI_REC_TYPE_SRV * 100) + 4,
  /*! SRV Record. Target domain. Datatype: NAME */
  CI_RR_SRV_TARGET = (CI_REC_TYPE_SRV * 100) + 5,
  /*! NAPTR Record. Order. Datatype: U16 */
  CI_RR_NAPTR_ORDER = (CI_REC_TYPE_NAPTR * 100) + 1,
  /*! NAPTR Record. Preference. Datatype: U16 */
  CI_RR_NAPTR_PREFERENCE = (CI_REC_TYPE_NAPTR * 100) + 2,
  /*! NAPTR Record. Flags. Datatype: STR */
  CI_RR_NAPTR_FLAGS = (CI_REC_TYPE_NAPTR * 100) + 3,
  /*! NAPTR Record. Services. Datatype: STR */
  CI_RR_NAPTR_SERVICES = (CI_REC_TYPE_NAPTR * 100) + 4,
  /*! NAPTR Record. Regexp. Datatype: STR */
  CI_RR_NAPTR_REGEXP = (CI_REC_TYPE_NAPTR * 100) + 5,
  /*! NAPTR Record. Replacement. Datatype: NAME */
  CI_RR_NAPTR_REPLACEMENT = (CI_REC_TYPE_NAPTR * 100) + 6,
  /*! OPT Record. UDP Size. Datatype: U16 */
  CI_RR_OPT_UDP_SIZE = (CI_REC_TYPE_OPT * 100) + 1,
  /*! OPT Record. Version. Datatype: U8 */
  CI_RR_OPT_VERSION = (CI_REC_TYPE_OPT * 100) + 3,
  /*! OPT Record. Flags. Datatype: U16 */
  CI_RR_OPT_FLAGS = (CI_REC_TYPE_OPT * 100) + 4,
  /*! OPT Record. Options. Datatype: OPT */
  CI_RR_OPT_OPTIONS = (CI_REC_TYPE_OPT * 100) + 5,
  /*! TLSA Record. Certificate Usage. Datatype: U8 */
  CI_RR_TLSA_CERT_USAGE = (CI_REC_TYPE_TLSA * 100) + 1,
  /*! TLSA Record. Selector. Datatype: U8 */
  CI_RR_TLSA_SELECTOR = (CI_REC_TYPE_TLSA * 100) + 2,
  /*! TLSA Record. Matching Type. Datatype: U8 */
  CI_RR_TLSA_MATCH = (CI_REC_TYPE_TLSA * 100) + 3,
  /*! TLSA Record. Certificate Association Data. Datatype: BIN */
  CI_RR_TLSA_DATA = (CI_REC_TYPE_TLSA * 100) + 4,
  /*! SVCB Record. SvcPriority. Datatype: U16 */
  CI_RR_SVCB_PRIORITY = (CI_REC_TYPE_SVCB * 100) + 1,
  /*! SVCB Record. TargetName. Datatype: NAME */
  CI_RR_SVCB_TARGET = (CI_REC_TYPE_SVCB * 100) + 2,
  /*! SVCB Record. SvcParams. Datatype: OPT */
  CI_RR_SVCB_PARAMS = (CI_REC_TYPE_SVCB * 100) + 3,
  /*! HTTPS Record. SvcPriority. Datatype: U16 */
  CI_RR_HTTPS_PRIORITY = (CI_REC_TYPE_HTTPS * 100) + 1,
  /*! HTTPS Record. TargetName. Datatype: NAME */
  CI_RR_HTTPS_TARGET = (CI_REC_TYPE_HTTPS * 100) + 2,
  /*! HTTPS Record. SvcParams. Datatype: OPT */
  CI_RR_HTTPS_PARAMS = (CI_REC_TYPE_HTTPS * 100) + 3,
  /*! URI Record. Priority. Datatype: U16 */
  CI_RR_URI_PRIORITY = (CI_REC_TYPE_URI * 100) + 1,
  /*! URI Record. Weight. Datatype: U16 */
  CI_RR_URI_WEIGHT = (CI_REC_TYPE_URI * 100) + 2,
  /*! URI Record. Target domain. Datatype: NAME */
  CI_RR_URI_TARGET = (CI_REC_TYPE_URI * 100) + 3,
  /*! CAA Record. Critical flag. Datatype: U8 */
  CI_RR_CAA_CRITICAL = (CI_REC_TYPE_CAA * 100) + 1,
  /*! CAA Record. Tag/Property. Datatype: STR */
  CI_RR_CAA_TAG = (CI_REC_TYPE_CAA * 100) + 2,
  /*! CAA Record. Value. Datatype: BINP */
  CI_RR_CAA_VALUE = (CI_REC_TYPE_CAA * 100) + 3,
  /*! RAW Record. RR Type. Datatype: U16 */
  CI_RR_RAW_RR_TYPE = (CI_REC_TYPE_RAW_RR * 100) + 1,
  /*! RAW Record. RR Data. Datatype: BIN */
  CI_RR_RAW_RR_DATA = (CI_REC_TYPE_RAW_RR * 100) + 2
} ci_dns_rr_key_t;

/*! TLSA Record CI_RR_TLSA_CERT_USAGE known values */
typedef enum {
  /*! Certificate Usage 0. CA Constraint. */
  CI_TLSA_USAGE_CA = 0,
  /*! Certificate Usage 1. Service Certificate Constraint. */
  CI_TLSA_USAGE_SERVICE = 1,
  /*! Certificate Usage 2. Trust Anchor Assertion. */
  CI_TLSA_USAGE_TRUSTANCHOR = 2,
  /*! Certificate Usage 3. Domain-issued certificate. */
  CI_TLSA_USAGE_DOMAIN = 3
} ci_tlsa_usage_t;

/*! TLSA Record CI_RR_TLSA_SELECTOR known values */
typedef enum {
  /*! Full Certificate */
  CI_TLSA_SELECTOR_FULL = 0,
  /*! DER-encoded SubjectPublicKeyInfo */
  CI_TLSA_SELECTOR_SUBJPUBKEYINFO = 1
} ci_tlsa_selector_t;

/*! TLSA Record CI_RR_TLSA_MATCH known values */
typedef enum {
  /*! Exact match */
  CI_TLSA_MATCH_EXACT = 0,
  /*! Sha256 match */
  CI_TLSA_MATCH_SHA256 = 1,
  /*! Sha512 match */
  CI_TLSA_MATCH_SHA512 = 2
} ci_tlsa_match_t;

/*! SVCB (and HTTPS) RR known parameters */
typedef enum {
  /*! Mandatory keys in this RR (RFC 9460 Section 8) */
  CI_SVCB_PARAM_MANDATORY = 0,
  /*! Additional supported protocols (RFC 9460 Section 7.1) */
  CI_SVCB_PARAM_ALPN = 1,
  /*! No support for default protocol (RFC 9460 Section 7.1) */
  CI_SVCB_PARAM_NO_DEFAULT_ALPN = 2,
  /*! Port for alternative endpoint (RFC 9460 Section 7.2) */
  CI_SVCB_PARAM_PORT = 3,
  /*! IPv4 address hints (RFC 9460 Section 7.3) */
  CI_SVCB_PARAM_IPV4HINT = 4,
  /*! RESERVED (held for Encrypted ClientHello) */
  CI_SVCB_PARAM_ECH = 5,
  /*! IPv6 address hints (RFC 9460 Section 7.3) */
  CI_SVCB_PARAM_IPV6HINT = 6
} ci_svcb_param_t;

/*! OPT RR known parameters */
typedef enum {
  /*! RFC 8764. Apple's DNS Long-Lived Queries Protocol */
  CI_OPT_PARAM_LLQ = 1,
  /*! http://files.dns-sd.org/draft-sekar-dns-ul.txt: Update Lease */
  CI_OPT_PARAM_UL = 2,
  /*! RFC 5001. Name Server Identification */
  CI_OPT_PARAM_NSID = 3,
  /*! RFC 6975. DNSSEC Algorithm Understood */
  CI_OPT_PARAM_DAU = 5,
  /*! RFC 6975. DS Hash Understood */
  CI_OPT_PARAM_DHU = 6,
  /*! RFC 6975. NSEC3 Hash Understood */
  CI_OPT_PARAM_N3U = 7,
  /*! RFC 7871. Client Subnet */
  CI_OPT_PARAM_EDNS_CLIENT_SUBNET = 8,
  /*! RFC 7314. Expire Timer */
  CI_OPT_PARAM_EDNS_EXPIRE = 9,
  /*! RFC 7873. Client and Server Cookies */
  CI_OPT_PARAM_COOKIE = 10,
  /*! RFC 7828. TCP Keepalive timeout */
  CI_OPT_PARAM_EDNS_TCP_KEEPALIVE = 11,
  /*! RFC 7830. Padding */
  CI_OPT_PARAM_PADDING = 12,
  /*! RFC 7901. Chain query requests */
  CI_OPT_PARAM_CHAIN = 13,
  /*! RFC 8145. Signaling Trust Anchor Knowledge in DNSSEC */
  CI_OPT_PARAM_EDNS_KEY_TAG = 14,
  /*! RFC 8914. Extended ERROR code and message */
  CI_OPT_PARAM_EXTENDED_DNS_ERROR = 15
} ci_opt_param_t;

/*! Data type for option records for keys like CI_RR_OPT_OPTIONS and
 *  CI_RR_HTTPS_PARAMS returned by ci_dns_opt_get_datatype() */
typedef enum {
  /*! No value allowed for this option */
  CI_OPT_DATATYPE_NONE = 1,
  /*! List of strings, each prefixed with a single octet representing the length
   */
  CI_OPT_DATATYPE_STR_LIST = 2,
  /*! List of 8bit integers, concatenated */
  CI_OPT_DATATYPE_U8_LIST = 3,
  /*! 16bit integer in network byte order */
  CI_OPT_DATATYPE_U16 = 4,
  /*! list of 16bit integer in network byte order, concatenated. */
  CI_OPT_DATATYPE_U16_LIST = 5,
  /*! 32bit integer in network byte order */
  CI_OPT_DATATYPE_U32 = 6,
  /*! list 32bit integer in network byte order, concatenated */
  CI_OPT_DATATYPE_U32_LIST = 7,
  /*! List of ipv4 addresses in network byte order, concatenated */
  CI_OPT_DATATYPE_INADDR4_LIST = 8,
  /*! List of ipv6 addresses in network byte order, concatenated */
  CI_OPT_DATATYPE_INADDR6_LIST = 9,
  /*! Binary Data */
  CI_OPT_DATATYPE_BIN = 10,
  /*! DNS Domain Name Format */
  CI_OPT_DATATYPE_NAME = 11
} ci_dns_opt_datatype_t;

/*! Data type for flags to ci_dns_parse() */
typedef enum {
  /*! Parse Answers from RFC 1035 that allow name compression as RAW */
  CI_DNS_PARSE_AN_BASE_RAW = 1 << 0,
  /*! Parse Authority from RFC 1035 that allow name compression as RAW */
  CI_DNS_PARSE_NS_BASE_RAW = 1 << 1,
  /*! Parse Additional from RFC 1035 that allow name compression as RAW */
  CI_DNS_PARSE_AR_BASE_RAW = 1 << 2,
  /*! Parse Answers from later RFCs (no name compression) RAW */
  CI_DNS_PARSE_AN_EXT_RAW = 1 << 3,
  /*! Parse Authority from later RFCs (no name compression) as RAW */
  CI_DNS_PARSE_NS_EXT_RAW = 1 << 4,
  /*! Parse Additional from later RFCs (no name compression) as RAW */
  CI_DNS_PARSE_AR_EXT_RAW = 1 << 5
} ci_dns_parse_flags_t;

/*! String representation of DNS Record Type
 *
 *  \param[in] type  DNS Record Type
 *  \return string
 */
CI_EXTERN const char *ci_dns_rec_type_tostr(ci_dns_rec_type_t type);

/*! String representation of DNS Class
 *
 *  \param[in] qclass  DNS Class
 *  \return string
 */
CI_EXTERN const char *ci_dns_class_tostr(ci_dns_class_t qclass);

/*! String representation of DNS OpCode
 *
 *  \param[in] opcode  DNS OpCode
 *  \return string
 */
CI_EXTERN const char *ci_dns_opcode_tostr(ci_dns_opcode_t opcode);

/*! String representation of DNS Resource Record Parameter
 *
 *  \param[in] key  DNS Resource Record parameter
 *  \return string
 */
CI_EXTERN const char *ci_dns_rr_key_tostr(ci_dns_rr_key_t key);

/*! String representation of DNS Resource Record section
 *
 * \param[in] section  Section
 * \return string
 */
CI_EXTERN const char *ci_dns_section_tostr(ci_dns_section_t section);

/*! Convert DNS class name as string to ci_dns_class_t
 *
 *  \param[out] qclass  Pointer passed by reference to write class
 *  \param[in]  str     String to convert
 *  \return CI_TRUE on success
 */
CI_EXTERN ci_bool_t ci_dns_class_fromstr(ci_dns_class_t *qclass,
                                                const char       *str);

/*! Convert DNS record type as string to ci_dns_rec_type_t
 *
 *  \param[out] qtype   Pointer passed by reference to write record type
 *  \param[in]  str     String to convert
 *  \return CI_TRUE on success
 */
CI_EXTERN ci_bool_t ci_dns_rec_type_fromstr(ci_dns_rec_type_t *qtype,
                                                   const char          *str);


/*! Convert DNS response code as string to from ci_dns_rcode_t
 *
 *  \param[in] rcode  Response code to convert
 *  \return CI_TRUE on success
 */
CI_EXTERN const char *ci_dns_rcode_tostr(ci_dns_rcode_t rcode);

/*! Convert any valid ip address (ipv4 or ipv6) into struct ci_addr and
 *  return the starting pointer of the network byte order address and the
 *  length of the address (4 or 16).
 *
 *  \param[in]     ipaddr  ASCII string form of the ip address
 *  \param[in,out] addr    Must set "family" member to one of AF_UNSPEC,
 *                         AF_INET, AF_INET6 on input.
 *  \param[out]    out_len Length of binary form address
 *  \return Pointer to start of binary address or NULL on error.
 */
CI_EXTERN const void *ci_dns_pton(const char       *ipaddr,
                                       struct ci_addr *addr, size_t *out_len);

/*! Convert an ip address into the PTR format for in-addr.arpa or in6.arpa
 *
 *  \param[in]  addr  properly filled address structure
 *  \return  String representing PTR, use ci_free_string() to free
 */
CI_EXTERN char       *ci_dns_addr_to_ptr(const struct ci_addr *addr);


/*! The options/parameters extensions to some RRs can be somewhat opaque, this
 *  is a helper to return the best match for a datatype for interpreting the
 *  option record.
 *
 *  \param[in] key  Key associated with options/parameters
 *  \param[in] opt  Option Key/Parameter
 *  \return Datatype
 */
CI_EXTERN ci_dns_opt_datatype_t
  ci_dns_opt_get_datatype(ci_dns_rr_key_t key, unsigned short opt);

/*! The options/parameters extensions to some RRs can be somewhat opaque, this
 *  is a helper to return the name if the option is known.
 *
 *  \param[in] key  Key associated with options/parameters
 *  \param[in] opt  Option Key/Parameter
 *  \return name, or NULL if not known.
 */
CI_EXTERN const char *ci_dns_opt_get_name(ci_dns_rr_key_t key,
                                               unsigned short    opt);


/*! Retrieve a list of Resource Record keys that can be set or retrieved for
 *  the Resource record type.
 *
 *  \param[in]  type  Record Type
 *  \param[out] cnt   Number of keys returned
 *  \return array of keys associated with Resource Record
 */
CI_EXTERN const ci_dns_rr_key_t *
  ci_dns_rr_get_keys(ci_dns_rec_type_t type, size_t *cnt);

/*! Retrieve the datatype associated with a Resource Record key.
 *
 *  \param[in] key   Resource Record Key
 *  \return datatype
 */
CI_EXTERN ci_dns_datatype_t
  ci_dns_rr_key_datatype(ci_dns_rr_key_t key);

/*! Retrieve the DNS Resource Record type associated with a Resource Record key.
 *
 *  \param[in] key   Resource Record Key
 *  \return DNS Resource Record Type
 */
CI_EXTERN ci_dns_rec_type_t
  ci_dns_rr_key_to_rec_type(ci_dns_rr_key_t key);

/*! Opaque data type representing a DNS RR (Resource Record) */
struct ci_dns_rr;

/*! Typedef for opaque data type representing a DNS RR (Resource Record) */
typedef struct ci_dns_rr ci_dns_rr_t;

/*! Opaque data type representing a DNS Query Data QD Packet */
struct ci_dns_qd;

/*! Typedef for opaque data type representing a DNS Query Data QD Packet */
typedef struct ci_dns_qd ci_dns_qd_t;

/*! Opaque data type representing a DNS Packet */
struct ci_dns_record;

/*! Typedef for opaque data type representing a DNS Packet */
typedef struct ci_dns_record ci_dns_record_t;


/*! Create a new DNS record object
 *
 *  \param[out] dnsrec  Pointer passed by reference for a newly allocated
 *                      record object.  Must be ci_dns_record_destroy()'d by
 *                      caller.
 *  \param[in]  id      DNS Query ID.  If structuring a new query to be sent
 *                      with ci_send(), this value should be zero.
 *  \param[in]  flags   DNS Flags from \ci_dns_flags_t
 *  \param[in]  opcode  DNS OpCode (typically CI_OPCODE_QUERY)
 *  \param[in]  rcode   DNS RCode
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_record_create(ci_dns_record_t **dnsrec,
                                                  unsigned short      id,
                                                  unsigned short      flags,
                                                  ci_dns_opcode_t   opcode,
                                                  ci_dns_rcode_t    rcode);

/*! Destroy a DNS record object
 *
 *  \param[in] dnsrec  Initialized record object
 */
CI_EXTERN void          ci_dns_record_destroy(ci_dns_record_t *dnsrec);

/*! Get the DNS Query ID
 *
 *  \param[in] dnsrec  Initialized record object
 *  \return DNS query id
 */
CI_EXTERN unsigned short
  ci_dns_record_get_id(const ci_dns_record_t *dnsrec);

/*! Overwrite the DNS query id
 *
 * \param[in] dnsrec  Initialized record object
 * \param[in] id      DNS query id
 * \return CI_TRUE on success, CI_FALSE on usage error
 */
CI_EXTERN ci_bool_t ci_dns_record_set_id(ci_dns_record_t *dnsrec,
                                                unsigned short     id);

/*! Get the DNS Record Flags
 *
 *  \param[in] dnsrec  Initialized record object
 *  \return One or more \ci_dns_flags_t
 */
CI_EXTERN unsigned short
  ci_dns_record_get_flags(const ci_dns_record_t *dnsrec);

/*! Get the DNS Record OpCode
 *
 *  \param[in] dnsrec  Initialized record object
 *  \return opcode
 */
CI_EXTERN ci_dns_opcode_t
  ci_dns_record_get_opcode(const ci_dns_record_t *dnsrec);

/*! Get the DNS Record RCode
 *
 *  \param[in] dnsrec  Initialized record object
 *  \return rcode
 */
CI_EXTERN ci_dns_rcode_t
  ci_dns_record_get_rcode(const ci_dns_record_t *dnsrec);

/*! Add a query to the DNS Record.  Typically a record will have only 1
 *  query. Most DNS servers will reject queries with more than 1 question.
 *
 * \param[in] dnsrec  Initialized record object
 * \param[in] name    Name/Hostname of request
 * \param[in] qtype   Type of query
 * \param[in] qclass  Class of query (typically CI_CLASS_IN)
 * \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_record_query_add(ci_dns_record_t  *dnsrec,
                                                     const char         *name,
                                                     ci_dns_rec_type_t qtype,
                                                     ci_dns_class_t qclass);

/*! Replace the question name with a new name.  This may be used when performing
 *  a search with aliases.
 *
 *  Note that this will invalidate the name pointer returned from
 *  ci_dns_record_query_get().
 *
 * \param[in] dnsrec  Initialized record object
 * \param[in] idx     Index of question (typically 0)
 * \param[in] name    Name to use as replacement.
 * \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_record_query_set_name(
  ci_dns_record_t *dnsrec, size_t idx, const char *name);


/*! Replace the question type with a different type.  This may be used when
 *  needing to query more than one address class (e.g. A and AAAA)
 *
 * \param[in] dnsrec  Initialized record object
 * \param[in] idx     Index of question (typically 0)
 * \param[in] qtype   Record Type to use as replacement.
 * \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_record_query_set_type(
  ci_dns_record_t *dnsrec, size_t idx, ci_dns_rec_type_t qtype);

/*! Get the count of queries in the DNS Record
 *
 * \param[in] dnsrec  Initialized record object
 * \return count of queries
 */
CI_EXTERN size_t ci_dns_record_query_cnt(const ci_dns_record_t *dnsrec);

/*! Get the data about the query at the provided index.
 *
 * \param[in]  dnsrec  Initialized record object
 * \param[in]  idx     Index of query
 * \param[out] name    Optional.  Returns name, may pass NULL if not desired.
 *                     This pointer will be invalided by any call to
 *                     ci_dns_record_query_set_name().
 * \param[out] qtype   Optional.  Returns record type, may pass NULL.
 * \param[out] qclass  Optional.  Returns class, may pass NULL.
 * \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_record_query_get(
  const ci_dns_record_t *dnsrec, size_t idx, const char **name,
  ci_dns_rec_type_t *qtype, ci_dns_class_t *qclass);

/*! Get the count of Resource Records in the provided section
 *
 * \param[in] dnsrec  Initialized record object
 * \param[in] sect    Section.  CI_SECTION_ANSWER is most used.
 * \return count of resource records.
 */
CI_EXTERN size_t ci_dns_record_rr_cnt(const ci_dns_record_t *dnsrec,
                                           ci_dns_section_t       sect);


/*! Add a Resource Record to the DNS Record.
 *
 *  \param[out] rr_out   Pointer to created resource record.  This pointer
 *                       is owned by the DNS record itself, this is just made
 *                       available to facilitate adding RR-specific fields.
 *  \param[in]  dnsrec   Initialized record object
 *  \param[in]  sect     Section to add resource record to
 *  \param[in]  name     Resource Record name/hostname
 *  \param[in]  type     Record Type
 *  \param[in]  rclass   Class
 *  \param[in]  ttl      TTL
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_record_rr_add(
  ci_dns_rr_t **rr_out, ci_dns_record_t *dnsrec, ci_dns_section_t sect,
  const char *name, ci_dns_rec_type_t type, ci_dns_class_t rclass,
  unsigned int ttl);

/*! Fetch a writable resource record based on the section and index.
 *
 *  \param[in]  dnsrec   Initialized record object
 *  \param[in]  sect     Section for resource record
 *  \param[in]  idx      Index of resource record in section
 *  \return NULL on misuse, otherwise a writable pointer to the resource record
 */
CI_EXTERN ci_dns_rr_t *ci_dns_record_rr_get(ci_dns_record_t *dnsrec,
                                                   ci_dns_section_t sect,
                                                   size_t             idx);

/*! Fetch a non-writeable resource record based on the section and index.
 *
 *  \param[in]  dnsrec   Initialized record object
 *  \param[in]  sect     Section for resource record
 *  \param[in]  idx      Index of resource record in section
 *  \return NULL on misuse, otherwise a const pointer to the resource record
 */
CI_EXTERN const ci_dns_rr_t *
  ci_dns_record_rr_get_const(const ci_dns_record_t *dnsrec,
                               ci_dns_section_t sect, size_t idx);


/*! Remove the resource record based on the section and index
 *
 *  \param[in]  dnsrec   Initialized record object
 *  \param[in]  sect     Section for resource record
 *  \param[in]  idx      Index of resource record in section
 *  \return CI_SUCCESS on success, otherwise an error code.
 */
CI_EXTERN ci_status_t ci_dns_record_rr_del(ci_dns_record_t *dnsrec,
                                                  ci_dns_section_t sect,
                                                  size_t             idx);


/*! Retrieve the resource record Name/Hostname
 *
 *  \param[in] rr  Pointer to resource record
 *  \return Name
 */
CI_EXTERN const char   *ci_dns_rr_get_name(const ci_dns_rr_t *rr);

/*! Retrieve the resource record type
 *
 *  \param[in] rr  Pointer to resource record
 *  \return type
 */
CI_EXTERN ci_dns_rec_type_t ci_dns_rr_get_type(const ci_dns_rr_t *rr);

/*! Retrieve the resource record class
 *
 *  \param[in] rr  Pointer to resource record
 *  \return class
 */
CI_EXTERN ci_dns_class_t    ci_dns_rr_get_class(const ci_dns_rr_t *rr);

/*! Retrieve the resource record TTL
 *
 *  \param[in] rr  Pointer to resource record
 *  \return TTL
 */
CI_EXTERN unsigned int        ci_dns_rr_get_ttl(const ci_dns_rr_t *rr);

/*! Set ipv4 address data type for specified resource record and key.  Can
 *  only be used on keys with datatype CI_DATATYPE_INADDR
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \param[in] addr   Pointer to ipv4 address to use.
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t       ci_dns_rr_set_addr(ci_dns_rr_t        *dns_rr,
                                                      ci_dns_rr_key_t     key,
                                                      const struct in_addr *addr);

/*! Set ipv6 address data type for specified resource record and key.  Can
 *  only be used on keys with datatype CI_DATATYPE_INADDR6
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \param[in] addr   Pointer to ipv6 address to use.
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t
  ci_dns_rr_set_addr6(ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                        const struct ci_in6_addr *addr);

/*! Set string data for specified resource record and key.  Can
 *  only be used on keys with datatype CI_DATATYPE_STR or CI_DATATYPE_NAME.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \param[in] val    Pointer to string to set.
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_rr_set_str(ci_dns_rr_t    *dns_rr,
                                               ci_dns_rr_key_t key,
                                               const char       *val);

/*! Set 8bit unsigned integer for specified resource record and key.  Can
 *  only be used on keys with datatype CI_DATATYPE_U8
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \param[in] val    8bit unsigned integer
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_rr_set_u8(ci_dns_rr_t    *dns_rr,
                                              ci_dns_rr_key_t key,
                                              unsigned char     val);

/*! Set 16bit unsigned integer for specified resource record and key.  Can
 *  only be used on keys with datatype CI_DATATYPE_U16
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \param[in] val    16bit unsigned integer
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_rr_set_u16(ci_dns_rr_t    *dns_rr,
                                               ci_dns_rr_key_t key,
                                               unsigned short    val);

/*! Set 32bit unsigned integer for specified resource record and key.  Can
 *  only be used on keys with datatype CI_DATATYPE_U32
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \param[in] val    32bit unsigned integer
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_rr_set_u32(ci_dns_rr_t    *dns_rr,
                                               ci_dns_rr_key_t key,
                                               unsigned int      val);

/*! Set binary (BIN or BINP) data for specified resource record and key.  Can
 *  only be used on keys with datatype CI_DATATYPE_BIN or CI_DATATYPE_BINP.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \param[in] val    Pointer to binary data.
 *  \param[in] len    Length of binary data
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_rr_set_bin(ci_dns_rr_t       *dns_rr,
                                               ci_dns_rr_key_t    key,
                                               const unsigned char *val,
                                               size_t               len);

/*! Add binary array value (ABINP) data for specified resource record and key.
 *  Can only be used on keys with datatype CI_DATATYPE_ABINP.  The value will
 *  Be added as the last element in the array.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \param[in] val    Pointer to binary data.
 *  \param[in] len    Length of binary data
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_rr_add_abin(ci_dns_rr_t       *dns_rr,
                                                ci_dns_rr_key_t    key,
                                                const unsigned char *val,
                                                size_t               len);

/*! Delete binary array value (ABINP) data for specified resource record and
 *  key by specified index. Can only be used on keys with datatype
 *  CI_DATATYPE_ABINP.  The value at the index will be deleted.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \param[in] idx    Index to delete
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_rr_del_abin(ci_dns_rr_t    *dns_rr,
                                                ci_dns_rr_key_t key,
                                                size_t            idx);

/*! Set the option for the RR
 *
 *  \param[in]  dns_rr   Pointer to resource record
 *  \param[in]  key      DNS Resource Record Key
 *  \param[in]  opt      Option record key id.
 *  \param[out] val      Optional. Value to associate with option.
 *  \param[out] val_len  Length of value passed.
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_rr_set_opt(ci_dns_rr_t       *dns_rr,
                                               ci_dns_rr_key_t    key,
                                               unsigned short       opt,
                                               const unsigned char *val,
                                               size_t               val_len);

/*! Delete the option for the RR by id
 *
 *  \param[in] dns_rr   Pointer to resource record
 *  \param[in] key      DNS Resource Record Key
 *  \param[in] opt      Option record key id.
 *  \return CI_SUCCESS if removed, CI_ENOTFOUND if not found
 */
CI_EXTERN ci_status_t ci_dns_rr_del_opt_byid(ci_dns_rr_t    *dns_rr,
                                                    ci_dns_rr_key_t key,
                                                    unsigned short    opt);

/*! Retrieve a pointer to the ipv4 address.  Can only be used on keys with
 *  datatype CI_DATATYPE_INADDR.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \return pointer to ipv4 address or NULL on error
 */
CI_EXTERN const struct in_addr *
  ci_dns_rr_get_addr(const ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key);

/*! Retrieve a pointer to the ipv6 address.  Can only be used on keys with
 *  datatype CI_DATATYPE_INADDR6.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \return pointer to ipv6 address or NULL on error
 */
CI_EXTERN const struct ci_in6_addr *
  ci_dns_rr_get_addr6(const ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key);

/*! Retrieve a pointer to the string.  Can only be used on keys with
 *  datatype CI_DATATYPE_STR and CI_DATATYPE_NAME.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \return pointer string or NULL on error
 */
CI_EXTERN const char    *ci_dns_rr_get_str(const ci_dns_rr_t *dns_rr,
                                                ci_dns_rr_key_t    key);

/*! Retrieve an 8bit unsigned integer.  Can only be used on keys with
 *  datatype CI_DATATYPE_U8.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \return 8bit unsigned integer
 */
CI_EXTERN unsigned char  ci_dns_rr_get_u8(const ci_dns_rr_t *dns_rr,
                                               ci_dns_rr_key_t    key);

/*! Retrieve an 16bit unsigned integer.  Can only be used on keys with
 *  datatype CI_DATATYPE_U16.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \return 16bit unsigned integer
 */
CI_EXTERN unsigned short ci_dns_rr_get_u16(const ci_dns_rr_t *dns_rr,
                                                ci_dns_rr_key_t    key);

/*! Retrieve an 32bit unsigned integer.  Can only be used on keys with
 *  datatype CI_DATATYPE_U32.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \return 32bit unsigned integer
 */
CI_EXTERN unsigned int   ci_dns_rr_get_u32(const ci_dns_rr_t *dns_rr,
                                                ci_dns_rr_key_t    key);

/*! Retrieve a pointer to the binary data.  Can only be used on keys with
 *  datatype CI_DATATYPE_BIN, CI_DATATYPE_BINP, or CI_DATATYPE_ABINP.
 *  If BINP or ABINP, the data is guaranteed to have a NULL terminator which
 *  is NOT included in the length.
 *
 *  \param[in]  dns_rr Pointer to resource record
 *  \param[in]  key    DNS Resource Record Key
 *  \param[out] len    Length of binary data returned
 *  \return pointer binary data or NULL on error
 */
CI_EXTERN const unsigned char *
  ci_dns_rr_get_bin(const ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                      size_t *len);

/*! Retrieve the count of the array of stored binary values. Can only be used on
 *  keys with datatype CI_DATATYPE_ABINP.
 *
 *  \param[in]  dns_rr Pointer to resource record
 *  \param[in]  key    DNS Resource Record Key
 *  \return count of values
 */
CI_EXTERN size_t ci_dns_rr_get_abin_cnt(const ci_dns_rr_t *dns_rr,
                                             ci_dns_rr_key_t    key);

/*! Retrieve a pointer to the binary array data from the specified index.  Can
 *  only be used on keys with datatype CI_DATATYPE_ABINP.  If ABINP, the data
 *  is guaranteed to have a NULL terminator which is NOT included in the length.
 *  If want all array membersconcatenated, may use ci_dns_rr_get_bin()
 *  instead.
 *
 *  \param[in]  dns_rr Pointer to resource record
 *  \param[in]  key    DNS Resource Record Key
 *  \param[in]  idx    Index of value to retrieve
 *  \param[out] len    Length of binary data returned
 *  \return pointer binary data or NULL on error
 */
CI_EXTERN const unsigned char *
  ci_dns_rr_get_abin(const ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                       size_t idx, size_t *len);


/*! Retrieve the number of options stored for the RR.
 *
 *  \param[in] dns_rr Pointer to resource record
 *  \param[in] key    DNS Resource Record Key
 *  \return count, or 0 if none.
 */
CI_EXTERN size_t ci_dns_rr_get_opt_cnt(const ci_dns_rr_t *dns_rr,
                                            ci_dns_rr_key_t    key);

/*! Retrieve the option for the RR by index.
 *
 *  \param[in]  dns_rr  Pointer to resource record
 *  \param[in]  key     DNS Resource Record Key
 *  \param[in]  idx     Index of option record
 *  \param[out] val     Optional. Pointer passed by reference to hold value.
 *                      Options may not have values.  Value if returned is
 *                      guaranteed to be NULL terminated, however in most
 *                      cases it is not printable.
 *  \param[out] val_len Optional. Pointer passed by reference to hold value
 *                      length.
 *  \return option key/id on success, 65535 on misuse.
 */
CI_EXTERN unsigned short
  ci_dns_rr_get_opt(const ci_dns_rr_t *dns_rr, ci_dns_rr_key_t key,
                      size_t idx, const unsigned char **val, size_t *val_len);

/*! Retrieve the option for the RR by the option key/id.
 *
 *  \param[in]  dns_rr  Pointer to resource record
 *  \param[in]  key     DNS Resource Record Key
 *  \param[in]  opt     Option record key id (this is not the index).
 *  \param[out] val     Optional. Pointer passed by reference to hold value.
 *                      Options may not have values. Value if returned is
 *                      guaranteed to be NULL terminated, however in most cases
 *                      it is not printable.
 *  \param[out] val_len Optional. Pointer passed by reference to hold value
 *                      length.
 *  \return CI_TRUE on success, CI_FALSE on misuse.
 */
CI_EXTERN ci_bool_t   ci_dns_rr_get_opt_byid(const ci_dns_rr_t  *dns_rr,
                                                    ci_dns_rr_key_t     key,
                                                    unsigned short        opt,
                                                    const unsigned char **val,
                                                    size_t *val_len);

/*! Parse a complete DNS message.
 *
 *  \param[in]  buf      pointer to bytes to be parsed
 *  \param[in]  buf_len  Length of buf provided
 *  \param[in]  flags    Flags dictating how the message should be parsed.
 *  \param[out] dnsrec   Pointer passed by reference for a new DNS record object
 *                       that must be ci_dns_record_destroy()'d by caller.
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_parse(const unsigned char *buf,
                                          size_t buf_len, unsigned int flags,
                                          ci_dns_record_t **dnsrec);

/*! Write a complete DNS message
 *
 *  \param[in]  dnsrec   Pointer to initialized and filled DNS record object.
 *  \param[out] buf      Pointer passed by reference to be filled in with with
 *                       DNS message.  Must be ci_free()'d by caller.
 *  \param[out] buf_len  Length of returned buffer containing DNS message.
 *  \return CI_SUCCESS on success
 */
CI_EXTERN ci_status_t ci_dns_write(const ci_dns_record_t *dnsrec,
                                          unsigned char **buf, size_t *buf_len);


/*! Duplicate a complete DNS message.  This does not copy internal members
 *  (such as the ttl decrement capability).
 *
 *  \param[in] dnsrec Pointer to initialized and filled DNS record object.
 *  \return duplicted DNS record object, or NULL on out of memory.
 */
CI_EXTERN ci_dns_record_t *
  ci_dns_record_duplicate(const ci_dns_record_t *dnsrec);

/*! @} */

#ifdef __cplusplus
}
#endif

#endif /* __CI_DNS_RECORD_H */
