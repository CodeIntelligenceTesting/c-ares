/* MIT License
 *
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
#include <stddef.h>
#include <stdio.h>
#include "ci.h"
#include "include/ci_buf.h"
#include "include/ci_mem.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

#ifdef USE_LEGACY_FUZZERS

/* This implementation calls the legacy c-ci parsers, which historically
 * all used different logic and parsing.  As of c-ci 1.21.0 these are
 * simply wrappers around a single parser, and simply convert the parsed
 * DNS response into the data structures the legacy parsers used which is a
 * small amount of code and not likely going to vary based on the input data.
 *
 * Instead, these days, it makes more sense to test the new parser directly
 * instead of calling it 10 or 11 times with the same input data to speed up
 * the number of iterations per second the fuzzer can perform.
 *
 * We are keeping this legacy fuzzer test for historic reasons or if someone
 * finds them of use.
 */

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  /* Feed the data into each of the ci_parse_*_reply functions. */
  struct hostent          *host = NULL;
  struct ci_addrttl      info[5];
  struct ci_addr6ttl     info6[5];
  unsigned char            addrv4[4] = { 0x10, 0x20, 0x30, 0x40 };
  struct ci_srv_reply   *srv       = NULL;
  struct ci_mx_reply    *mx        = NULL;
  struct ci_txt_reply   *txt       = NULL;
  struct ci_soa_reply   *soa       = NULL;
  struct ci_naptr_reply *naptr     = NULL;
  struct ci_caa_reply   *caa       = NULL;
  struct ci_uri_reply   *uri       = NULL;
  int                      count     = 5;
  ci_parse_a_reply(data, (int)size, &host, info, &count);
  if (host) {
    ci_free_hostent(host);
  }

  host  = NULL;
  count = 5;
  ci_parse_aaaa_reply(data, (int)size, &host, info6, &count);
  if (host) {
    ci_free_hostent(host);
  }

  host = NULL;
  ci_parse_ptr_reply(data, (int)size, addrv4, sizeof(addrv4), AF_INET, &host);
  if (host) {
    ci_free_hostent(host);
  }

  host = NULL;
  ci_parse_ns_reply(data, (int)size, &host);
  if (host) {
    ci_free_hostent(host);
  }

  ci_parse_srv_reply(data, (int)size, &srv);
  if (srv) {
    ci_free_data(srv);
  }

  ci_parse_mx_reply(data, (int)size, &mx);
  if (mx) {
    ci_free_data(mx);
  }

  ci_parse_txt_reply(data, (int)size, &txt);
  if (txt) {
    ci_free_data(txt);
  }

  ci_parse_soa_reply(data, (int)size, &soa);
  if (soa) {
    ci_free_data(soa);
  }

  ci_parse_naptr_reply(data, (int)size, &naptr);
  if (naptr) {
    ci_free_data(naptr);
  }

  ci_parse_caa_reply(data, (int)size, &caa);
  if (caa) {
    ci_free_data(caa);
  }

  ci_parse_uri_reply(data, (int)size, &uri);
  if (uri) {
    ci_free_data(uri);
  }

  return 0;
}

#else

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  ci_dns_record_t *dnsrec    = NULL;
  char              *printdata = NULL;
  ci_buf_t        *printmsg  = NULL;
  size_t             i;
  unsigned char     *datadup     = NULL;
  size_t             datadup_len = 0;

  /* There is never a reason to have a size > 65535, it is immediately
   * rejected by the parser */
  if (size > 65535) {
    return -1;
  }

  if (ci_dns_parse(data, size, 0, &dnsrec) != CI_SUCCESS) {
    goto done;
  }

  /* Lets test the message fetchers */
  printmsg = ci_buf_create();
  if (printmsg == NULL) {
    goto done;
  }

  ci_buf_append_str(printmsg, ";; ->>HEADER<<- opcode: ");
  ci_buf_append_str(
    printmsg, ci_dns_opcode_tostr(ci_dns_record_get_opcode(dnsrec)));
  ci_buf_append_str(printmsg, ", status: ");
  ci_buf_append_str(printmsg,
                      ci_dns_rcode_tostr(ci_dns_record_get_rcode(dnsrec)));
  ci_buf_append_str(printmsg, ", id: ");
  ci_buf_append_num_dec(printmsg, (size_t)ci_dns_record_get_id(dnsrec), 0);
  ci_buf_append_str(printmsg, "\n;; flags: ");
  ci_buf_append_num_hex(printmsg, (size_t)ci_dns_record_get_flags(dnsrec),
                          0);
  ci_buf_append_str(printmsg, "; QUERY: ");
  ci_buf_append_num_dec(printmsg, ci_dns_record_query_cnt(dnsrec), 0);
  ci_buf_append_str(printmsg, ", ANSWER: ");
  ci_buf_append_num_dec(
    printmsg, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER), 0);
  ci_buf_append_str(printmsg, ", AUTHORITY: ");
  ci_buf_append_num_dec(
    printmsg, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_AUTHORITY), 0);
  ci_buf_append_str(printmsg, ", ADDITIONAL: ");
  ci_buf_append_num_dec(
    printmsg, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ADDITIONAL), 0);
  ci_buf_append_str(printmsg, "\n\n");
  ci_buf_append_str(printmsg, ";; QUESTION SECTION:\n");
  for (i = 0; i < ci_dns_record_query_cnt(dnsrec); i++) {
    const char         *name;
    ci_dns_rec_type_t qtype;
    ci_dns_class_t    qclass;

    if (ci_dns_record_query_get(dnsrec, i, &name, &qtype, &qclass) !=
        CI_SUCCESS) {
      goto done;
    }

    ci_buf_append_str(printmsg, ";");
    ci_buf_append_str(printmsg, name);
    ci_buf_append_str(printmsg, ".\t\t\t");
    ci_buf_append_str(printmsg, ci_dns_class_tostr(qclass));
    ci_buf_append_str(printmsg, "\t");
    ci_buf_append_str(printmsg, ci_dns_rec_type_tostr(qtype));
    ci_buf_append_str(printmsg, "\n");
  }
  ci_buf_append_str(printmsg, "\n");
  for (i = CI_SECTION_ANSWER; i < CI_SECTION_ADDITIONAL + 1; i++) {
    size_t j;

    ci_buf_append_str(printmsg, ";; ");
    ci_buf_append_str(printmsg,
                        ci_dns_section_tostr((ci_dns_section_t)i));
    ci_buf_append_str(printmsg, " SECTION:\n");
    for (j = 0; j < ci_dns_record_rr_cnt(dnsrec, (ci_dns_section_t)i);
         j++) {
      size_t                   keys_cnt = 0;
      const ci_dns_rr_key_t *keys     = NULL;
      ci_dns_rr_t           *rr       = NULL;
      size_t                   k;

      rr = ci_dns_record_rr_get(dnsrec, (ci_dns_section_t)i, j);
      ci_buf_append_str(printmsg, ci_dns_rr_get_name(rr));
      ci_buf_append_str(printmsg, ".\t\t\t");
      ci_buf_append_str(printmsg,
                          ci_dns_class_tostr(ci_dns_rr_get_class(rr)));
      ci_buf_append_str(printmsg, "\t");
      ci_buf_append_str(printmsg,
                          ci_dns_rec_type_tostr(ci_dns_rr_get_type(rr)));
      ci_buf_append_str(printmsg, "\t");
      ci_buf_append_num_dec(printmsg, ci_dns_rr_get_ttl(rr), 0);
      ci_buf_append_str(printmsg, "\t");

      keys = ci_dns_rr_get_keys(ci_dns_rr_get_type(rr), &keys_cnt);
      for (k = 0; k < keys_cnt; k++) {
        char buf[256] = "";

        ci_buf_append_str(printmsg, ci_dns_rr_key_tostr(keys[k]));
        ci_buf_append_str(printmsg, "=");
        switch (ci_dns_rr_key_datatype(keys[k])) {
          case CI_DATATYPE_INADDR:
            ci_inet_ntop(AF_INET, ci_dns_rr_get_addr(rr, keys[k]), buf,
                           sizeof(buf));
            ci_buf_append_str(printmsg, buf);
            break;
          case CI_DATATYPE_INADDR6:
            ci_inet_ntop(AF_INET6, ci_dns_rr_get_addr6(rr, keys[k]), buf,
                           sizeof(buf));
            ci_buf_append_str(printmsg, buf);
            break;
          case CI_DATATYPE_U8:
            ci_buf_append_num_dec(printmsg, ci_dns_rr_get_u8(rr, keys[k]),
                                    0);
            break;
          case CI_DATATYPE_U16:
            ci_buf_append_num_dec(printmsg, ci_dns_rr_get_u16(rr, keys[k]),
                                    0);
            break;
          case CI_DATATYPE_U32:
            ci_buf_append_num_dec(printmsg, ci_dns_rr_get_u32(rr, keys[k]),
                                    0);
            break;
          case CI_DATATYPE_NAME:
          case CI_DATATYPE_STR:
            ci_buf_append_byte(printmsg, '"');
            ci_buf_append_str(printmsg, ci_dns_rr_get_str(rr, keys[k]));
            ci_buf_append_byte(printmsg, '"');
            break;
          case CI_DATATYPE_BIN:
            /* TODO */
            break;
          case CI_DATATYPE_BINP:
            {
              size_t templen;
              ci_buf_append_byte(printmsg, '"');
              ci_buf_append_str(printmsg, (const char *)ci_dns_rr_get_bin(
                                              rr, keys[k], &templen));
              ci_buf_append_byte(printmsg, '"');
            }
            break;
          case CI_DATATYPE_ABINP:
            {
              size_t a;
              for (a = 0; a < ci_dns_rr_get_abin_cnt(rr, keys[k]); a++) {
                size_t templen;

                if (a != 0) {
                  ci_buf_append_byte(printmsg, ' ');
                }
                ci_buf_append_byte(printmsg, '"');
                ci_buf_append_str(
                  printmsg,
                  (const char *)ci_dns_rr_get_abin(rr, keys[k], a, &templen));
                ci_buf_append_byte(printmsg, '"');
              }
            }
            break;
          case CI_DATATYPE_OPT:
            /* TODO */
            break;
        }
        ci_buf_append_str(printmsg, " ");
      }
      ci_buf_append_str(printmsg, "\n");
    }
  }
  ci_buf_append_str(printmsg, ";; SIZE: ");
  ci_buf_append_num_dec(printmsg, size, 0);
  ci_buf_append_str(printmsg, "\n\n");

  printdata = ci_buf_finish_str(printmsg, NULL);
  printmsg  = NULL;

  /* Write it back out as a dns message to test writer */
  if (ci_dns_write(dnsrec, &datadup, &datadup_len) != CI_SUCCESS) {
    goto done;
  }

done:
  ci_dns_record_destroy(dnsrec);
  ci_buf_destroy(printmsg);
  ci_free(printdata);
  ci_free(datadup);
  return 0;
}

#endif
