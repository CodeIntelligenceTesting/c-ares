/* MIT License
 *
 * Copyright (c) 2009 Daniel Stenberg
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
#ifndef __CI_DATA_H
#define __CI_DATA_H

typedef enum {
  CI_DATATYPE_UNKNOWN = 1, /* unknown data type     - introduced in 1.7.0 */
  CI_DATATYPE_SRV_REPLY,   /* struct ci_srv_reply - introduced in 1.7.0 */
  CI_DATATYPE_TXT_REPLY,   /* struct ci_txt_reply - introduced in 1.7.0 */
  CI_DATATYPE_TXT_EXT,     /* struct ci_txt_ext   - introduced in 1.11.0 */
  CI_DATATYPE_ADDR_NODE,   /* struct ci_addr_node - introduced in 1.7.1 */
  CI_DATATYPE_MX_REPLY,    /* struct ci_mx_reply   - introduced in 1.7.2 */
  CI_DATATYPE_NAPTR_REPLY, /* struct ci_naptr_reply - introduced in 1.7.6 */
  CI_DATATYPE_SOA_REPLY,   /* struct ci_soa_reply - introduced in 1.9.0 */
  CI_DATATYPE_URI_REPLY,   /* struct ci_uri_reply */
#if 0
  CI_DATATYPE_ADDR6TTL,     /* struct ci_addrttl   */
  CI_DATATYPE_ADDRTTL,      /* struct ci_addr6ttl  */
  CI_DATATYPE_HOSTENT,      /* struct hostent        */
  CI_DATATYPE_OPTIONS,      /* struct ci_options   */
#endif
  CI_DATATYPE_ADDR_PORT_NODE, /* struct ci_addr_port_node - introduced
                                   in 1.11.0 */
  CI_DATATYPE_CAA_REPLY, /* struct ci_caa_reply   - introduced in 1.17 */
  CI_DATATYPE_LAST       /* not used              - introduced in 1.7.0 */
} ci_datatype;

#define CI_DATATYPE_MARK 0xbead

/*
 * ci_data struct definition is internal to c-ci and shall not
 * be exposed by the public API in order to allow future changes
 * and extensions to it without breaking ABI.  This will be used
 * internally by c-ci as the container of multiple types of data
 * dynamically allocated for which a reference will be returned
 * to the calling application.
 *
 * c-ci API functions returning a pointer to c-ci internally
 * allocated data will actually be returning an interior pointer
 * into this ci_data struct.
 *
 * All this is 'invisible' to the calling application, the only
 * requirement is that this kind of data must be free'ed by the
 * calling application using ci_free_data() with the pointer
 * it has received from a previous c-ci function call.
 */

struct ci_data {
  ci_datatype type; /* Actual data type identifier. */
  unsigned int  mark; /* Private ci_data signature. */

  union {
    struct ci_txt_reply      txt_reply;
    struct ci_txt_ext        txt_ext;
    struct ci_srv_reply      srv_reply;
    struct ci_addr_node      addr_node;
    struct ci_addr_port_node addr_port_node;
    struct ci_mx_reply       mx_reply;
    struct ci_naptr_reply    naptr_reply;
    struct ci_soa_reply      soa_reply;
    struct ci_caa_reply      caa_reply;
    struct ci_uri_reply      uri_reply;
  } data;
};

void *ci_malloc_data(ci_datatype type);


#endif /* __CI_DATA_H */
