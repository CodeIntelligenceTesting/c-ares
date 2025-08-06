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
#include "ci-test.h"
#include "dns-proto.h"

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
extern "C" {
// Remove command-line defines of package variables for the test project...
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
// ... so we can include the library's config without symbol redefinitions.
#include "ci_private.h"
#include "ci_inet_net_pton.h"
#include "ci_data.h"
#include "str/ci_strsplit.h"
#include "dsa/ci_htable.h"

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif
}

#include <string>
#include <vector>

namespace ci {
namespace test {

#ifndef CI_SYMBOL_HIDING
void CheckPtoN4(int size, unsigned int value, const char *input) {
  struct in_addr a4;
  a4.s_addr = 0;
  uint32_t expected = htonl(value);
  EXPECT_EQ(size, ci_inet_net_pton(AF_INET, input, &a4, sizeof(a4)))
    << " for input " << input;
  EXPECT_EQ(expected, a4.s_addr) << " for input " << input;
}

TEST_F(LibraryTest, Strsplit) {
  using std::vector;
  using std::string;
  size_t n;
  struct {
    vector<string> inputs;
    vector<string> delimiters;
    vector<vector<string>> expected;
  } data = {
    {
      "",
      " ",
      "             ",
      "example.com, example.co",
      "        a, b, A,c,     d, e,,,D,e,e,E",
    },
    { ", ", ", ", ", ", ", ", ", " },
    {
      {}, {}, {},
      { "example.com", "example.co" },
      { "a", "b", "c", "d", "e" },
    },
  };
  for(size_t i = 0; i < data.inputs.size(); i++) {
    char **out = ci_strsplit(data.inputs.at(i).c_str(),
                               data.delimiters.at(i).c_str(), &n);
    if(data.expected.at(i).size() == 0) {
      EXPECT_EQ(out, nullptr);
    }
    else {
      EXPECT_EQ(n, data.expected.at(i).size());
      for(size_t j = 0; j < n && j < data.expected.at(i).size(); j++) {
        EXPECT_STREQ(out[j], data.expected.at(i).at(j).c_str());
      }
    }
    ci_strsplit_free(out, n);
  }
}

TEST_F(LibraryTest, InetNetPtoN) {
  uint32_t expected;
  struct in_addr a4;
  struct in6_addr a6;
  CheckPtoN4(4 * 8, 0x01020304, "1.2.3.4");
  CheckPtoN4(4 * 8, 0x81010101, "129.1.1.1");
  CheckPtoN4(4 * 8, 0xC0010101, "192.1.1.1");
  CheckPtoN4(4 * 8, 0xE0010101, "224.1.1.1");
  CheckPtoN4(4 * 8, 0xE1010101, "225.1.1.1");
  CheckPtoN4(4, 0xE0000000, "224");
  CheckPtoN4(4 * 8, 0xFD000000, "253");
  CheckPtoN4(4 * 8, 0xF0010101, "240.1.1.1");
  CheckPtoN4(4 * 8, 0x02030405, "02.3.4.5");
  CheckPtoN4(3 * 8, 0x01020304, "1.2.3.4/24");
  CheckPtoN4(3 * 8, 0x01020300, "1.2.3/24");
  CheckPtoN4(2 * 8, 0xa0000000, "0xa");
  CheckPtoN4(0, 0x02030405, "2.3.4.5/000");
  CheckPtoN4(1 * 8, 0x01020000, "1.2/8");
  CheckPtoN4(2 * 8, 0x01020000, "0x0102/16");
  CheckPtoN4(4 * 8, 0x02030405, "02.3.4.5");

  EXPECT_EQ(16 * 8, ci_inet_net_pton(AF_INET6, "::", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ci_inet_net_pton(AF_INET6, "::1", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ci_inet_net_pton(AF_INET6, "1234:5678::", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ci_inet_net_pton(AF_INET6, "12:34::ff", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ci_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(23, ci_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4/23", &a6, sizeof(a6)));
  EXPECT_EQ(3 * 8, ci_inet_net_pton(AF_INET6, "12:34::ff/24", &a6, sizeof(a6)));
  EXPECT_EQ(0, ci_inet_net_pton(AF_INET6, "12:34::ff/0", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ci_inet_net_pton(AF_INET6, "12:34::ffff:0.2", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ci_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234", &a6, sizeof(a6)));
  EXPECT_EQ(2, ci_inet_net_pton(AF_INET6, "0::00:00:00/2", &a6, sizeof(a6)));

  // Various malformed versions
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, " ", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "0x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "0x ", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "x0", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "0xXYZZY", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "xyzzy", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET+AF_INET6, "1.2.3.4", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "257.2.3.4", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "002.3.4.x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "00.3.4.x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "2.3.4.x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "2.3.4.5.6", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "2.3.4.5.6/12", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "2.3.4:5", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "2.3.4.5/120", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "2.3.4.5/1x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "2.3.4.5/x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ff/240", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ff/02", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ff/2y", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ff/y", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ff/", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, ":x", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, ":", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, ": :1234", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "::12345", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "1234::2345:3456::0011", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234::", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, ":1234:1234:1234:1234:1234:1234:1234:1234", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, ":1234:1234:1234:1234:1234:1234:1234:1234:", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678:5678", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678:5678:5678", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ffff:257.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4.5.6", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4.5", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.z", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3001.4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3..4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.", &a6, sizeof(a6)));

  // Hex constants are allowed.
  EXPECT_EQ(4 * 8, ci_inet_net_pton(AF_INET, "0x01020304", &a4, sizeof(a4)));
  expected = htonl(0x01020304);
  EXPECT_EQ(expected, a4.s_addr);
  EXPECT_EQ(4 * 8, ci_inet_net_pton(AF_INET, "0x0a0b0c0d", &a4, sizeof(a4)));
  expected = htonl(0x0a0b0c0d);
  EXPECT_EQ(expected, a4.s_addr);
  EXPECT_EQ(4 * 8, ci_inet_net_pton(AF_INET, "0x0A0B0C0D", &a4, sizeof(a4)));
  expected = htonl(0x0a0b0c0d);
  EXPECT_EQ(expected, a4.s_addr);
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "0x0xyz", &a4, sizeof(a4)));
  EXPECT_EQ(4 * 8, ci_inet_net_pton(AF_INET, "0x1122334", &a4, sizeof(a4)));
  expected = htonl(0x11223340);
  EXPECT_EQ(expected, a4.s_addr);  // huh?

  // No room, no room.
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "1.2.3.4", &a4, sizeof(a4) - 1));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET6, "12:34::ff", &a6, sizeof(a6) - 1));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "0x01020304", &a4, 2));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "0x01020304", &a4, 0));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "0x0a0b0c0d", &a4, 0));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "0x0xyz", &a4, 0));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "0x1122334", &a4, sizeof(a4) - 1));
  EXPECT_EQ(-1, ci_inet_net_pton(AF_INET, "253", &a4, sizeof(a4) - 1));
}

TEST_F(LibraryTest, FreeLongChain) {
  struct ci_addr_node *data = nullptr;
  for (int ii = 0; ii < 100000; ii++) {
    struct ci_addr_node *prev = (struct ci_addr_node*)ci_malloc_data(CI_DATATYPE_ADDR_NODE);
    prev->next = data;
    data = prev;
  }

  ci_free_data(data);
}

TEST_F(LibraryTest, MallocDataFail) {
  EXPECT_EQ(nullptr, ci_malloc_data((ci_datatype)99));
  SetAllocSizeFail(sizeof(struct ci_data));
  EXPECT_EQ(nullptr, ci_malloc_data(CI_DATATYPE_MX_REPLY));
}

TEST(Misc, OnionDomain) {
  EXPECT_EQ(0, ci_is_onion_domain("onion.no"));
  EXPECT_EQ(0, ci_is_onion_domain(".onion.no"));
  EXPECT_EQ(1, ci_is_onion_domain(".onion"));
  EXPECT_EQ(1, ci_is_onion_domain(".onion."));
  EXPECT_EQ(1, ci_is_onion_domain("yes.onion"));
  EXPECT_EQ(1, ci_is_onion_domain("yes.onion."));
  EXPECT_EQ(1, ci_is_onion_domain("YES.ONION"));
  EXPECT_EQ(1, ci_is_onion_domain("YES.ONION."));
}

TEST_F(LibraryTest, CatDomain) {
  char *s;

  ci_cat_domain("foo", "example.net", &s);
  EXPECT_STREQ("foo.example.net", s);
  ci_free(s);

  ci_cat_domain("foo", ".", &s);
  EXPECT_STREQ("foo.", s);
  ci_free(s);

  ci_cat_domain("foo", "example.net.", &s);
  EXPECT_STREQ("foo.example.net.", s);
  ci_free(s);
}

TEST_F(LibraryTest, SlistMisuse) {
  EXPECT_EQ(NULL, ci_slist_create(NULL, NULL, NULL));
  ci_slist_replace_destructor(NULL, NULL);
  EXPECT_EQ(NULL, ci_slist_insert(NULL, NULL));
  EXPECT_EQ(NULL, ci_slist_node_find(NULL, NULL));
  EXPECT_EQ(NULL, ci_slist_node_first(NULL));
  EXPECT_EQ(NULL, ci_slist_node_last(NULL));
  EXPECT_EQ(NULL, ci_slist_node_next(NULL));
  EXPECT_EQ(NULL, ci_slist_node_prev(NULL));
  EXPECT_EQ(NULL, ci_slist_node_val(NULL));
  EXPECT_EQ((size_t)0, ci_slist_len(NULL));
  EXPECT_EQ(NULL, ci_slist_node_parent(NULL));
  EXPECT_EQ(NULL, ci_slist_first_val(NULL));
  EXPECT_EQ(NULL, ci_slist_last_val(NULL));
  EXPECT_EQ(NULL, ci_slist_node_claim(NULL));
}

TEST_F(LibraryTest, IfaceIPs) {
  ci_status_t      status;
  ci_iface_ips_t *ips = NULL;
  size_t             i;

  status = ci_iface_ips(&ips, CI_IFACE_IP_DEFAULT, NULL);
  EXPECT_TRUE(status == CI_SUCCESS || status == CI_ENOTIMP);

  /* Not implemented, can't run tests */
  if (status == CI_ENOTIMP)
    return;

  EXPECT_NE(nullptr, ips);

  for (i=0; i<ci_iface_ips_cnt(ips); i++) {
    const char *name = ci_iface_ips_get_name(ips, i);
    EXPECT_NE(nullptr, name);
    int flags = (int)ci_iface_ips_get_flags(ips, i);
    EXPECT_NE(0, (int)flags);
    EXPECT_NE(nullptr, ci_iface_ips_get_addr(ips, i));
    EXPECT_NE(0, ci_iface_ips_get_netmask(ips, i));
    if (flags & CI_IFACE_IP_LINKLOCAL && flags & CI_IFACE_IP_V6) {
      /* Hmm, seems not to work at least on MacOS
       * EXPECT_NE(0, ci_iface_ips_get_ll_scope(ips, i));
       */
    } else {
      EXPECT_EQ(0, ci_iface_ips_get_ll_scope(ips, i));
    }
    unsigned int idx = ci_os_if_nametoindex(name);
    EXPECT_NE(0, idx);
    char namebuf[256];
    EXPECT_EQ(std::string(ci_os_if_indextoname(idx, namebuf, sizeof(namebuf))), std::string(name));
  }


  /* Negative checking */
  ci_iface_ips_get_name(ips, ci_iface_ips_cnt(ips));
  ci_iface_ips_get_flags(ips, ci_iface_ips_cnt(ips));
  ci_iface_ips_get_addr(ips, ci_iface_ips_cnt(ips));
  ci_iface_ips_get_netmask(ips, ci_iface_ips_cnt(ips));
  ci_iface_ips_get_ll_scope(ips, ci_iface_ips_cnt(ips));

  ci_iface_ips(NULL, CI_IFACE_IP_DEFAULT, NULL);
  ci_iface_ips_cnt(NULL);
  ci_iface_ips_get_name(NULL, 0);
  ci_iface_ips_get_flags(NULL, 0);
  ci_iface_ips_get_addr(NULL, 0);
  ci_iface_ips_get_netmask(NULL, 0);
  ci_iface_ips_get_ll_scope(NULL, 0);
  ci_iface_ips_destroy(NULL);
  ci_os_if_nametoindex(NULL);
  ci_os_if_indextoname(0, NULL, 0);

  ci_iface_ips_destroy(ips);
}

TEST_F(LibraryTest, HtableMisuse) {
  EXPECT_EQ(NULL, ci_htable_create(NULL, NULL, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_insert(NULL, NULL));
  EXPECT_EQ(NULL, ci_htable_get(NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ci_htable_num_keys(NULL));
}

TEST_F(LibraryTest, URI) {
  struct {
    ci_bool_t success;
    const char *uri;
    const char *alt_match_uri;
  } tests[] = {
    { CI_TRUE,  "https://www.example.com",                                                               NULL },
    { CI_TRUE,  "https://www.example.com:8443",                                                          NULL },
    { CI_TRUE,  "https://user:password@www.example.com",                                                 NULL },
    { CI_TRUE,  "https://user%25:password@www.example.com",                                              NULL },
    { CI_TRUE,  "https://user:password%25@www.example.com",                                              NULL },
    { CI_TRUE,  "https://user@www.example.com",                                                          NULL },
    { CI_TRUE,  "https://www.example.com/path",                                                          NULL },
    { CI_TRUE,  "https://www.example.com/path/",                                                         NULL },
    { CI_TRUE,  "https://www.example.com/a/../",                                                         "https://www.example.com/" },
    { CI_TRUE,  "https://www.example.com/../a/",                                                         "https://www.example.com/a/" },
    { CI_TRUE,  "https://www.example.com/.././../a/",                                                    "https://www.example.com/a/" },
    { CI_TRUE,  "https://www.example.com/.././../a//b/c/d/../../",                                       "https://www.example.com/a/b/" },
    { CI_TRUE,  "https://www.example.com?key=val",                                                       NULL },
    { CI_TRUE,  "https://www.example.com?key",                                                           NULL },
    { CI_TRUE,  "https://www.example.com?key=",                                                          "https://www.example.com?key" },
    { CI_TRUE,  "https://www.example.com#fragment",                                                      NULL },
    { CI_TRUE,  "https://user:password@www.example.com/path",                                            NULL },
    { CI_TRUE,  "https://user:password@www.example.com/path#fragment",                                   NULL },
    { CI_TRUE,  "https://user:password@www.example.com/path?key=val",                                    NULL },
    { CI_TRUE,  "https://user:password@www.example.com/path?key=val#fragment",                           NULL },
    { CI_TRUE,  "https://user:password@www.example.com/path?key=val#fragment/with?chars",                NULL },
    { CI_TRUE,  "HTTPS://www.example.com",                                                               "https://www.example.com" },
    { CI_TRUE,  "https://www.example.com?key=hello+world",                                               "https://www.example.com?key=hello%20world" },
    { CI_TRUE,  "https://www.example.com?key=val%26",                                                    NULL },
    { CI_TRUE,  "https://www.example.com?key%26=val",                                                    NULL },
    { CI_TRUE,  "https://www.example.com?key=Aa2-._~/?!$'()*,;:@",                                       NULL },
    { CI_TRUE,  "https://www.example.com?key1=val1&key2=val2&key3=val3&key4=val4",                       "ignore" }, /* keys get randomized, can't match */
    { CI_TRUE,  "https://www.example.com?key=%41%61%32%2D%2E%5f%7e%2F%3F%21%24%27%28%29%2a%2C%3b%3a%40", "https://www.example.com?key=Aa2-._~/?!$'()*,;:@" },
    { CI_TRUE,  "dns+tls://192.168.1.1:53",                                                              NULL },
    { CI_TRUE,  "dns+tls://[fe80::1]:53",                                                                NULL },
    { CI_TRUE,  "dns://[fe80::b542:84df:1719:65e3%en0]",                                                 NULL },
    { CI_TRUE,  "dns+tls://[fe80:00::00:1]:53",                                                          "dns+tls://[fe80::1]:53" },
    { CI_TRUE,  "d.n+s-tls://www.example.com",                                                           NULL },
    { CI_FALSE, "dns*tls://www.example.com",                                                             NULL }, /* invalid scheme character */
    { CI_FALSE, "0dns://www.example.com",                                                                NULL }, /* dns can't start with digits */
    { CI_FALSE, "https://www.example.com?key=val%01",                                                    NULL }, /* non-printable character */
    { CI_FALSE, "abcdef0123456789://www.example.com",                                                    NULL }, /* scheme too long */
    { CI_FALSE, "www.example.com",                                                                       NULL }, /* missing scheme */
    { CI_FALSE, "https://www.example.com?key=val%0",                                                     NULL }, /* truncated uri-encoding */
    { CI_FALSE, "https://www.example.com?key=val%AZ",                                                    NULL }, /* invalid uri-encoding sequence */
    { CI_FALSE, "https://www.example.com?key=hello world",                                               NULL }, /* invalid character in query value */
    { CI_FALSE, "https://:password@www.example.com",                                                     NULL }, /* can't have password without username */
    { CI_FALSE, "dns+tls://[fe8G::1]",                                                                   NULL }, /* invalid ipv6 address */

    { CI_FALSE, NULL, NULL }
  };
  size_t i;

  for (i=0; tests[i].uri != NULL; i++) {
    ci_uri_t *uri = NULL;
    ci_status_t status;

    if (verbose) std::cerr << "Testing " << tests[i].uri << std::endl;
    status = ci_uri_parse(&uri, tests[i].uri);
    if (tests[i].success) {
      EXPECT_EQ(CI_SUCCESS, status);
    } else {
      EXPECT_NE(CI_SUCCESS, status);
    }

    if (status == CI_SUCCESS) {
      char *out = NULL;
      EXPECT_EQ(CI_SUCCESS, ci_uri_write(&out, uri));
      if (tests[i].alt_match_uri == NULL || strcmp(tests[i].alt_match_uri, "ignore") != 0) {
        EXPECT_STRCASEEQ(tests[i].alt_match_uri == NULL?tests[i].uri:tests[i].alt_match_uri, out);
      }
      ci_free(out);
    }
    ci_uri_destroy(uri);
  }

  /* Invalid tests  */
  EXPECT_NE(CI_SUCCESS, ci_uri_set_scheme(NULL, NULL));
  EXPECT_EQ(nullptr, ci_uri_get_scheme(NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_set_username(NULL, NULL));
  EXPECT_EQ(nullptr, ci_uri_get_username(NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_set_password(NULL, NULL));
  EXPECT_EQ(nullptr, ci_uri_get_password(NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_set_host(NULL, NULL));
  EXPECT_EQ(nullptr, ci_uri_get_host(NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_set_port(NULL, 0));
  EXPECT_EQ(0, ci_uri_get_port(NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_set_path(NULL, NULL));
  EXPECT_EQ(nullptr, ci_uri_get_path(NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_set_query_key(NULL, NULL, NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_del_query_key(NULL, NULL));
  EXPECT_EQ(nullptr, ci_uri_get_query_key(NULL, NULL));
  EXPECT_EQ(nullptr, ci_uri_get_query_keys(NULL, NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_set_fragment(NULL, NULL));
  EXPECT_EQ(nullptr, ci_uri_get_fragment(NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_write_buf(NULL, NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_write(NULL, NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_parse_buf(NULL, NULL));
  EXPECT_NE(CI_SUCCESS, ci_uri_parse_buf(NULL, NULL));
}
#endif /* !CI_SYMBOL_HIDING */

TEST_F(LibraryTest, InetPtoN) {
  struct in_addr a4;
  struct in6_addr a6;
  EXPECT_EQ(1, ci_inet_pton(AF_INET, "1.2.3.4", &a4));
  EXPECT_EQ(1, ci_inet_pton(AF_INET6, "12:34::ff", &a6));
  EXPECT_EQ(1, ci_inet_pton(AF_INET6, "12:34::ffff:1.2.3.4", &a6));
  EXPECT_EQ(0, ci_inet_pton(AF_INET, "xyzzy", &a4));
  EXPECT_EQ(-1, ci_inet_pton(AF_INET+AF_INET6, "1.2.3.4", &a4));
}

TEST_F(LibraryTest, FreeCorruptData) {
  // ci_free_data(p) expects that there is a type field and a marker
  // field in the memory before p.  Feed it incorrect versions of each.
  struct ci_data *data = (struct ci_data *)malloc(sizeof(struct ci_data));
  void* p = &(data->data);

  // Invalid type
  data->type = (ci_datatype)CI_DATATYPE_LAST;
  data->mark = CI_DATATYPE_MARK;
  ci_free_data(p);

  // Invalid marker
  data->type = (ci_datatype)CI_DATATYPE_MX_REPLY;
  data->mark = CI_DATATYPE_MARK + 1;
  ci_free_data(p);

  // Null pointer
  ci_free_data(nullptr);

  free(data);
}

TEST(LibraryInit, StrdupFailures) {
  EXPECT_EQ(CI_SUCCESS, ci_library_init(CI_LIB_INIT_ALL));
  char* copy = ci_strdup("string");
  EXPECT_NE(nullptr, copy);
  ci_free(copy);
  ci_library_cleanup();
}

TEST_F(LibraryTest, StrdupFailures) {
  SetAllocFail(1);
  char* copy = ci_strdup("string");
  EXPECT_EQ(nullptr, copy);
}

TEST_F(FileChannelTest, GetAddrInfoHostsPositive) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CI_HOSTS", hostsfile.filename());
  struct ci_addrinfo_hints hints = {0, 0, 0, 0};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET;
  hints.ai_flags = CI_AI_CANONNAME | CI_AI_ENVHOSTS | CI_AI_NOSORT;
  ci_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{example.com addr=[1.2.3.4]}", ss.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsSpaces) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CI_HOSTS", hostsfile.filename());
  struct ci_addrinfo_hints hints = {0, 0, 0, 0};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET;
  hints.ai_flags = CI_AI_CANONNAME | CI_AI_ENVHOSTS | CI_AI_NOSORT;
  ci_getaddrinfo(channel_, "google.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{www.google.com->google.com, www2.google.com->google.com addr=[2.3.4.5]}", ss.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsByALias) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CI_HOSTS", hostsfile.filename());
  struct ci_addrinfo_hints hints = {0, 0, 0, 0};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET;
  hints.ai_flags = CI_AI_CANONNAME | CI_AI_ENVHOSTS | CI_AI_NOSORT;
  ci_getaddrinfo(channel_, "www2.google.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{www.google.com->google.com, www2.google.com->google.com addr=[2.3.4.5]}", ss.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsIPV6) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CI_HOSTS", hostsfile.filename());
  struct ci_addrinfo_hints hints = {0, 0, 0, 0};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET6;
  hints.ai_flags = CI_AI_CANONNAME | CI_AI_ENVHOSTS | CI_AI_NOSORT;
  ci_getaddrinfo(channel_, "ipv6.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{ipv6.com addr=[[0000:0000:0000:0000:0000:0000:0000:0001]]}", ss.str());
}


TEST_F(FileChannelTest, GetAddrInfoAllocFail) {
  TempFile hostsfile("1.2.3.4 example.com alias1 alias2\n");
  EnvValue with_env("CI_HOSTS", hostsfile.filename());
  struct ci_addrinfo_hints hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;

  // Fail a variety of different memory allocations, and confirm
  // that the operation either fails with ENOMEM or succeeds
  // with the expected result.
  const int kCount = 34;
  AddrInfoResult results[kCount];
  for (int ii = 1; ii <= kCount; ii++) {
    AddrInfoResult* result = &(results[ii - 1]);
    ClearFails();
    SetAllocFail(ii);
    ci_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback, result);
    Process();
    EXPECT_TRUE(result->done_);
    if (result->status_ == CI_SUCCESS) {
      std::stringstream ss;
      ss << result->ai_;
      EXPECT_EQ("{alias1->example.com, alias2->example.com addr=[1.2.3.4]}", ss.str()) << " failed alloc #" << ii;
      if (verbose) std::cerr << "Succeeded despite failure of alloc #" << ii << std::endl;
    }
  }
}

TEST_F(LibraryTest, DNSRecord) {
  ci_dns_record_t   *dnsrec = NULL;
  ci_dns_rr_t       *rr     = NULL;
  struct in_addr       addr;
  struct ci_in6_addr addr6;
  unsigned char       *msg    = NULL;
  size_t               msglen = 0;
  size_t               qdcount = 0;
  size_t               ancount = 0;
  size_t               nscount = 0;
  size_t               arcount = 0;

  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_create(&dnsrec, 0x1234,
      CI_FLAG_QR|CI_FLAG_AA|CI_FLAG_RD|CI_FLAG_RA,
      CI_OPCODE_QUERY, CI_RCODE_NOERROR));

  /* == Question == */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_query_add(dnsrec, "example.com",
      CI_REC_TYPE_ANY,
      CI_CLASS_IN));

  /* == Answer == */
  /* A */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ANSWER, "example.com",
      CI_REC_TYPE_A, CI_CLASS_IN, 300));
  EXPECT_LT(0, ci_inet_pton(AF_INET, "1.1.1.1", &addr));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_addr(rr, CI_RR_A_ADDR, &addr));
  /* AAAA */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ANSWER, "example.com",
      CI_REC_TYPE_AAAA, CI_CLASS_IN, 300));
  EXPECT_LT(0, ci_inet_pton(AF_INET6, "2600::4", &addr6));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_addr6(rr, CI_RR_AAAA_ADDR, &addr6));
  /* MX */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ANSWER, "example.com",
      CI_REC_TYPE_MX, CI_CLASS_IN, 3600));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_MX_PREFERENCE, 10));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_MX_EXCHANGE, "mail.example.com"));
  /* CNAME */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ANSWER, "example.com",
      CI_REC_TYPE_CNAME, CI_CLASS_IN, 3600));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_CNAME_CNAME, "b.example.com"));
  /* TXT */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ANSWER, "example.com",
      CI_REC_TYPE_TXT, CI_CLASS_IN, 3600));
  const char txt1[] = "blah=here blah=there anywhere";
  const char txt2[] = "some other record";
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_add_abin(rr, CI_RR_TXT_DATA, (unsigned char *)txt1,
      sizeof(txt1)-1));
   EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_add_abin(rr, CI_RR_TXT_DATA, (unsigned char *)txt2,
      sizeof(txt2)-1));
  /* SIG */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ANSWER, "example.com",
      CI_REC_TYPE_SIG, CI_CLASS_ANY, 0));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_SIG_TYPE_COVERED, CI_REC_TYPE_TXT));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u8(rr, CI_RR_SIG_ALGORITHM, 1));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u8(rr, CI_RR_SIG_LABELS, 1));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u32(rr, CI_RR_SIG_ORIGINAL_TTL, 3200));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u32(rr, CI_RR_SIG_EXPIRATION, (unsigned int)time(NULL)));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u32(rr, CI_RR_SIG_INCEPTION, (unsigned int)time(NULL) - (86400 * 365)));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_SIG_KEY_TAG, 0x1234));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_SIG_SIGNERS_NAME, "signer.example.com"));
  const unsigned char sig[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_bin(rr, CI_RR_SIG_SIGNATURE, sig, sizeof(sig)));


  /* == Authority == */
  /* NS */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_AUTHORITY, "example.com",
      CI_REC_TYPE_NS, CI_CLASS_IN, 38400));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_NS_NSDNAME, "ns1.example.com"));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_AUTHORITY, "example.com",
      CI_REC_TYPE_NS, CI_CLASS_IN, 38400));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_NS_NSDNAME, "ns2.example.com"));
  /* SOA */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_AUTHORITY, "example.com",
      CI_REC_TYPE_SOA, CI_CLASS_IN, 86400));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_SOA_MNAME, "ns1.example.com"));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_SOA_RNAME, "tech\\.support.example.com"));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u32(rr, CI_RR_SOA_SERIAL, 2023110701));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u32(rr, CI_RR_SOA_REFRESH, 28800));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u32(rr, CI_RR_SOA_RETRY, 7200));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u32(rr, CI_RR_SOA_EXPIRE, 604800));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u32(rr, CI_RR_SOA_MINIMUM, 86400));

  /* == Additional */
  /* OPT */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL, "",
      CI_REC_TYPE_OPT, CI_CLASS_IN, 0));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_OPT_UDP_SIZE, 1280));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u8(rr, CI_RR_OPT_VERSION, 0));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_OPT_FLAGS, 0));
  unsigned char optval[] = { 'c', '-', 'a', 'r', 'e', 's' };
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_opt(rr, CI_RR_OPT_OPTIONS, 3 /* NSID */, optval, sizeof(optval)));
  /* PTR -- doesn't make sense, but ok */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL, "example.com",
      CI_REC_TYPE_PTR, CI_CLASS_IN, 300));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_PTR_DNAME, "b.example.com"));
  /* HINFO */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL, "example.com",
      CI_REC_TYPE_HINFO, CI_CLASS_IN, 300));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_HINFO_CPU, "Virtual"));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_HINFO_OS, "Linux"));
  /* SRV */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL,
      "_ldap.example.com", CI_REC_TYPE_SRV, CI_CLASS_IN, 300));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_SRV_PRIORITY, 100));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_SRV_WEIGHT, 1));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_SRV_PORT, 389));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_SRV_TARGET, "ldap.example.com"));
  /* TLSA */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL,
      "_443._tcp.example.com", CI_REC_TYPE_TLSA, CI_CLASS_IN, 86400));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u8(rr, CI_RR_TLSA_CERT_USAGE, CI_TLSA_USAGE_CA));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u8(rr, CI_RR_TLSA_SELECTOR, CI_TLSA_SELECTOR_FULL));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u8(rr, CI_RR_TLSA_MATCH, CI_TLSA_MATCH_SHA256));
  const unsigned char tlsa[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_bin(rr, CI_RR_TLSA_DATA, tlsa, sizeof(tlsa)));
  /* SVCB */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL,
      "_1234._bar.example.com", CI_REC_TYPE_SVCB, CI_CLASS_IN, 300));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_SVCB_PRIORITY, 1));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_SVCB_TARGET, "svc1.example.net"));
  /* IPV6 hint is a list of IPV6 addresses in network byte order, concatenated */
  struct ci_addr svcb_addr;
  svcb_addr.family = AF_UNSPEC;
  size_t               svcb_ipv6hint_len = 0;
  const unsigned char *svcb_ipv6hint = (const unsigned char *)ci_dns_pton("2001:db8::1", &svcb_addr, &svcb_ipv6hint_len);
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_opt(rr, CI_RR_SVCB_PARAMS, CI_SVCB_PARAM_IPV6HINT,
      svcb_ipv6hint, svcb_ipv6hint_len));
  /* Port is 16bit big endian format */
  unsigned short svcb_port = htons(1234);
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_opt(rr, CI_RR_SVCB_PARAMS, CI_SVCB_PARAM_PORT,
      (const unsigned char *)&svcb_port, sizeof(svcb_port)));
  /* HTTPS */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL,
      "example.com", CI_REC_TYPE_HTTPS, CI_CLASS_IN, 300));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_HTTPS_PRIORITY, 1));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_HTTPS_TARGET, ""));

  /* In DNS string format which is 1 octet length indicator followed by string */
  const unsigned char https_alpn[] = { 0x02, 'h', '3' };
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_opt(rr, CI_RR_HTTPS_PARAMS, CI_SVCB_PARAM_ALPN,
      https_alpn, sizeof(https_alpn)));
  /* URI */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL,
      "_ftp._tcp.example.com", CI_REC_TYPE_URI, CI_CLASS_IN, 3600));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_URI_PRIORITY, 10));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_URI_WEIGHT, 1));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_URI_TARGET, "ftp://ftp.example.com/public"));
  /* CAA */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL,
      "example.com", CI_REC_TYPE_CAA, CI_CLASS_IN, 86400));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u8(rr, CI_RR_CAA_CRITICAL, 0));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_CAA_TAG, "issue"));
  unsigned char caa[] = "letsencrypt.org";
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_bin(rr, CI_RR_CAA_VALUE, caa, sizeof(caa)));
  /* NAPTR */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL,
      "example.com", CI_REC_TYPE_NAPTR, CI_CLASS_IN, 86400));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_NAPTR_ORDER, 100));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_NAPTR_PREFERENCE, 10));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_NAPTR_FLAGS, "S"));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_NAPTR_SERVICES, "SIP+D2U"));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_NAPTR_REGEXP,
      "!^.*$!sip:customer-service@example.com!"));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_NAPTR_REPLACEMENT,
      "_sip._udp.example.com."));
  /* RAW_RR */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL, "",
      CI_REC_TYPE_RAW_RR, CI_CLASS_IN, 0));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u16(rr, CI_RR_RAW_RR_TYPE, 65432));
  unsigned char data[] = { 0x00 };
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_bin(rr, CI_RR_RAW_RR_DATA, data, sizeof(data)));

  qdcount = ci_dns_record_query_cnt(dnsrec);
  ancount = ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER);
  nscount = ci_dns_record_rr_cnt(dnsrec, CI_SECTION_AUTHORITY);
  arcount = ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ADDITIONAL);

  /* Write */
  EXPECT_EQ(CI_SUCCESS, ci_dns_write(dnsrec, &msg, &msglen));

  ci_buf_t *hexdump = ci_buf_create();
  EXPECT_EQ(CI_SUCCESS, ci_buf_hexdump(hexdump, msg, msglen));
  char *hexdata = ci_buf_finish_str(hexdump, NULL);
  //printf("HEXDUMP\n%s", hexdata);
  ci_free(hexdata);

  ci_dns_record_destroy(dnsrec); dnsrec = NULL;

  /* Parse */
  EXPECT_EQ(CI_SUCCESS, ci_dns_parse(msg, msglen, 0, &dnsrec));
  ci_free_string(msg); msg = NULL;

  /* Re-write */
  EXPECT_EQ(CI_SUCCESS, ci_dns_write(dnsrec, &msg, &msglen));

  EXPECT_EQ(qdcount, ci_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(ancount, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER));
  EXPECT_EQ(nscount, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_AUTHORITY));
  EXPECT_EQ(arcount, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ADDITIONAL));

  /* Iterate and print */
  ci_buf_t *printmsg = ci_buf_create();
  ci_buf_append_str(printmsg, ";; ->>HEADER<<- opcode: ");
  ci_buf_append_str(printmsg, ci_dns_opcode_tostr(ci_dns_record_get_opcode(dnsrec)));
  ci_buf_append_str(printmsg, ", status: ");
  ci_buf_append_str(printmsg, ci_dns_rcode_tostr(ci_dns_record_get_rcode(dnsrec)));
  ci_buf_append_str(printmsg, ", id: ");
  ci_buf_append_num_dec(printmsg, (size_t)ci_dns_record_get_id(dnsrec), 0);
  ci_buf_append_str(printmsg, "\n;; flags: ");
  ci_buf_append_num_hex(printmsg, (size_t)ci_dns_record_get_flags(dnsrec), 0);
  ci_buf_append_str(printmsg, "; QUERY: ");
  ci_buf_append_num_dec(printmsg, ci_dns_record_query_cnt(dnsrec), 0);
  ci_buf_append_str(printmsg, ", ANSWER: ");
  ci_buf_append_num_dec(printmsg, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER), 0);
  ci_buf_append_str(printmsg, ", AUTHORITY: ");
  ci_buf_append_num_dec(printmsg, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_AUTHORITY), 0);
  ci_buf_append_str(printmsg, ", ADDITIONAL: ");
  ci_buf_append_num_dec(printmsg, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ADDITIONAL), 0);
  ci_buf_append_str(printmsg, "\n\n");
  ci_buf_append_str(printmsg, ";; QUESTION SECTION:\n");
  for (size_t i = 0; i < ci_dns_record_query_cnt(dnsrec); i++) {
    const char         *name;
    ci_dns_rec_type_t qtype;
    ci_dns_class_t    qclass;
    ci_dns_record_query_get(dnsrec, i, &name, &qtype, &qclass);
    ci_buf_append_str(printmsg, ";");
    ci_buf_append_str(printmsg, name);
    ci_buf_append_str(printmsg, ".\t\t\t");
    ci_buf_append_str(printmsg, ci_dns_class_tostr(qclass));
    ci_buf_append_str(printmsg, "\t");
    ci_buf_append_str(printmsg, ci_dns_rec_type_tostr(qtype));
    ci_buf_append_str(printmsg, "\n");
  }
  ci_buf_append_str(printmsg, "\n");
  for (size_t i = CI_SECTION_ANSWER; i < CI_SECTION_ADDITIONAL + 1; i++) {
    ci_buf_append_str(printmsg, ";; ");
    ci_buf_append_str(printmsg, ci_dns_section_tostr((ci_dns_section_t)i));
    ci_buf_append_str(printmsg, " SECTION:\n");
    for (size_t j = 0; j < ci_dns_record_rr_cnt(dnsrec, (ci_dns_section_t)i); j++) {
      rr = ci_dns_record_rr_get(dnsrec, (ci_dns_section_t)i, j);
      ci_buf_append_str(printmsg, ci_dns_rr_get_name(rr));
      ci_buf_append_str(printmsg, ".\t\t\t");
      ci_buf_append_str(printmsg, ci_dns_class_tostr(ci_dns_rr_get_class(rr)));
      ci_buf_append_str(printmsg, "\t");
      ci_buf_append_str(printmsg, ci_dns_rec_type_tostr(ci_dns_rr_get_type(rr)));
      ci_buf_append_str(printmsg, "\t");
      ci_buf_append_num_dec(printmsg, ci_dns_rr_get_ttl(rr), 0);
      ci_buf_append_str(printmsg, "\t");

      size_t keys_cnt;
      const ci_dns_rr_key_t *keys = ci_dns_rr_get_keys(ci_dns_rr_get_type(rr), &keys_cnt);
      for (size_t k = 0; k<keys_cnt; k++) {
        char buf[256] = "";
        ci_buf_append_str(printmsg, ci_dns_rr_key_tostr(keys[k]));
        ci_buf_append_str(printmsg, "=");
        switch (ci_dns_rr_key_datatype(keys[k])) {
          case CI_DATATYPE_INADDR:
            ci_inet_ntop(AF_INET, ci_dns_rr_get_addr(rr, keys[k]), buf, sizeof(buf));
            ci_buf_append_str(printmsg, buf);
            break;
          case CI_DATATYPE_INADDR6:
            ci_inet_ntop(AF_INET6, ci_dns_rr_get_addr6(rr, keys[k]), buf, sizeof(buf));
            ci_buf_append_str(printmsg, buf);
            break;
          case CI_DATATYPE_U8:
            ci_buf_append_num_dec(printmsg, ci_dns_rr_get_u8(rr, keys[k]), 0);
            break;
          case CI_DATATYPE_U16:
            ci_buf_append_num_dec(printmsg, ci_dns_rr_get_u16(rr, keys[k]), 0);
            break;
          case CI_DATATYPE_U32:
            ci_buf_append_num_dec(printmsg, ci_dns_rr_get_u32(rr, keys[k]), 0);
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
              ci_buf_append_byte(printmsg, '"');
              size_t templen;
              ci_buf_append_str(printmsg, (const char *)ci_dns_rr_get_bin(rr, keys[k], &templen));
              ci_buf_append_byte(printmsg, '"');
            }
            break;
          case CI_DATATYPE_ABINP:
            for (size_t a=0; a<ci_dns_rr_get_abin_cnt(rr, keys[k]); a++) {
              if (a != 0) {
                ci_buf_append_byte(printmsg, ' ');
              }
              ci_buf_append_byte(printmsg, '"');
              size_t templen;
              ci_buf_append_str(printmsg, (const char *)ci_dns_rr_get_abin(rr, keys[k], a, &templen));
              ci_buf_append_byte(printmsg, '"');
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
  ci_buf_append_num_dec(printmsg, msglen, 0);
  ci_buf_append_str(printmsg, "\n\n");

  char *printdata = ci_buf_finish_str(printmsg, NULL);
  //printf("%s", printdata);
  ci_free(printdata);

  ci_dns_record_destroy(dnsrec);
  ci_free_string(msg);

  // Invalid
  EXPECT_NE(CI_SUCCESS, ci_dns_parse(NULL, 0, 0, NULL));
  EXPECT_NE(CI_SUCCESS, ci_dns_record_create(NULL, 0, 0, CI_OPCODE_QUERY, CI_RCODE_NOERROR));
  EXPECT_EQ(0, ci_dns_record_get_id(NULL));
  EXPECT_EQ(0, ci_dns_record_get_flags(NULL));
  EXPECT_EQ(0, (int)ci_dns_record_get_opcode(NULL));
  EXPECT_EQ(0, (int)ci_dns_record_get_rcode(NULL));
  EXPECT_EQ(0, (int)ci_dns_record_query_cnt(NULL));
  EXPECT_NE(CI_SUCCESS, ci_dns_record_query_set_name(NULL, 0, NULL));
  EXPECT_NE(CI_SUCCESS, ci_dns_record_query_set_type(NULL, 0, CI_REC_TYPE_A));
  EXPECT_NE(CI_SUCCESS, ci_dns_record_query_get(NULL, 0, NULL, NULL, NULL));
  EXPECT_EQ(0, ci_dns_record_rr_cnt(NULL, CI_SECTION_ANSWER));
  EXPECT_NE(CI_SUCCESS, ci_dns_record_rr_add(NULL, NULL, CI_SECTION_ANSWER, NULL, CI_REC_TYPE_A, CI_CLASS_IN, 0));
  EXPECT_NE(CI_SUCCESS, ci_dns_record_rr_del(NULL, CI_SECTION_ANSWER, 0));
  EXPECT_EQ(nullptr, ci_dns_record_rr_get(NULL, CI_SECTION_ANSWER, 0));
  EXPECT_EQ(nullptr, ci_dns_rr_get_name(NULL));
  EXPECT_EQ(0, (int)ci_dns_rr_get_type(NULL));
  EXPECT_EQ(0, (int)ci_dns_rr_get_class(NULL));
  EXPECT_EQ(0, ci_dns_rr_get_ttl(NULL));
  EXPECT_NE(CI_SUCCESS, ci_dns_write(NULL, NULL, NULL));
#ifndef CI_SYMBOL_HIDING
  ci_dns_record_ttl_decrement(NULL, 0);
#endif
  EXPECT_EQ(nullptr, ci_dns_rr_get_addr(NULL, CI_RR_A_ADDR));
  EXPECT_EQ(nullptr, ci_dns_rr_get_addr(NULL, CI_RR_NS_NSDNAME));
  EXPECT_EQ(nullptr, ci_dns_rr_get_addr6(NULL, CI_RR_AAAA_ADDR));
  EXPECT_EQ(nullptr, ci_dns_rr_get_addr6(NULL, CI_RR_NS_NSDNAME));
  EXPECT_EQ(0, ci_dns_rr_get_u8(NULL, CI_RR_SIG_ALGORITHM));
  EXPECT_EQ(0, ci_dns_rr_get_u8(NULL, CI_RR_NS_NSDNAME));
  EXPECT_EQ(0, ci_dns_rr_get_u16(NULL, CI_RR_MX_PREFERENCE));
  EXPECT_EQ(0, ci_dns_rr_get_u16(NULL, CI_RR_NS_NSDNAME));
  EXPECT_EQ(0, ci_dns_rr_get_u32(NULL, CI_RR_SOA_SERIAL));
  EXPECT_EQ(0, ci_dns_rr_get_u32(NULL, CI_RR_NS_NSDNAME));
  EXPECT_EQ(nullptr, ci_dns_rr_get_bin(NULL, CI_RR_TXT_DATA, NULL));
  EXPECT_EQ(nullptr, ci_dns_rr_get_bin(NULL, CI_RR_NS_NSDNAME, NULL));
  EXPECT_EQ(nullptr, ci_dns_rr_get_str(NULL, CI_RR_NS_NSDNAME));
  EXPECT_EQ(nullptr, ci_dns_rr_get_str(NULL, CI_RR_MX_PREFERENCE));
  EXPECT_EQ(0, ci_dns_rr_get_opt_cnt(NULL, CI_RR_OPT_OPTIONS));
  EXPECT_EQ(0, ci_dns_rr_get_opt_cnt(NULL, CI_RR_A_ADDR));
  EXPECT_EQ(65535, ci_dns_rr_get_opt(NULL, CI_RR_OPT_OPTIONS, 0, NULL, NULL));
  EXPECT_EQ(65535, ci_dns_rr_get_opt(NULL, CI_RR_A_ADDR, 0, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_dns_rr_get_opt_byid(NULL, CI_RR_OPT_OPTIONS, 1, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_dns_rr_get_opt_byid(NULL, CI_RR_A_ADDR, 1, NULL, NULL));
}

TEST_F(LibraryTest, DNSParseFlags) {
  ci_dns_record_t   *dnsrec = NULL;
  ci_dns_rr_t       *rr     = NULL;
  struct in_addr       addr;
  unsigned char       *msg    = NULL;
  size_t               msglen = 0;

  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_create(&dnsrec, 0x1234,
      CI_FLAG_QR|CI_FLAG_AA|CI_FLAG_RD|CI_FLAG_RA,
      CI_OPCODE_QUERY, CI_RCODE_NOERROR));

  /* == Question == */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_query_add(dnsrec, "example.com",
      CI_REC_TYPE_ANY,
      CI_CLASS_IN));

  /* == Answer == */
  /* A */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ANSWER, "example.com",
      CI_REC_TYPE_A, CI_CLASS_IN, 300));
  EXPECT_LT(0, ci_inet_pton(AF_INET, "1.1.1.1", &addr));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_addr(rr, CI_RR_A_ADDR, &addr));
  /* TLSA */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ANSWER,
      "_443._tcp.example.com", CI_REC_TYPE_TLSA, CI_CLASS_IN, 86400));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u8(rr, CI_RR_TLSA_CERT_USAGE, CI_TLSA_USAGE_CA));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u8(rr, CI_RR_TLSA_SELECTOR, CI_TLSA_SELECTOR_FULL));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_u8(rr, CI_RR_TLSA_MATCH, CI_TLSA_MATCH_SHA256));
  const unsigned char tlsa[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_bin(rr, CI_RR_TLSA_DATA, tlsa, sizeof(tlsa)));

  /* == Authority == */
  /* NS */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_AUTHORITY, "example.com",
      CI_REC_TYPE_NS, CI_CLASS_IN, 38400));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_NS_NSDNAME, "ns1.example.com"));

  /* == Additional */
  /* PTR -- doesn't make sense, but ok */
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_record_rr_add(&rr, dnsrec, CI_SECTION_ADDITIONAL, "example.com",
      CI_REC_TYPE_PTR, CI_CLASS_IN, 300));
  EXPECT_EQ(CI_SUCCESS,
    ci_dns_rr_set_str(rr, CI_RR_PTR_DNAME, "b.example.com"));

  /* Write */
  EXPECT_EQ(CI_SUCCESS, ci_dns_write(dnsrec, &msg, &msglen));

  /* Cleanup - before reuse */
  ci_dns_record_destroy(dnsrec);

  /* Parse "base" type records (1035) */
  EXPECT_EQ(CI_SUCCESS, ci_dns_parse(msg, msglen, CI_DNS_PARSE_AN_BASE_RAW |
    CI_DNS_PARSE_NS_BASE_RAW | CI_DNS_PARSE_AR_BASE_RAW, &dnsrec));

  EXPECT_EQ(1, ci_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(2, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER));
  EXPECT_EQ(1, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_AUTHORITY));
  EXPECT_EQ(1, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ADDITIONAL));

  rr = ci_dns_record_rr_get(dnsrec, CI_SECTION_ANSWER, 0);
  EXPECT_EQ(CI_REC_TYPE_RAW_RR, ci_dns_rr_get_type(rr));

  rr = ci_dns_record_rr_get(dnsrec, CI_SECTION_ANSWER, 1);
  EXPECT_EQ(CI_REC_TYPE_TLSA, ci_dns_rr_get_type(rr));

  rr = ci_dns_record_rr_get(dnsrec, CI_SECTION_AUTHORITY, 0);
  EXPECT_EQ(CI_REC_TYPE_RAW_RR, ci_dns_rr_get_type(rr));

  rr = ci_dns_record_rr_get(dnsrec, CI_SECTION_ADDITIONAL, 0);
  EXPECT_EQ(CI_REC_TYPE_RAW_RR, ci_dns_rr_get_type(rr));

  /* Cleanup - before reuse */

  ci_dns_record_destroy(dnsrec);

  /* Parse later RFCs (no name compression) type records */

  EXPECT_EQ(CI_SUCCESS, ci_dns_parse(msg, msglen, CI_DNS_PARSE_AN_EXT_RAW |
    CI_DNS_PARSE_NS_EXT_RAW | CI_DNS_PARSE_AR_EXT_RAW, &dnsrec));

  EXPECT_EQ(1, ci_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(2, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER));
  EXPECT_EQ(1, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_AUTHORITY));
  EXPECT_EQ(1, ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ADDITIONAL));

  rr = ci_dns_record_rr_get(dnsrec, CI_SECTION_ANSWER, 0);
  EXPECT_EQ(CI_REC_TYPE_A, ci_dns_rr_get_type(rr));

  rr = ci_dns_record_rr_get(dnsrec, CI_SECTION_ANSWER, 1);
  EXPECT_EQ(CI_REC_TYPE_RAW_RR, ci_dns_rr_get_type(rr));

  rr = ci_dns_record_rr_get(dnsrec, CI_SECTION_AUTHORITY, 0);
  EXPECT_EQ(CI_REC_TYPE_NS, ci_dns_rr_get_type(rr));

  rr = ci_dns_record_rr_get(dnsrec, CI_SECTION_ADDITIONAL, 0);
  EXPECT_EQ(CI_REC_TYPE_PTR, ci_dns_rr_get_type(rr));

  ci_dns_record_destroy(dnsrec);
  ci_free_string(msg); msg = NULL;
}

TEST_F(LibraryTest, ArrayMisuse) {
  EXPECT_EQ(NULL, ci_array_create(0, NULL));
  ci_array_destroy(NULL);
  EXPECT_EQ(NULL, ci_array_finish(NULL, NULL));
  EXPECT_EQ(0, ci_array_len(NULL));
  EXPECT_NE(CI_SUCCESS, ci_array_insert_at(NULL, NULL, 0));
  EXPECT_NE(CI_SUCCESS, ci_array_insertdata_at(NULL, 0, NULL));
  EXPECT_NE(CI_SUCCESS, ci_array_insert_last(NULL, NULL));
  EXPECT_NE(CI_SUCCESS, ci_array_insertdata_last(NULL, NULL));
  EXPECT_NE(CI_SUCCESS, ci_array_insert_first(NULL, NULL));
  EXPECT_NE(CI_SUCCESS, ci_array_insertdata_first(NULL, NULL));
  EXPECT_EQ(NULL, ci_array_at(NULL, 0));
  EXPECT_EQ(NULL, ci_array_first(NULL));
  EXPECT_EQ(NULL, ci_array_last(NULL));
  EXPECT_NE(CI_SUCCESS, ci_array_claim_at(NULL, 0, NULL, 0));
  EXPECT_NE(CI_SUCCESS, ci_array_remove_at(NULL, 0));
  EXPECT_NE(CI_SUCCESS, ci_array_remove_first(NULL));
  EXPECT_NE(CI_SUCCESS, ci_array_remove_last(NULL));
  EXPECT_NE(CI_SUCCESS, ci_array_sort(NULL, NULL));
  EXPECT_NE(CI_SUCCESS, ci_array_set_size(NULL, 0));
}

TEST_F(LibraryTest, BufMisuse) {
  EXPECT_EQ(NULL, ci_buf_create_const(NULL, 0));
  ci_buf_reclaim(NULL);
  EXPECT_NE(CI_SUCCESS, ci_buf_append(NULL, NULL, 55));
  size_t len = 10;
  EXPECT_EQ(NULL, ci_buf_append_start(NULL, &len));
  EXPECT_EQ(NULL, ci_buf_append_start(NULL, NULL));
  ci_buf_append_finish(NULL, 0);
  EXPECT_EQ(NULL, ci_buf_finish_bin(NULL, NULL));
  EXPECT_EQ(NULL, ci_buf_finish_str(NULL, NULL));
  ci_buf_tag(NULL);
  EXPECT_NE(CI_SUCCESS, ci_buf_tag_rollback(NULL));
  EXPECT_NE(CI_SUCCESS, ci_buf_tag_clear(NULL));
  EXPECT_EQ(NULL, ci_buf_tag_fetch(NULL, NULL));
  EXPECT_EQ((size_t)0, ci_buf_tag_length(NULL));
  EXPECT_NE(CI_SUCCESS, ci_buf_tag_fetch_bytes(NULL, NULL, NULL));
  EXPECT_NE(CI_SUCCESS, ci_buf_tag_fetch_string(NULL, NULL, 0));
  EXPECT_NE(CI_SUCCESS, ci_buf_fetch_bytes_dup(NULL, 0, CI_FALSE, NULL));
  EXPECT_NE(CI_SUCCESS, ci_buf_fetch_str_dup(NULL, 0, NULL));
  EXPECT_EQ((size_t)0, ci_buf_consume_whitespace(NULL, CI_FALSE));
  EXPECT_EQ((size_t)0, ci_buf_consume_nonwhitespace(NULL));
  EXPECT_EQ((size_t)0, ci_buf_consume_line(NULL, CI_FALSE));
  EXPECT_EQ(CI_FALSE, ci_buf_begins_with(NULL, NULL, 0));
  EXPECT_EQ((size_t)0, ci_buf_get_position(NULL));
  EXPECT_NE(CI_SUCCESS, ci_buf_set_position(NULL, 0));
  EXPECT_NE(CI_SUCCESS, ci_buf_parse_dns_binstr(NULL, 0, NULL, NULL));
}

TEST_F(LibraryTest, HtableAsvpMisuse) {
  EXPECT_EQ(CI_FALSE, ci_htable_asvp_insert(NULL, CI_SOCKET_BAD, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_asvp_get(NULL, CI_SOCKET_BAD, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_asvp_remove(NULL, CI_SOCKET_BAD));
  EXPECT_EQ((size_t)0, ci_htable_asvp_num_keys(NULL));
}

TEST_F(LibraryTest, HtableStrvpMisuse) {
  EXPECT_EQ(CI_FALSE, ci_htable_strvp_insert(NULL, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_strvp_get(NULL, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_strvp_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ci_htable_strvp_num_keys(NULL));
}

TEST_F(LibraryTest, HtableVpStrMisuse) {
  EXPECT_EQ(CI_FALSE, ci_htable_vpstr_insert(NULL, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_vpstr_get(NULL, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_vpstr_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ci_htable_vpstr_num_keys(NULL));
}

TEST_F(LibraryTest, HtableDictMisuse) {
  EXPECT_EQ(CI_FALSE, ci_htable_dict_insert(NULL, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_dict_get(NULL, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_dict_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ci_htable_dict_num_keys(NULL));
}

TEST_F(LibraryTest, HtableSzvpMisuse) {
  EXPECT_EQ(CI_FALSE, ci_htable_szvp_insert(NULL, 0, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_szvp_get(NULL, 0, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_szvp_remove(NULL, 0));
  EXPECT_EQ((size_t)0, ci_htable_szvp_num_keys(NULL));
}

TEST_F(LibraryTest, HtableVpvpMisuse) {
  EXPECT_EQ(CI_FALSE, ci_htable_vpvp_insert(NULL, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_vpvp_get(NULL, NULL, NULL));
  EXPECT_EQ(CI_FALSE, ci_htable_vpvp_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ci_htable_vpvp_num_keys(NULL));
}

TEST_F(LibraryTest, LlistMisuse) {
  ci_llist_replace_destructor(NULL, NULL);
  EXPECT_EQ(NULL, ci_llist_insert_before(NULL, NULL));
  EXPECT_EQ(NULL, ci_llist_insert_after(NULL, NULL));
  EXPECT_EQ(NULL, ci_llist_node_last(NULL));
  EXPECT_EQ(NULL, ci_llist_node_next(NULL));
  EXPECT_EQ(NULL, ci_llist_node_prev(NULL));
  EXPECT_EQ((size_t)0, ci_llist_len(NULL));
  EXPECT_EQ(NULL, ci_llist_node_parent(NULL));
  EXPECT_EQ(NULL, ci_llist_node_claim(NULL));
  ci_llist_node_replace(NULL, NULL);
}

typedef struct {
  unsigned int id;
  ci_buf_t *buf;
} array_member_t;

static void array_member_init(void *mb, unsigned int id)
{
  array_member_t *m = (array_member_t *)mb;
  m->id             = id;
  m->buf            = ci_buf_create();
  ci_buf_append_be32(m->buf, id);
}

static void array_member_destroy(void *mb)
{
  array_member_t *m = (array_member_t *)mb;
  ci_buf_destroy(m->buf);
}

static int array_sort_cmp(const void *data1, const void *data2)
{
  const array_member_t *m1 = (const array_member_t *)data1;
  const array_member_t *m2 = (const array_member_t *)data2;
  if (m1->id > m2->id)
    return 1;
  if (m1->id < m2->id)
    return -1;
  return 0;
}

TEST_F(LibraryTest, Array) {
  ci_array_t   *a       = NULL;
  array_member_t *m       = NULL;
  array_member_t  mbuf;
  unsigned int    cnt     = 0;
  unsigned int    removed = 0;
  void           *ptr     = NULL;
  size_t          i;

  a = ci_array_create(sizeof(array_member_t), array_member_destroy);
  EXPECT_NE(nullptr, a);

  /* Try to sort with no elements, should break out */
  EXPECT_EQ(CI_SUCCESS, ci_array_sort(a, array_sort_cmp));

  /* Add 8 elements */
  for ( ; cnt < 8 ; cnt++) {
    EXPECT_EQ(CI_SUCCESS, ci_array_insert_last(&ptr, a));
    array_member_init(ptr, cnt+1);
  }

  /* Insert at invalid index */
  EXPECT_NE(CI_SUCCESS, ci_array_insert_at(&ptr, a, 12345678));

  /* Verify count */
  EXPECT_EQ(cnt, ci_array_len(a));

  /* Remove the first 2 elements */
  EXPECT_EQ(CI_SUCCESS, ci_array_remove_first(a));
  EXPECT_EQ(CI_SUCCESS, ci_array_remove_first(a));
  removed += 2;

  /* Verify count */
  EXPECT_EQ(cnt-removed, ci_array_len(a));

  /* Verify id of first element */
  m = (array_member_t *)ci_array_first(a);
  EXPECT_NE(nullptr, m);
  EXPECT_EQ(3, m->id);


  /* Add 100 total elements, this should force a shift of memory at some
   * to make sure moves are working */
  for ( ; cnt < 100 ; cnt++) {
    EXPECT_EQ(CI_SUCCESS, ci_array_insert_last(&ptr, a));
    array_member_init(ptr, cnt+1);
  }

  /* Verify count */
  EXPECT_EQ(cnt-removed, ci_array_len(a));

  /* Remove 2 from the end */
  EXPECT_EQ(CI_SUCCESS, ci_array_remove_last(a));
  EXPECT_EQ(CI_SUCCESS, ci_array_remove_last(a));
  removed += 2;

  /* Verify count */
  EXPECT_EQ(cnt-removed, ci_array_len(a));

  /* Verify expected id of last member */
  m = (array_member_t *)ci_array_last(a);
  EXPECT_NE(nullptr, m);
  EXPECT_EQ(cnt-2, m->id);

  /* Remove 3 middle members */
  EXPECT_EQ(CI_SUCCESS, ci_array_remove_at(a, ci_array_len(a)/2));
  EXPECT_EQ(CI_SUCCESS, ci_array_remove_at(a, ci_array_len(a)/2));
  EXPECT_EQ(CI_SUCCESS, ci_array_remove_at(a, ci_array_len(a)/2));
  removed += 3;

  /* Verify count */
  EXPECT_EQ(cnt-removed, ci_array_len(a));

  /* Claim a middle member then re-add it at the same position */
  i = ci_array_len(a) / 2;
  EXPECT_EQ(CI_SUCCESS, ci_array_claim_at(&mbuf, sizeof(mbuf), a, i));
  EXPECT_EQ(CI_SUCCESS, ci_array_insert_at(&ptr, a, i));
  array_member_init(ptr, mbuf.id);
  array_member_destroy((void *)&mbuf);
  /* Verify count */
  EXPECT_EQ(cnt-removed, ci_array_len(a));

  /* Iterate across the array, make sure each entry is greater than the last and
   * the data in the buffer matches the id in the array */
  unsigned int last_id = 0;
  for (i=0; i<ci_array_len(a); i++) {
    m = (array_member_t *)ci_array_at(a, i);
    EXPECT_NE(nullptr, m);
    EXPECT_GT(m->id, last_id);
    last_id = m->id;

    unsigned int bufval = 0;
    ci_buf_tag(m->buf);
    EXPECT_EQ(CI_SUCCESS, ci_buf_fetch_be32(m->buf, &bufval));
    ci_buf_tag_rollback(m->buf);
    EXPECT_EQ(bufval, m->id);
  }

  /* add a new element in the middle to the beginning with a high id */
  EXPECT_EQ(CI_SUCCESS, ci_array_insert_at(&ptr, a, ci_array_len(a)/2));
  array_member_init(ptr, 100000);

  /* Sort the array */
  EXPECT_EQ(CI_SUCCESS, ci_array_sort(a, array_sort_cmp));

  /* Iterate across the array, make sure each entry is greater than the last and
   * the data in the buffer matches the id in the array */
  last_id = 0;
  for (i=0; i<ci_array_len(a); i++) {
    m = (array_member_t *)ci_array_at(a, i);
    EXPECT_NE(nullptr, m);
    EXPECT_GT(m->id, last_id);
    last_id = m->id;

    unsigned int bufval = 0;
    ci_buf_tag(m->buf);
    EXPECT_EQ(CI_SUCCESS, ci_buf_fetch_be32(m->buf, &bufval));
    ci_buf_tag_rollback(m->buf);
    EXPECT_EQ(bufval, m->id);
  }

  ci_array_destroy(a);
}

TEST_F(LibraryTest, HtableVpvp) {
  ci_llist_t       *l = NULL;
  ci_htable_vpvp_t *h = NULL;
  ci_llist_node_t  *n = NULL;
  size_t               i;

#define VPVP_TABLE_SIZE 1000

  l = ci_llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ci_htable_vpvp_create(NULL, ci_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<VPVP_TABLE_SIZE; i++) {
    void *p = ci_malloc_zero(4);
    EXPECT_NE((void *)NULL, p);
    EXPECT_NE((void *)NULL, ci_llist_insert_last(l, p));
    EXPECT_TRUE(ci_htable_vpvp_insert(h, p, p));
  }

  EXPECT_EQ(VPVP_TABLE_SIZE, ci_llist_len(l));
  EXPECT_EQ(VPVP_TABLE_SIZE, ci_htable_vpvp_num_keys(h));

  n = ci_llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ci_llist_node_t *next = ci_llist_node_next(n);
    void               *p    = ci_llist_node_val(n);
    EXPECT_NE((void *)NULL, p);
    EXPECT_EQ(p, ci_htable_vpvp_get_direct(h, p));
    EXPECT_TRUE(ci_htable_vpvp_get(h, p, NULL));
    EXPECT_TRUE(ci_htable_vpvp_remove(h, p));
    ci_llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ci_llist_len(l));
  EXPECT_EQ(0, ci_htable_vpvp_num_keys(h));

  ci_llist_destroy(l);
  ci_htable_vpvp_destroy(h);
}

TEST_F(LibraryTest, BufSplitStr) {
  ci_buf_t  *buf   = NULL;
  char        **strs  = NULL;
  size_t        nstrs = 0;

  buf = ci_buf_create();
  ci_buf_append_str(buf, "string1\nstring2 string3\t   \nstring4");
  ci_buf_split_str(buf, (const unsigned char *)"\n \t", 2, CI_BUF_SPLIT_TRIM, 0, &strs, &nstrs);
  ci_buf_destroy(buf);

  EXPECT_EQ(4, nstrs);
  EXPECT_TRUE(ci_streq(strs[0], "string1"));
  EXPECT_TRUE(ci_streq(strs[1], "string2"));
  EXPECT_TRUE(ci_streq(strs[2], "string3"));
  EXPECT_TRUE(ci_streq(strs[3], "string4"));
  ci_free_array(strs, nstrs, ci_free);
}

typedef struct {
  ci_socket_t s;
} test_htable_asvp_t;

TEST_F(LibraryTest, HtableAsvp) {
  ci_llist_t       *l = NULL;
  ci_htable_asvp_t *h = NULL;
  ci_llist_node_t  *n = NULL;
  size_t               i;

#define ASVP_TABLE_SIZE 1000

  l = ci_llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ci_htable_asvp_create(ci_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<ASVP_TABLE_SIZE; i++) {
    test_htable_asvp_t *a = (test_htable_asvp_t *)ci_malloc_zero(sizeof(*a));
    EXPECT_NE((void *)NULL, a);
    a->s = (ci_socket_t)i+1;
    EXPECT_NE((void *)NULL, ci_llist_insert_last(l, a));
    EXPECT_TRUE(ci_htable_asvp_insert(h, a->s, a));
  }

  EXPECT_EQ(ASVP_TABLE_SIZE, ci_llist_len(l));
  EXPECT_EQ(ASVP_TABLE_SIZE, ci_htable_asvp_num_keys(h));

  n = ci_llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ci_llist_node_t *next = ci_llist_node_next(n);
    test_htable_asvp_t *a    = (test_htable_asvp_t *)ci_llist_node_val(n);
    EXPECT_NE((void *)NULL, a);
    EXPECT_EQ(a, ci_htable_asvp_get_direct(h, a->s));
    EXPECT_TRUE(ci_htable_asvp_get(h, a->s, NULL));
    EXPECT_TRUE(ci_htable_asvp_remove(h, a->s));
    ci_llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ci_llist_len(l));
  EXPECT_EQ(0, ci_htable_asvp_num_keys(h));

  ci_llist_destroy(l);
  ci_htable_asvp_destroy(h);
}


typedef struct {
  size_t s;
} test_htable_szvp_t;

TEST_F(LibraryTest, HtableSzvp) {
  ci_llist_t       *l = NULL;
  ci_htable_szvp_t *h = NULL;
  ci_llist_node_t  *n = NULL;
  size_t               i;

#define SZVP_TABLE_SIZE 1000

  l = ci_llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ci_htable_szvp_create(ci_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<SZVP_TABLE_SIZE; i++) {
    test_htable_szvp_t *s = (test_htable_szvp_t *)ci_malloc_zero(sizeof(*s));
    EXPECT_NE((void *)NULL, s);
    s->s = i+1;
    EXPECT_NE((void *)NULL, ci_llist_insert_last(l, s));
    EXPECT_TRUE(ci_htable_szvp_insert(h, s->s, s));
  }

  EXPECT_EQ(SZVP_TABLE_SIZE, ci_llist_len(l));
  EXPECT_EQ(SZVP_TABLE_SIZE, ci_htable_szvp_num_keys(h));

  n = ci_llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ci_llist_node_t *next = ci_llist_node_next(n);
    test_htable_szvp_t *s    = (test_htable_szvp_t *)ci_llist_node_val(n);
    EXPECT_NE((void *)NULL, s);
    EXPECT_EQ(s, ci_htable_szvp_get_direct(h, s->s));
    EXPECT_TRUE(ci_htable_szvp_get(h, s->s, NULL));
    EXPECT_TRUE(ci_htable_szvp_remove(h, s->s));
    ci_llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ci_llist_len(l));
  EXPECT_EQ(0, ci_htable_szvp_num_keys(h));

  ci_llist_destroy(l);
  ci_htable_szvp_destroy(h);
}

typedef struct {
  char s[32];
} test_htable_vpstr_t;

TEST_F(LibraryTest, HtableVpstr) {
  ci_llist_t        *l = NULL;
  ci_htable_vpstr_t *h = NULL;
  ci_llist_node_t   *n = NULL;
  size_t                i;

#define VPSTR_TABLE_SIZE 1000

  l = ci_llist_create(ci_free);
  EXPECT_NE((void *)NULL, l);

  h = ci_htable_vpstr_create();
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<VPSTR_TABLE_SIZE; i++) {
    test_htable_vpstr_t *s = (test_htable_vpstr_t *)ci_malloc_zero(sizeof(*s));
    EXPECT_NE((void *)NULL, s);
    snprintf(s->s, sizeof(s->s), "%d", (int)i);
    EXPECT_NE((void *)NULL, ci_llist_insert_last(l, s));
    EXPECT_TRUE(ci_htable_vpstr_insert(h, s, s->s));
  }

  EXPECT_EQ(VPSTR_TABLE_SIZE, ci_llist_len(l));
  EXPECT_EQ(VPSTR_TABLE_SIZE, ci_htable_vpstr_num_keys(h));

  n = ci_llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ci_llist_node_t *next = ci_llist_node_next(n);
    test_htable_vpstr_t *s   = (test_htable_vpstr_t *)ci_llist_node_val(n);
    EXPECT_NE((void *)NULL, s);
    EXPECT_STREQ(s->s, ci_htable_vpstr_get_direct(h, s));
    EXPECT_TRUE(ci_htable_vpstr_get(h, s, NULL));
    EXPECT_TRUE(ci_htable_vpstr_remove(h, s));
    ci_llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ci_llist_len(l));
  EXPECT_EQ(0, ci_htable_vpstr_num_keys(h));

  ci_llist_destroy(l);
  ci_htable_vpstr_destroy(h);
}


typedef struct {
  char s[32];
} test_htable_strvp_t;

TEST_F(LibraryTest, HtableStrvp) {
  ci_llist_t        *l = NULL;
  ci_htable_strvp_t *h = NULL;
  ci_llist_node_t   *n = NULL;
  size_t                i;

#define STRVP_TABLE_SIZE 1000

  l = ci_llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ci_htable_strvp_create(ci_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<STRVP_TABLE_SIZE; i++) {
    test_htable_strvp_t *s = (test_htable_strvp_t *)ci_malloc_zero(sizeof(*s));
    EXPECT_NE((void *)NULL, s);
    snprintf(s->s, sizeof(s->s), "%d", (int)i);
    EXPECT_NE((void *)NULL, ci_llist_insert_last(l, s));
    EXPECT_TRUE(ci_htable_strvp_insert(h, s->s, s));
  }

  EXPECT_EQ(STRVP_TABLE_SIZE, ci_llist_len(l));
  EXPECT_EQ(STRVP_TABLE_SIZE, ci_htable_strvp_num_keys(h));

  n = ci_llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ci_llist_node_t *next = ci_llist_node_next(n);
    test_htable_strvp_t *s   = (test_htable_strvp_t *)ci_llist_node_val(n);
    EXPECT_NE((void *)NULL, s);
    EXPECT_EQ(s, ci_htable_strvp_get_direct(h, s->s));
    EXPECT_TRUE(ci_htable_strvp_get(h, s->s, NULL));
    EXPECT_TRUE(ci_htable_strvp_remove(h, s->s));
    ci_llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ci_llist_len(l));
  EXPECT_EQ(0, ci_htable_strvp_num_keys(h));

  ci_llist_destroy(l);
  ci_htable_strvp_destroy(h);
}

TEST_F(LibraryTest, HtableDict) {
  ci_htable_dict_t  *h = NULL;
  size_t               i;
  char               **keys;
  size_t               nkeys;

#define DICT_TABLE_SIZE 1000

  h = ci_htable_dict_create();
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<DICT_TABLE_SIZE; i++) {
    char key[32];
    char val[32];
    snprintf(key, sizeof(key), "%d", (int)i);
    snprintf(val, sizeof(val), "val%d", (int)i);
    EXPECT_TRUE(ci_htable_dict_insert(h, key, val));
  }

  EXPECT_EQ(DICT_TABLE_SIZE, ci_htable_dict_num_keys(h));

  keys = ci_htable_dict_keys(h, &nkeys);
  for (i=0; i<nkeys; i++) {
    char val[32];
    snprintf(val, sizeof(val), "val%s", keys[i]);
    EXPECT_STREQ(val, ci_htable_dict_get_direct(h, keys[i]));
    EXPECT_TRUE(ci_htable_dict_get(h, keys[i], NULL));
    EXPECT_TRUE(ci_htable_dict_remove(h, keys[i]));
  }
  ci_free_array(keys, nkeys, ci_free);

  EXPECT_EQ(0, ci_htable_dict_num_keys(h));

  ci_htable_dict_destroy(h);
}

TEST_F(DefaultChannelTest, SaveInvalidChannel) {
  ci_slist_t *saved = channel_->servers;
  channel_->servers = NULL;
  struct ci_options opts;
  int optmask = 0;
  EXPECT_EQ(CI_ENODATA, ci_save_options(channel_, &opts, &optmask));
  channel_->servers = saved;
}

// Need to put this in own function due to nested lambda bug
// in VS2013. (C2888)
static int configure_socket(ci_socket_t s) {
  // transposed from ci-process, simplified non-block setter.
#if defined(USE_BLOCKING_SOCKETS)
  return 0; /* returns success */
#elif defined(HAVE_FCNTL_O_NONBLOCK)
  /* most recent unix versions */
  int flags;
  flags = fcntl(s, F_GETFL, 0);
  return fcntl(s, F_SETFL, flags | O_NONBLOCK);
#elif defined(HAVE_IOCTL_FIONBIO)
  /* older unix versions */
  int flags = 1;
  return ioctl(s, FIONBIO, &flags);
#elif defined(HAVE_IOCTLSOCKET_FIONBIO)
#ifdef WATT32
  char flags = 1;
#else
  /* Windows */
  unsigned long flags = 1UL;
#endif
  return ioctlsocket(s, (long)FIONBIO, &flags);
#elif defined(HAVE_IOCTLSOCKET_CAMEL_FIONBIO)
  /* Amiga */
  long flags = 1L;
  return IoctlSocket(s, FIONBIO, flags);
#elif defined(HAVE_SETSOCKOPT_SO_NONBLOCK)
  /* BeOS */
  long b = 1L;
  return setsockopt(s, SOL_SOCKET, SO_NONBLOCK, &b, sizeof(b));
#else
#  error "no non-blocking method was found/used/set"
#endif
}

// TODO: This should not really be in this file, but we need ci config
// flags, and here they are available.
const struct ci_socket_functions VirtualizeIO::default_functions = {
  [](int af, int type, int protocol, void *) -> ci_socket_t {
    auto s = ::socket(af, type, protocol);
    if (s == CI_SOCKET_BAD) {
      return s;
    }
    if (configure_socket(s) != 0) {
      sclose(s);
      return ci_socket_t(-1);
    }
    return s;
  },
  NULL,
  NULL,
  NULL,
  NULL
};


}  // namespace test
}  // namespace ci
