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
// This file includes tests that attempt to do real lookups
// of DNS names using the local machine's live infrastructure.
// As a result, we don't check the results very closely, to allow
// for varying local configurations.

#include "ci-test.h"

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

namespace ci {
namespace test {

// Use the address of CloudFlare's public DNS servers as example addresses that are
// likely to be accessible everywhere/everywhen.  We used to use google but they
// stopped returning reverse dns answers in Dec 2023
unsigned char cflare_addr4[4]  = { 0x01, 0x01, 0x01, 0x01 };
unsigned char cflare_addr6[16] = {
  0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11
};

MATCHER_P(IncludesAtLeastNumAddresses, n, "") {
  if(!arg)
    return false;
  int cnt = 0;
  for (const ci_addrinfo_node* ai = arg->nodes; ai != NULL; ai = ai->ai_next)
    cnt++;
  return cnt >= n;
}

MATCHER_P(OnlyIncludesAddrType, addrtype, "") {
  if(!arg)
    return false;
  for (const ci_addrinfo_node* ai = arg->nodes; ai != NULL; ai = ai->ai_next)
    if (ai->ai_family != addrtype)
      return false;
  return true;
}

MATCHER_P(IncludesAddrType, addrtype, "") {
  if(!arg)
    return false;
  for (const ci_addrinfo_node* ai = arg->nodes; ai != NULL; ai = ai->ai_next)
    if (ai->ai_family == addrtype)
      return true;
  return false;
}

//VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetAddrInfoV4) {
  //struct ci_addrinfo_hints hints = {0, 0, 0, 0};
  //hints.ai_family = AF_INET;
  //AddrInfoResult result;
  //ci_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result);
  //Process();
  //EXPECT_TRUE(result.done_);
  //EXPECT_EQ(CI_SUCCESS, result.status_);
  //EXPECT_THAT(result.ai_, IncludesAtLeastNumAddresses(1));
  //EXPECT_THAT(result.ai_, OnlyIncludesAddrType(AF_INET));
//}

//VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetAddrInfoV6) {
  //struct ci_addrinfo_hints hints = {0, 0, 0, 0};
  //hints.ai_family = AF_INET6;
  //AddrInfoResult result;
  //ci_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result);
  //Process();
  //EXPECT_TRUE(result.done_);
  //EXPECT_EQ(CI_SUCCESS, result.status_);
  //EXPECT_THAT(result.ai_, IncludesAtLeastNumAddresses(1));
  //EXPECT_THAT(result.ai_, OnlyIncludesAddrType(AF_INET6));
//}

//VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetAddrInfoUnspec) {
  //struct ci_addrinfo_hints hints = {0, 0, 0, 0};
  //hints.ai_family = AF_UNSPEC;
  //AddrInfoResult result;
  //ci_getaddrinfo(channel_, "www.google.com.", NULL, &hints, AddrInfoCallback, &result);
  //Process();
  //EXPECT_TRUE(result.done_);
  //EXPECT_EQ(CI_SUCCESS, result.status_);
  //EXPECT_THAT(result.ai_, IncludesAtLeastNumAddresses(2));
  //EXPECT_THAT(result.ai_, IncludesAddrType(AF_INET6));
  //EXPECT_THAT(result.ai_, IncludesAddrType(AF_INET));
//}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetHostByNameV4) {
  HostResult result;
  ci_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET, result.host_.addrtype_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetHostByNameV6) {
  HostResult result;
  ci_gethostbyname(channel_, "www.google.com.", AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET6, result.host_.addrtype_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetHostByAddrV4) {
  HostResult result;
  ci_gethostbyaddr(channel_, cflare_addr4, sizeof(cflare_addr4), AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET, result.host_.addrtype_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetHostByAddrV6) {
  HostResult result;
  ci_gethostbyaddr(channel_, cflare_addr6, sizeof(cflare_addr6), AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_LT(0, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET6, result.host_.addrtype_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetHostByNameFile) {
  struct hostent *host = nullptr;

  // Still need a channel even to query /etc/hosts.
  EXPECT_EQ(CI_ENOTFOUND,
            ci_gethostbyname_file(nullptr, "localhost", AF_INET, &host));

  int rc = ci_gethostbyname_file(channel_, "bogus.mcname", AF_INET, &host);
  EXPECT_EQ(nullptr, host);
  EXPECT_EQ(CI_ENOTFOUND, rc);

  rc = ci_gethostbyname_file(channel_, "localhost", AF_INET, &host);
  if (rc == CI_SUCCESS) {
    EXPECT_NE(nullptr, host);
    ci_free_hostent(host);
  }
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostByNameV4) {
  HostResult result;
  ci_gethostbyname(channel_, "localhost", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != CI_ECONNREFUSED) {
    EXPECT_EQ(CI_SUCCESS, result.status_);
    EXPECT_EQ(1, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET, result.host_.addrtype_);
    EXPECT_NE(SIZE_MAX, result.host_.name_.find("localhost"));
  }
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostByNameV6) {
  HostResult result;
  ci_gethostbyname(channel_, "localhost", AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != CI_ECONNREFUSED) {
    EXPECT_EQ(CI_SUCCESS, result.status_);
    EXPECT_EQ(1, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET6, result.host_.addrtype_);
    std::stringstream ss;
    ss << HostEnt(result.host_);
    EXPECT_NE(SIZE_MAX, result.host_.name_.find("localhost"));
  }
}

TEST_P(DefaultChannelModeTest, LiveGetNonExistLocalhostByNameV4) {
  HostResult result;
  ci_gethostbyname(channel_, "idonotexist.localhost", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != CI_ECONNREFUSED) {
    EXPECT_EQ(CI_SUCCESS, result.status_);
    EXPECT_EQ(1, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET, result.host_.addrtype_);
    EXPECT_NE(SIZE_MAX, result.host_.name_.find("idonotexist.localhost"));
  }
}

TEST_P(DefaultChannelModeTest, LiveGetNonExistLocalhostByNameV6) {
  HostResult result;
  ci_gethostbyname(channel_, "idonotexist.localhost", AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != CI_ECONNREFUSED) {
    EXPECT_EQ(CI_SUCCESS, result.status_);
    EXPECT_EQ(1, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET6, result.host_.addrtype_);
    std::stringstream ss;
    ss << HostEnt(result.host_);
    EXPECT_NE(SIZE_MAX, result.host_.name_.find("idonotexist.localhost"));
  }
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostByNameIPV4) {
  HostResult result;
  ci_gethostbyname(channel_, "127.0.0.1", AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_EQ(1, (int)result.host_.addrs_.size());
  EXPECT_EQ(AF_INET, result.host_.addrtype_);
  std::stringstream ss;
  ss << HostEnt(result.host_);
  EXPECT_EQ("{'127.0.0.1' aliases=[] addrs=[127.0.0.1]}", ss.str());
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostByNameIPV6) {
  HostResult result;
  ci_gethostbyname(channel_, "::1", AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != CI_ENOTFOUND) {
    EXPECT_EQ(CI_SUCCESS, result.status_);
    EXPECT_EQ(1, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET6, result.host_.addrtype_);
    std::stringstream ss;
    ss << HostEnt(result.host_);
    EXPECT_EQ("{'::1' aliases=[] addrs=[0000:0000:0000:0000:0000:0000:0000:0001]}", ss.str());
  }
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostFailFamily) {
  HostResult result;
  ci_gethostbyname(channel_, "127.0.0.1", AF_INET+AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_ENOTIMP, result.status_);
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostByAddrV4) {
  HostResult result;
  struct in_addr addr;
  addr.s_addr = htonl(INADDR_LOOPBACK);
  ci_gethostbyaddr(channel_, &addr, sizeof(addr), AF_INET, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != CI_ENOTFOUND) {
    EXPECT_EQ(CI_SUCCESS, result.status_);
    EXPECT_LT(0, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET, result.host_.addrtype_);
    // oddly, travis does not resolve to localhost, but a random hostname starting with travis-job
    if (result.host_.name_.find("travis-job") == SIZE_MAX) {
        EXPECT_NE(SIZE_MAX,
                  result.host_.name_.find("localhost"));
    }
  }
}

TEST_P(DefaultChannelModeTest, LiveGetLocalhostByAddrV6) {
  HostResult result;
  struct in6_addr addr;
  memset(&addr, 0, sizeof(addr));
  addr.s6_addr[15] = 1;  // in6addr_loopback
  ci_gethostbyaddr(channel_, &addr, sizeof(addr), AF_INET6, HostCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  if (result.status_ != CI_ENOTFOUND) {
    EXPECT_EQ(CI_SUCCESS, result.status_);
    EXPECT_LT(0, (int)result.host_.addrs_.size());
    EXPECT_EQ(AF_INET6, result.host_.addrtype_);
    const std::string& name = result.host_.name_;
    EXPECT_TRUE(SIZE_MAX != name.find("localhost") ||
                SIZE_MAX != name.find("ip6-loopback"));
  }
}

TEST_P(DefaultChannelModeTest, LiveGetHostByAddrFailFamily) {
  HostResult result;
  unsigned char addr[4] = {8, 8, 8, 8};
  ci_gethostbyaddr(channel_, addr, sizeof(addr), AF_INET6+AF_INET,
                     HostCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_ENOTIMP, result.status_);
}

TEST_P(DefaultChannelModeTest, LiveGetHostByAddrFailAddrSize) {
  HostResult result;
  unsigned char addr[4] = {8, 8, 8, 8};
  ci_gethostbyaddr(channel_, addr, sizeof(addr) - 1, AF_INET,
                     HostCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_ENOTIMP, result.status_);
}

TEST_P(DefaultChannelModeTest, LiveGetHostByAddrFailAlloc) {
  HostResult result;
  unsigned char addr[4] = {8, 8, 8, 8};
  SetAllocFail(1);
  ci_gethostbyaddr(channel_, addr, sizeof(addr), AF_INET,
                     HostCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_ENOMEM, result.status_);
}

INSTANTIATE_TEST_SUITE_P(Modes, DefaultChannelModeTest,
                        ::testing::Values("f", "b", "fb", "bf"));

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveSearchA) {
  SearchResult result;
  ci_search(channel_, "www.youtube.com.", C_IN, T_A,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveSearchEmptyA) {
  SearchResult result;
  ci_search(channel_, "", C_IN, T_A,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_NE(CI_SUCCESS, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveSearchNS) {
  SearchResult result;
  ci_search(channel_, "google.com.", C_IN, T_NS,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveSearchMX) {
  SearchResult result;
  ci_search(channel_, "google.com.", C_IN, T_MX,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveSearchTXT) {
  SearchResult result;
  ci_search(channel_, "google.com.", C_IN, T_TXT,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveSearchSOA) {
  SearchResult result;
  ci_search(channel_, "google.com.", C_IN, T_SOA,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveSearchSRV) {
  SearchResult result;
  ci_search(channel_, "_imap._tcp.gmail.com.", C_IN, T_SRV,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveSearchANY) {
  SearchResult result;
  ci_search(channel_, "google.com.", C_IN, T_ANY,
              SearchCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV4) {
  NameInfoResult result;
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(53);
  sockaddr.sin_addr.s_addr = htonl(0x08080808);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_UDP,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  if (verbose) std::cerr << "8.8.8.8:53 => " << result.node_ << "/" << result.service_ << std::endl;
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV4NoPort) {
  NameInfoResult result;
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(0);
  sockaddr.sin_addr.s_addr = htonl(0x08080808);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_UDP,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  if (verbose) std::cerr << "8.8.8.8:0 => " << result.node_ << "/" << result.service_ << std::endl;
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV4UnassignedPort) {
  NameInfoResult result;
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(4);  // Unassigned at IANA
  sockaddr.sin_addr.s_addr = htonl(0x08080808);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_UDP,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  if (verbose) std::cerr << "8.8.8.8:4 => " << result.node_ << "/" << result.service_ << std::endl;
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV6Both) {
  NameInfoResult result;
  struct sockaddr_in6 sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin6_family = AF_INET6;
  sockaddr.sin6_port = htons(53);
  memcpy(sockaddr.sin6_addr.s6_addr, cflare_addr6, 16);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_TCP|CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_NOFQDN,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  if (verbose) std::cerr << "[2001:4860:4860::8888]:53 => " << result.node_ << "/" << result.service_ << std::endl;
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV6Neither) {
  NameInfoResult result;
  struct sockaddr_in6 sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin6_family = AF_INET6;
  sockaddr.sin6_port = htons(53);
  memcpy(sockaddr.sin6_addr.s6_addr, cflare_addr6, 16);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_TCP|CI_NI_NOFQDN,  // Neither specified => assume lookup host.
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  if (verbose) std::cerr << "[2001:4860:4860::8888]:53 => " << result.node_ << "/" << result.service_ << std::endl;
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV4Numeric) {
  NameInfoResult result;
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(53);
  sockaddr.sin_addr.s_addr = htonl(0x08080808);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_TCP|CI_NI_NUMERICHOST,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_EQ("8.8.8.8", result.node_);
  if (verbose) std::cerr << "8.8.8.8:53 => " << result.node_ << "/" << result.service_ << std::endl;
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV6Numeric) {
  NameInfoResult result;
  struct sockaddr_in6 sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin6_family = AF_INET6;
  sockaddr.sin6_port = htons(53);
  memcpy(sockaddr.sin6_addr.s6_addr, cflare_addr6, 16);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_DCCP|CI_NI_NUMERICHOST,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_EQ("2606:4700:4700::1111%0", result.node_);
  if (verbose) std::cerr << "[2606:4700:4700::1111]:53 => " << result.node_ << "/" << result.service_ << std::endl;
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV6LinkLocal) {
  NameInfoResult result;
  struct sockaddr_in6 sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin6_family = AF_INET6;
  sockaddr.sin6_port = htons(53);
  unsigned char addr6[16] = {0xfe, 0x80, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x04};
  memcpy(sockaddr.sin6_addr.s6_addr, addr6, 16);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_DCCP|CI_NI_NUMERICHOST,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_EQ("fe80:102:102::304%0", result.node_);
  if (verbose) std::cerr << "[fe80:102:102::304]:53 => " << result.node_ << "/" << result.service_ << std::endl;
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV4NotFound) {
  NameInfoResult result;
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(4);  // Port 4 unassigned at IANA
  // RFC5737 says 192.0.2.0 should not be used publicly.
  sockaddr.sin_addr.s_addr = htonl(0xC0000200);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_UDP,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_EQ("192.0.2.0", result.node_);
  if (verbose) std::cerr << "192.0.2.0:53 => " << result.node_ << "/" << result.service_ << std::endl;
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV4NotFoundFail) {
  NameInfoResult result;
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(53);
  // RFC5737 says 192.0.2.0 should not be used publicly.
  sockaddr.sin_addr.s_addr = htonl(0xC0000200);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_UDP|CI_NI_NAMEREQD,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_ENOTFOUND, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoV6NotFound) {
  NameInfoResult result;
  struct sockaddr_in6 sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin6_family = AF_INET6;
  sockaddr.sin6_port = htons(53);
  // 2001:db8::/32 is only supposed to be used in documentation.
  unsigned char addr6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x02, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x04};
  memcpy(sockaddr.sin6_addr.s6_addr, addr6, 16);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_UDP,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_EQ("2001:db8:102::304%0", result.node_);
  if (verbose) std::cerr << "[2001:db8:102::304]:53 => " << result.node_ << "/" << result.service_ << std::endl;
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInvalidFamily) {
  NameInfoResult result;
  struct sockaddr_in6 sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin6_family = AF_INET6 + AF_INET;
  sockaddr.sin6_port = htons(53);
  memcpy(sockaddr.sin6_addr.s6_addr, cflare_addr6, 16);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_UDP,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_ENOTIMP, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInvalidFlags) {
  NameInfoResult result;
  struct sockaddr_in6 sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin6_family = AF_INET6;
  sockaddr.sin6_port = htons(53);
  memcpy(sockaddr.sin6_addr.s6_addr, cflare_addr6, 16);
  // Ask for both a name-required, and a numeric host.
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_UDP|CI_NI_NUMERICHOST|CI_NI_NAMEREQD,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_EBADFLAGS, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetServiceInfo) {
  NameInfoResult result;
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(53);
  sockaddr.sin_addr.s_addr = htonl(0x08080808);
  // Just look up service info
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPSERVICE|CI_NI_SCTP,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_EQ("", result.node_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetServiceInfoNumeric) {
  NameInfoResult result;
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(53);
  sockaddr.sin_addr.s_addr = htonl(0x08080808);
  // Just look up service info
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPSERVICE|CI_NI_SCTP|CI_NI_NUMERICSERV,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_SUCCESS, result.status_);
  EXPECT_EQ("", result.node_);
  EXPECT_EQ("53", result.service_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, LiveGetNameInfoAllocFail) {
  NameInfoResult result;
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(53);
  sockaddr.sin_addr.s_addr = htonl(0x08080808);
  SetAllocFail(1);
  ci_getnameinfo(channel_, (const struct sockaddr*)&sockaddr, sizeof(sockaddr),
                   CI_NI_LOOKUPHOST|CI_NI_LOOKUPSERVICE|CI_NI_UDP,
                   NameInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(CI_ENOMEM, result.status_);
}

VIRT_NONVIRT_TEST_F(DefaultChannelTest, GetSock) {
  ci_socket_t socks[3] = {CI_SOCKET_BAD, CI_SOCKET_BAD, CI_SOCKET_BAD};
  int bitmask = ci_getsock(channel_, socks, 3);
  EXPECT_EQ(0, bitmask);
  bitmask = ci_getsock(channel_, nullptr, 0);
  EXPECT_EQ(0, bitmask);

  // Ask again with a pending query.
  HostResult result;
  ci_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  bitmask = ci_getsock(channel_, socks, 3);
  EXPECT_NE(0, bitmask);

  size_t sock_cnt = 0;
  for (size_t i=0; i<3; i++) {
    if (CI_GETSOCK_READABLE(bitmask, i) || CI_GETSOCK_WRITABLE(bitmask, i)) {
      EXPECT_NE(CI_SOCKET_BAD, socks[i]);
      if (socks[i] != CI_SOCKET_BAD)
        sock_cnt++;
    }
  }
  EXPECT_NE((size_t)0, sock_cnt);

  bitmask = ci_getsock(channel_, nullptr, 0);
  EXPECT_EQ(0, bitmask);

  Process();
}

TEST_F(LibraryTest, GetTCPSock) {
  ci_channel_t *channel;
  struct ci_options opts;
  memset(&opts, 0, sizeof(opts));
  opts.tcp_port = 53;
  opts.flags = CI_FLAG_USEVC;
  int optmask = CI_OPT_TCP_PORT | CI_OPT_FLAGS;
  EXPECT_EQ(CI_SUCCESS, ci_init_options(&channel, &opts, optmask));
  EXPECT_NE(nullptr, channel);

  ci_socket_t socks[3] = {CI_SOCKET_BAD, CI_SOCKET_BAD, CI_SOCKET_BAD};
  int bitmask = ci_getsock(channel, socks, 3);
  EXPECT_EQ(0, bitmask);
  bitmask = ci_getsock(channel, nullptr, 0);
  EXPECT_EQ(0, bitmask);

  // Ask again with a pending query.
  HostResult result;
  ci_gethostbyname(channel, "www.google.com.", AF_INET, HostCallback, &result);
  bitmask = ci_getsock(channel, socks, 3);
  EXPECT_NE(0, bitmask);

  size_t sock_cnt = 0;
  for (size_t i=0; i<3; i++) {
    if (CI_GETSOCK_READABLE(bitmask, i) || CI_GETSOCK_WRITABLE(bitmask, i)) {
      EXPECT_NE(CI_SOCKET_BAD, socks[i]);
      if (socks[i] != CI_SOCKET_BAD)
        sock_cnt++;
    }
  }
  EXPECT_NE((size_t)0, sock_cnt);

  bitmask = ci_getsock(channel, nullptr, 0);
  EXPECT_EQ(0, bitmask);

  ProcessWork(channel, NoExtraFDs, nullptr);

  ci_destroy(channel);
}

TEST_F(DefaultChannelTest, VerifySocketFunctionCallback) {
  VirtualizeIO vio(channel_);

  auto my_functions = VirtualizeIO::default_functions;
  size_t count = 0;

  my_functions.asocket = [](int af, int type, int protocol, void * p) -> ci_socket_t {
    EXPECT_NE(nullptr, p);
    (*reinterpret_cast<size_t *>(p))++;
    return ::socket(af, type, protocol);
  };

  ci_set_socket_functions(channel_, &my_functions, &count);

  {
    count = 0;
    HostResult result;
    ci_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
    Process();

    EXPECT_TRUE(result.done_);
    EXPECT_NE((size_t)0, count);
  }

  {
    count = 0;
    ci_channel_t *copy;
    EXPECT_EQ(CI_SUCCESS, ci_dup(&copy, channel_));

    HostResult result;
    ci_gethostbyname(copy, "www.google.com.", AF_INET, HostCallback, &result);

    ProcessWork(copy, NoExtraFDs, nullptr);

    EXPECT_TRUE(result.done_);
    ci_destroy(copy);
    EXPECT_NE((size_t)0, count);
  }

}

TEST_F(DefaultChannelTest, LiveSetServers) {
  struct ci_addr_node server1;
  struct ci_addr_node server2;
  server1.next = &server2;
  server1.family = AF_INET;
  server1.addr.addr4.s_addr = htonl(0x01020304);
  server2.next = nullptr;
  server2.family = AF_INET;
  server2.addr.addr4.s_addr = htonl(0x02030405);

  HostResult result;
  ci_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  EXPECT_EQ(CI_SUCCESS, ci_set_servers(channel_, &server1));
  ci_cancel(channel_);
}

TEST_F(DefaultChannelTest, LiveSetServersPorts) {
  struct ci_addr_port_node server1;
  struct ci_addr_port_node server2;
  server1.next = &server2;
  server1.family = AF_INET;
  server1.addr.addr4.s_addr = htonl(0x01020304);
  server1.udp_port = 111;
  server1.tcp_port = 111;
  server2.next = nullptr;
  server2.family = AF_INET;
  server2.addr.addr4.s_addr = htonl(0x02030405);
  server2.udp_port = 0;
  server2.tcp_port = 0;
  EXPECT_EQ(CI_ENODATA, ci_set_servers_ports(nullptr, &server1));

  // Change while pending will requeue any requests to new servers
  HostResult result;
  ci_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  EXPECT_EQ(CI_SUCCESS, ci_set_servers_ports(channel_, &server1));
  ci_cancel(channel_);
}

TEST_F(DefaultChannelTest, LiveSetServersCSV) {
  HostResult result;
  ci_gethostbyname(channel_, "www.google.com.", AF_INET, HostCallback, &result);
  // Change while pending will requeue any requests to new servers
  EXPECT_EQ(CI_SUCCESS, ci_set_servers_csv(channel_, "1.2.3.4,2.3.4.5"));
  EXPECT_EQ(CI_SUCCESS, ci_set_servers_ports_csv(channel_, "1.2.3.4:56,2.3.4.5:67"));
  ci_cancel(channel_);
}


}  // namespace test
}  // namespace ci
