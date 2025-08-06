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

extern "C" {
  #include "ci_private.h"
}

// library initialization is only needed for windows builds
#ifdef WIN32
#define EXPECTED_NONINIT CI_ENOTINITIALIZED
#else
#define EXPECTED_NONINIT CI_SUCCESS
#endif

namespace ci {
namespace test {

TEST(LibraryInit, Basic) {
  EXPECT_EQ(EXPECTED_NONINIT, ci_library_initialized());
  EXPECT_EQ(CI_SUCCESS, ci_library_init(CI_LIB_INIT_ALL));
  EXPECT_EQ(CI_SUCCESS, ci_library_initialized());
  ci_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ci_library_initialized());
}

TEST(LibraryInit, UnexpectedCleanup) {
  EXPECT_EQ(EXPECTED_NONINIT, ci_library_initialized());
  ci_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ci_library_initialized());
}

TEST(LibraryInit, Nested) {
  EXPECT_EQ(EXPECTED_NONINIT, ci_library_initialized());
  EXPECT_EQ(CI_SUCCESS, ci_library_init(CI_LIB_INIT_ALL));
  EXPECT_EQ(CI_SUCCESS, ci_library_initialized());
  EXPECT_EQ(CI_SUCCESS, ci_library_init(CI_LIB_INIT_ALL));
  EXPECT_EQ(CI_SUCCESS, ci_library_initialized());
  ci_library_cleanup();
  EXPECT_EQ(CI_SUCCESS, ci_library_initialized());
  ci_library_cleanup();
  EXPECT_EQ(EXPECTED_NONINIT, ci_library_initialized());
}

TEST(LibraryInit, BasicChannelInit) {
  EXPECT_EQ(CI_SUCCESS, ci_library_init(CI_LIB_INIT_ALL));
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));
  EXPECT_NE(nullptr, channel);
  ci_destroy(channel);
  ci_library_cleanup();
}

TEST_F(LibraryTest, OptionsChannelInit) {
  struct ci_options opts;
  int optmask = 0;
  memset(&opts, 0, sizeof(opts));
  opts.flags = CI_FLAG_USEVC | CI_FLAG_PRIMARY;
  optmask |= CI_OPT_FLAGS;
  opts.timeout = 2000;
  optmask |= CI_OPT_TIMEOUTMS;
  opts.tries = 2;
  optmask |= CI_OPT_TRIES;
  opts.ndots = 4;
  optmask |= CI_OPT_NDOTS;
  opts.udp_port = 54;
  optmask |= CI_OPT_MAXTIMEOUTMS;
  opts.maxtimeout = 10000;
  optmask |= CI_OPT_UDP_PORT;
  opts.tcp_port = 54;
  optmask |= CI_OPT_TCP_PORT;
  opts.socket_send_buffer_size = 514;
  optmask |= CI_OPT_SOCK_SNDBUF;
  opts.socket_receive_buffer_size = 514;
  optmask |= CI_OPT_SOCK_RCVBUF;
  opts.ednspsz = 1280;
  optmask |= CI_OPT_EDNSPSZ;
  opts.nservers = 2;
  opts.servers = (struct in_addr *)malloc((size_t)opts.nservers * sizeof(struct in_addr));
  opts.servers[0].s_addr = htonl(0x01020304);
  opts.servers[1].s_addr = htonl(0x02030405);
  optmask |= CI_OPT_SERVERS;
  opts.ndomains = 2;
  opts.domains = (char **)malloc((size_t)opts.ndomains * sizeof(char *));
  opts.domains[0] = strdup("example.com");
  opts.domains[1] = strdup("example2.com");
  optmask |= CI_OPT_DOMAINS;
  opts.lookups = strdup("b");
  optmask |= CI_OPT_LOOKUPS;
  optmask |= CI_OPT_ROTATE;
  opts.resolvconf_path = strdup("/etc/resolv.conf");
  optmask |= CI_OPT_RESOLVCONF;
  opts.hosts_path = strdup("/etc/hosts");
  optmask |= CI_OPT_HOSTS_FILE;

  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init_options(&channel, &opts, optmask));
  EXPECT_NE(nullptr, channel);

  ci_channel_t *channel2 = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_dup(&channel2, channel));
  EXPECT_NE(nullptr, channel2);

  struct ci_options opts2;
  int optmask2 = 0;
  memset(&opts2, 0, sizeof(opts2));
  EXPECT_EQ(CI_SUCCESS, ci_save_options(channel2, &opts2, &optmask2));

  // Note that not all opts-settable fields are saved (e.g.
  // ednspsz, socket_{send,receive}_buffer_size).
  EXPECT_EQ(opts.flags, opts2.flags);
  EXPECT_EQ(opts.timeout, opts2.timeout);
  EXPECT_EQ(opts.tries, opts2.tries);
  EXPECT_EQ(opts.ndots, opts2.ndots);
  EXPECT_EQ(opts.maxtimeout, opts2.maxtimeout);
  EXPECT_EQ(opts.udp_port, opts2.udp_port);
  EXPECT_EQ(opts.tcp_port, opts2.tcp_port);
  EXPECT_EQ(1, opts2.nservers);  // Truncated by CI_FLAG_PRIMARY
  EXPECT_EQ(opts.servers[0].s_addr, opts2.servers[0].s_addr);
  EXPECT_EQ(opts.ndomains, opts2.ndomains);
  EXPECT_EQ(std::string(opts.domains[0]), std::string(opts2.domains[0]));
  EXPECT_EQ(std::string(opts.domains[1]), std::string(opts2.domains[1]));
  EXPECT_EQ(std::string(opts.lookups), std::string(opts2.lookups));
  EXPECT_EQ(std::string(opts.resolvconf_path), std::string(opts2.resolvconf_path));
  EXPECT_EQ(std::string(opts.hosts_path), std::string(opts2.hosts_path));

  ci_destroy_options(&opts);
  ci_destroy_options(&opts2);
  ci_destroy(channel);
  ci_destroy(channel2);
}

TEST_F(LibraryTest, ChannelAllocFail) {
  ci_channel_t *channel;
  for (int ii = 1; ii <= 25; ii++) {
    ClearFails();
    SetAllocFail(ii);
    channel = nullptr;
    int rc = ci_init(&channel);
    // The number of allocations depends on local environment, so don't expect ENOMEM.
    if (rc == CI_ENOMEM) {
      EXPECT_EQ(nullptr, channel);
    } else {
      ci_destroy(channel);
    }
  }
}

TEST_F(LibraryTest, OptionsChannelAllocFail) {
  struct ci_options opts;
  int optmask = 0;
  memset(&opts, 0, sizeof(opts));
  opts.flags = CI_FLAG_USEVC;
  optmask |= CI_OPT_FLAGS;
  opts.timeout = 2;
  optmask |= CI_OPT_TIMEOUT;
  opts.tries = 2;
  optmask |= CI_OPT_TRIES;
  opts.ndots = 4;
  optmask |= CI_OPT_NDOTS;
  opts.udp_port = 54;
  optmask |= CI_OPT_UDP_PORT;
  opts.tcp_port = 54;
  optmask |= CI_OPT_TCP_PORT;
  opts.socket_send_buffer_size = 514;
  optmask |= CI_OPT_SOCK_SNDBUF;
  opts.socket_receive_buffer_size = 514;
  optmask |= CI_OPT_SOCK_RCVBUF;
  opts.ednspsz = 1280;
  optmask |= CI_OPT_EDNSPSZ;
  opts.nservers = 2;
  opts.servers = (struct in_addr *)malloc((size_t)opts.nservers * sizeof(struct in_addr));
  opts.servers[0].s_addr = htonl(0x01020304);
  opts.servers[1].s_addr = htonl(0x02030405);
  optmask |= CI_OPT_SERVERS;
  opts.ndomains = 2;
  opts.domains = (char **)malloc((size_t)opts.ndomains * sizeof(char *));
  opts.domains[0] = strdup("example.com");
  opts.domains[1] = strdup("example2.com");
  optmask |= CI_OPT_DOMAINS;
  opts.lookups = strdup("b");
  optmask |= CI_OPT_LOOKUPS;
  optmask |= CI_OPT_ROTATE;
  opts.resolvconf_path = strdup("/etc/resolv.conf");
  optmask |= CI_OPT_RESOLVCONF;
  opts.hosts_path = strdup("/etc/hosts");
  optmask |= CI_OPT_HOSTS_FILE;

  ci_channel_t *channel = nullptr;
  for (int ii = 1; ii <= 8; ii++) {
    ClearFails();
    SetAllocFail(ii);
    int rc = ci_init_options(&channel, &opts, optmask);
    if (rc == CI_ENOMEM) {
      EXPECT_EQ(nullptr, channel);
    } else {
      EXPECT_EQ(CI_SUCCESS, rc);
      ci_destroy(channel);
      channel = nullptr;
    }
  }
  ClearFails();

  EXPECT_EQ(CI_SUCCESS, ci_init_options(&channel, &opts, optmask));
  EXPECT_NE(nullptr, channel);

  // Add some servers and a sortlist for flavour.
  EXPECT_EQ(CI_SUCCESS,
            ci_set_servers_csv(channel, "1.2.3.4,0102:0304:0506:0708:0910:1112:1314:1516,2.3.4.5"));
  EXPECT_EQ(CI_SUCCESS, ci_set_sortlist(channel, "1.2.3.4 2.3.4.5"));

  ci_channel_t *channel2 = nullptr;
  for (int ii = 1; ii <= 18; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(CI_ENOMEM, ci_dup(&channel2, channel)) << ii;
    EXPECT_EQ(nullptr, channel2) << ii;
  }

  struct ci_options opts2;
  int optmask2 = 0;
  for (int ii = 1; ii <= 6; ii++) {
    memset(&opts2, 0, sizeof(opts2));
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(CI_ENOMEM, ci_save_options(channel, &opts2, &optmask2)) << ii;
    // May still have allocations even after CI_ENOMEM return code.
    ci_destroy_options(&opts2);
  }
  ci_destroy_options(&opts);
  ci_destroy(channel);
}

TEST_F(LibraryTest, FailChannelInit) {
  EXPECT_EQ(CI_SUCCESS,
            ci_library_init_mem(CI_LIB_INIT_ALL,
                                  &LibraryTest::amalloc,
                                  &LibraryTest::afree,
                                  &LibraryTest::arealloc));
  SetAllocFail(1);
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_ENOMEM, ci_init(&channel));
  EXPECT_EQ(nullptr, channel);
  ci_library_cleanup();
}

#ifndef WIN32
TEST_F(LibraryTest, EnvInit) {
  ci_channel_t *channel = nullptr;
  EnvValue v1("LOCALDOMAIN", "this.is.local");
  EnvValue v2("RES_OPTIONS", "options debug ndots:3 retry:3 rotate retrans:2");
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));
  ci_destroy(channel);
}

TEST_F(LibraryTest, EnvInitModernOptions) {
  ci_channel_t *channel = nullptr;
  EnvValue v1("LOCALDOMAIN", "this.is.local");
  EnvValue v2("RES_OPTIONS", "options debug retrans:2 ndots:3 attempts:4 timeout:5 rotate");
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));

  channel->optmask |= CI_OPT_TRIES;
  channel->optmask |= CI_OPT_TIMEOUTMS;

  struct ci_options opts;
  memset(&opts, 0, sizeof(opts));
  int optmask = 0;
  EXPECT_EQ(CI_SUCCESS, ci_save_options(channel, &opts, &optmask));
  EXPECT_EQ(5000, opts.timeout);
  EXPECT_EQ(4, opts.tries);

  ci_destroy(channel);
}

TEST_F(LibraryTest, EnvInitAllocFail) {
  ci_channel_t *channel;
  EnvValue v1("LOCALDOMAIN", "this.is.local");
  EnvValue v2("RES_OPTIONS", "options debug ndots:3 retry:3 rotate retrans:2");
  for (int ii = 1; ii <= 10; ii++) {
    ClearFails();
    SetAllocFail(ii);
    channel = nullptr;
    int rc = ci_init(&channel);
    if (rc == CI_SUCCESS) {
      ci_destroy(channel);
    } else {
      EXPECT_EQ(CI_ENOMEM, rc);
    }
  }
}
#endif

TEST_F(DefaultChannelTest, SetAddresses) {
  ci_set_local_ip4(channel_, 0x01020304);
  byte addr6[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
  ci_set_local_ip6(channel_, addr6);
  ci_set_local_dev(channel_, "dummy");
}

TEST_F(DefaultChannelTest, SetSortlistFailures) {
  EXPECT_EQ(CI_ENODATA, ci_set_sortlist(nullptr, "1.2.3.4"));
  EXPECT_EQ(CI_EBADSTR, ci_set_sortlist(channel_, "111.111.111.111*/16"));
  EXPECT_EQ(CI_EBADSTR, ci_set_sortlist(channel_, "111.111.111.111/255.255.255.240*"));
  EXPECT_EQ(CI_EBADSTR, ci_set_sortlist(channel_, "1 0123456789012345"));
  EXPECT_EQ(CI_EBADSTR, ci_set_sortlist(channel_, "1 /01234567890123456789012345678901"));
  EXPECT_EQ(CI_EBADSTR, ci_set_sortlist(channel_, "xyzzy ; lwk"));
  EXPECT_EQ(CI_EBADSTR, ci_set_sortlist(channel_, "xyzzy ; 0x123"));
}

TEST_F(DefaultChannelTest, SetSortlistVariants) {
  EXPECT_EQ(CI_SUCCESS, ci_set_sortlist(channel_, "1.2.3.4"));
  EXPECT_EQ(CI_SUCCESS, ci_set_sortlist(channel_, "1.2.3.4 ; 2.3.4.5"));
  EXPECT_EQ(CI_SUCCESS, ci_set_sortlist(channel_, "1.2.3.4/26;1234::5678/126;4.5.6.7;5678::1234"));
  EXPECT_EQ(CI_SUCCESS, ci_set_sortlist(channel_, " 1.2.3.4/26 1234::5678/126   4.5.6.7 5678::1234  "));
  EXPECT_EQ(CI_SUCCESS, ci_set_sortlist(channel_, "129.1.1.1"));
  EXPECT_EQ(CI_SUCCESS, ci_set_sortlist(channel_, "192.1.1.1"));
  EXPECT_EQ(CI_SUCCESS, ci_set_sortlist(channel_, "224.1.1.1"));
  EXPECT_EQ(CI_SUCCESS, ci_set_sortlist(channel_, "225.1.1.1"));
}

TEST_F(DefaultChannelTest, SetSortlistAllocFail) {
  for (int ii = 1; ii <= 3; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(CI_ENOMEM, ci_set_sortlist(channel_, "12.13.0.0/16 1234::5678/40 1.2.3.4")) << ii;
  }
}

#ifdef USE_WINSOCK
TEST(Init, NoLibraryInit) {
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_ENOTINITIALIZED, ci_init(&channel));
}
#endif

#ifdef HAVE_CONTAINER
// These tests rely on the ability of non-root users to create a chroot
// using Linux namespaces.


// The library uses a variety of information sources to initialize a channel,
// in particular to determine:
//  - search: the search domains to use
//  - servers: the name servers to use
//  - lookup: whether to check files or DNS or both (e.g. "fb")
//  - options: various resolver options
//  - sortlist: the order of preference for IP addresses
//
// The first source from the following list is used:
//  - init_by_options(): explicitly specified values in struct ci_options
//  - init_by_environment(): values from the environment:
//     - LOCALDOMAIN -> search (single value)
//     - RES_OPTIONS -> options
//  - init_by_resolv_conf(): values from various config files:
//     - /etc/resolv.conf -> search, lookup, servers, sortlist, options
//     - /etc/nsswitch.conf -> lookup
//     - /etc/host.conf -> lookup
//     - /etc/svc.conf -> lookup
//  - init_by_defaults(): fallback values:
//     - gethostname(3) -> domain
//     - "fb" -> lookup

NameContentList filelist = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "sortlist 1.2.3.4/16 2.3.4.5\n"
                       "search first.com second.com\n"},
  {"/etc/hosts", "3.4.5.6 ahostname.com\n"},
  {"/etc/nsswitch.conf", "hosts: files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerChannelInit,
                 "myhostname", "mydomainname.org", filelist) {
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));
  std::string actual = GetNameServers(channel);
  std::string expected = "1.2.3.4:53";
  EXPECT_EQ(expected, actual);
  EXPECT_EQ(2, channel->ndomains);
  EXPECT_EQ(std::string("first.com"), std::string(channel->domains[0]));
  EXPECT_EQ(std::string("second.com"), std::string(channel->domains[1]));

  HostResult result;
  ci_gethostbyname(channel, "ahostname.com", AF_INET, HostCallback, &result);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;

  EXPECT_EQ("{'ahostname.com' aliases=[] addrs=[3.4.5.6]}", ss.str());

  ci_destroy(channel);
  return HasFailure();
}

CONTAINED_TEST_F(LibraryTest, ContainerSortlistOptionInit,
                 "myhostname", "mydomainname.org", filelist) {
  ci_channel_t *channel = nullptr;
  struct ci_options opts;
  memset(&opts, 0, sizeof(opts));
  int optmask = 0;
  optmask |= CI_OPT_SORTLIST;
  opts.nsort = 0;
  // Explicitly specifying an empty sortlist in the options should override the
  // environment.
  EXPECT_EQ(CI_SUCCESS, ci_init_options(&channel, &opts, optmask));
  EXPECT_EQ(0, channel->nsort);
  EXPECT_EQ(nullptr, channel->sortlist);
  EXPECT_EQ(CI_OPT_SORTLIST, (channel->optmask & CI_OPT_SORTLIST));

  ci_destroy(channel);
  return HasFailure();
}

NameContentList fullresolv = {
  {"/etc/resolv.conf", " nameserver   1.2.3.4 \n"
                       "search   first.com second.com\n"
                       "lookup bind\n"
                       "options debug ndots:5\n"
                       "sortlist 1.2.3.4/16 2.3.4.5\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerFullResolvInit,
                 "myhostname", "mydomainname.org", fullresolv) {
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));

  EXPECT_EQ(std::string("b"), std::string(channel->lookups));
  EXPECT_EQ(5, channel->ndots);

  ci_destroy(channel);
  return HasFailure();
}

// Allow path for resolv.conf to be configurable
NameContentList myresolvconf = {
  {"/tmp/myresolv.cnf", " nameserver   1.2.3.4 \n"
                       "search   first.com second.com\n"
                       "lookup bind\n"
                       "options debug ndots:5\n"
                       "sortlist 1.2.3.4/16 2.3.4.5\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerMyResolvConfInit,
                 "myhostname", "mydomain.org", myresolvconf) {
  char filename[] = "/tmp/myresolv.cnf";
  ci_channel_t *channel = nullptr;
  struct ci_options options;
  memset(&options, 0, sizeof(options));
  options.resolvconf_path = strdup(filename);
  int optmask = CI_OPT_RESOLVCONF;
  EXPECT_EQ(CI_SUCCESS, ci_init_options(&channel, &options, optmask));

  optmask = 0;
  free(options.resolvconf_path);
  options.resolvconf_path = NULL;

  EXPECT_EQ(CI_SUCCESS, ci_save_options(channel, &options, &optmask));
  EXPECT_EQ(CI_OPT_RESOLVCONF, (optmask & CI_OPT_RESOLVCONF));
  EXPECT_EQ(std::string(filename), std::string(options.resolvconf_path));

  ci_destroy_options(&options);
  ci_destroy(channel);
  return HasFailure();
}

// Allow hosts path to be configurable
NameContentList myhosts = {
  {"/tmp/hosts", "10.0.12.26     foobar\n"
                 "2001:A0:C::1A  foobar\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerMyHostsInit,
                 "myhostname", "mydomain.org", myhosts) {
  char filename[] = "/tmp/hosts";
  ci_channel_t *channel = nullptr;
  struct ci_options options;

  options.hosts_path = strdup(filename);
  int optmask = CI_OPT_HOSTS_FILE;
  EXPECT_EQ(CI_SUCCESS, ci_init_options(&channel, &options, optmask));
  memset(&options, 0, sizeof(options));
  optmask = 0;
  free(options.hosts_path);
  options.hosts_path = NULL;

  EXPECT_EQ(CI_SUCCESS, ci_save_options(channel, &options, &optmask));
  EXPECT_EQ(CI_OPT_HOSTS_FILE, (optmask & CI_OPT_HOSTS_FILE));
  EXPECT_EQ(std::string(filename), std::string(options.hosts_path));

  ci_destroy_options(&options);
  ci_destroy(channel);
  return HasFailure();
}

NameContentList svcconf = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "search first.com second.com\n"},
  {"/etc/svc.conf", "hosts= bind\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerSvcConfInit,
                 "myhostname", "mydomainname.org", svcconf) {
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));

  EXPECT_EQ(std::string("b"), std::string(channel->lookups));

  ci_destroy(channel);
  return HasFailure();
}

NameContentList malformedresolvconflookup = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "lookup garbage\n"}};  // malformed line
CONTAINED_TEST_F(LibraryTest, ContainerMalformedResolvConfLookup,
                 "myhostname", "mydomainname.org", malformedresolvconflookup) {
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));

  EXPECT_EQ(std::string("fb"), std::string(channel->lookups));

  ci_destroy(channel);
  return HasFailure();
}

// Failures when expected config filenames are inaccessible.
class MakeUnreadable {
 public:
  explicit MakeUnreadable(const std::string& filename)
    : filename_(filename) {
    chmod(filename_.c_str(), 0000);
  }
  ~MakeUnreadable() { chmod(filename_.c_str(), 0644); }
 private:
  std::string filename_;
};

CONTAINED_TEST_F(LibraryTest, ContainerResolvConfNotReadable,
                 "myhostname", "mydomainname.org", filelist) {
  ci_channel_t *channel = nullptr;
  MakeUnreadable hide("/etc/resolv.conf");
  // Unavailable /etc/resolv.conf falls back to defaults
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));
  return HasFailure();
}
CONTAINED_TEST_F(LibraryTest, ContainerNsswitchConfNotReadable,
                 "myhostname", "mydomainname.org", filelist) {
  ci_channel_t *channel = nullptr;
  // Unavailable /etc/nsswitch.conf falls back to defaults.
  MakeUnreadable hide("/etc/nsswitch.conf");
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));

  EXPECT_EQ(std::string("fb"), std::string(channel->lookups));

  ci_destroy(channel);
  return HasFailure();
}

CONTAINED_TEST_F(LibraryTest, ContainerSvcConfNotReadable,
                 "myhostname", "mydomainname.org", svcconf) {
  ci_channel_t *channel = nullptr;
  // Unavailable /etc/svc.conf falls back to defaults.
  MakeUnreadable hide("/etc/svc.conf");
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));
  ci_destroy(channel);
  return HasFailure();
}

NameContentList rotateenv = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "search first.com second.com\n"
                       "options rotate\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerRotateInit,
                 "myhostname", "mydomainname.org", rotateenv) {
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));

  EXPECT_EQ(CI_TRUE, channel->rotate);

  ci_destroy(channel);
  return HasFailure();
}

CONTAINED_TEST_F(LibraryTest, ContainerRotateOverride,
                 "myhostname", "mydomainname.org", rotateenv) {
  ci_channel_t *channel = nullptr;
  struct ci_options opts;
  memset(&opts, 0, sizeof(opts));
  int optmask = CI_OPT_NOROTATE;
  EXPECT_EQ(CI_SUCCESS, ci_init_options(&channel, &opts, optmask));
  optmask = 0;
  ci_save_options(channel, &opts, &optmask);
  EXPECT_EQ(CI_OPT_NOROTATE, (optmask & CI_OPT_NOROTATE));
  ci_destroy_options(&opts);

  ci_destroy(channel);
  return HasFailure();
}

// Test that blacklisted IPv6 resolves are ignored.  They're filtered from any
// source, so resolv.conf is as good as any.
NameContentList blacklistedIpv6 = {
  {"/etc/resolv.conf", " nameserver 254.192.1.1\n" // 0xfe.0xc0.0x01.0x01
                       " nameserver fec0::dead\n"  // Blacklisted
                       " nameserver ffc0::c001\n"  // Not blacklisted
                       " domain first.com\n"},
  {"/etc/nsswitch.conf", "hosts: files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerBlacklistedIpv6,
                 "myhostname", "mydomainname.org", blacklistedIpv6) {
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));
  std::string actual = GetNameServers(channel);
  std::string expected = "254.192.1.1:53,"
                         "[ffc0::c001]:53";
  EXPECT_EQ(expected, actual);

  EXPECT_EQ(1, channel->ndomains);
  EXPECT_EQ(std::string("first.com"), std::string(channel->domains[0]));

  ci_destroy(channel);
  return HasFailure();
}

NameContentList multiresolv = {
  {"/etc/resolv.conf", " nameserver 1::2 ;  ;;\n"
                       " domain first.com\n"},
  {"/etc/nsswitch.conf", "hosts: files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerMultiResolvInit,
                 "myhostname", "mydomainname.org", multiresolv) {
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));
  std::string actual = GetNameServers(channel);
  std::string expected = "[1::2]:53";
  EXPECT_EQ(expected, actual);

  EXPECT_EQ(1, channel->ndomains);
  EXPECT_EQ(std::string("first.com"), std::string(channel->domains[0]));

  ci_destroy(channel);
  return HasFailure();
}

NameContentList systemdresolv = {
  {"/etc/resolv.conf", "nameserver 1.2.3.4\n"
                       "domain first.com\n"},
  {"/etc/nsswitch.conf", "hosts: junk resolve files\n"}};
CONTAINED_TEST_F(LibraryTest, ContainerSystemdResolvInit,
                 "myhostname", "mydomainname.org", systemdresolv) {
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));

  EXPECT_EQ(std::string("bf"), std::string(channel->lookups));

  ci_destroy(channel);
  return HasFailure();
}

NameContentList empty = {};  // no files
CONTAINED_TEST_F(LibraryTest, ContainerEmptyInit,
                 "host.domain.org", "domain.org", empty) {
  ci_channel_t *channel = nullptr;
  EXPECT_EQ(CI_SUCCESS, ci_init(&channel));
  std::string actual = GetNameServers(channel);
  std::string expected = "127.0.0.1:53";
  EXPECT_EQ(expected, actual);

  EXPECT_EQ(1, channel->ndomains);
  EXPECT_EQ(std::string("domain.org"), std::string(channel->domains[0]));
  EXPECT_EQ(std::string("fb"), std::string(channel->lookups));

  ci_destroy(channel);
  return HasFailure();
}

// Test that init fails if the flag to not use a default local named server is
// enabled and no other nameservers are available.
CONTAINED_TEST_F(LibraryTest, ContainerNoDfltSvrEmptyInit,
                 "myhostname", "mydomainname.org", empty) {
  ci_channel_t *channel = nullptr;
  struct ci_options opts;
  memset(&opts, 0, sizeof(opts));
  int optmask = CI_OPT_FLAGS;
  opts.flags = CI_FLAG_NO_DFLT_SVR;
  EXPECT_EQ(CI_ENOSERVER, ci_init_options(&channel, &opts, optmask));

  EXPECT_EQ(nullptr, channel);
  return HasFailure();
}
// Test that init succeeds if the flag to not use a default local named server
// is enabled but other nameservers are available.
CONTAINED_TEST_F(LibraryTest, ContainerNoDfltSvrFullInit,
                 "myhostname", "mydomainname.org", filelist) {
  ci_channel_t *channel = nullptr;
  struct ci_options opts;
  memset(&opts, 0, sizeof(opts));
  int optmask = CI_OPT_FLAGS;
  opts.flags = CI_FLAG_NO_DFLT_SVR;
  EXPECT_EQ(CI_SUCCESS, ci_init_options(&channel, &opts, optmask));

  std::string actual = GetNameServers(channel);
  std::string expected = "1.2.3.4:53";
  EXPECT_EQ(expected, actual);

  ci_destroy(channel);
  return HasFailure();
}

#endif

}  // namespace test
}  // namespace ci
