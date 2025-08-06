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

/* This test program is meant to loop indefinitely performing a query for the
 * same domain once per second.  The purpose of this is to test the event loop
 * configuration change detection.  You can modify the system configuration
 * and verify queries work or don't work as expected. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#  include <winsock2.h>
#  include <windows.h>
#else
#  include <unistd.h>
#  include <signal.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#endif
#include "ci.h"

static void ai_callback(void *arg, int status, int timeouts,
                        struct ci_addrinfo *result)
{
  struct ci_addrinfo_node *node = NULL;
  (void)timeouts;


  if (status != CI_SUCCESS) {
    fprintf(stderr, "%s: %s\n", (char *)arg, ci_strerror(status));
    return;
  }

  for (node = result->nodes; node != NULL; node = node->ai_next) {
    char        addr_buf[64] = "";
    const void *ptr          = NULL;
    if (node->ai_family == AF_INET) {
      const struct sockaddr_in *in_addr =
        (const struct sockaddr_in *)((void *)node->ai_addr);
      ptr = &in_addr->sin_addr;
    } else if (node->ai_family == AF_INET6) {
      const struct sockaddr_in6 *in_addr =
        (const struct sockaddr_in6 *)((void *)node->ai_addr);
      ptr = &in_addr->sin6_addr;
    } else {
      continue;
    }
    ci_inet_ntop(node->ai_family, ptr, addr_buf, sizeof(addr_buf));
    printf("%-32s\t%s\n", result->name, addr_buf);
  }

  ci_freeaddrinfo(result);
}

static volatile ci_bool_t is_running = CI_TRUE;


#ifdef _WIN32
static BOOL WINAPI ctrlc_handler(_In_ DWORD dwCtrlType)
{
  switch (dwCtrlType) {
    case CTRL_C_EVENT:
      is_running = CI_FALSE;
      return TRUE;
    default:
      break;
  }
  return FALSE;
}
#else
static void ctrlc_handler(int sig)
{
  switch (sig) {
    case SIGINT:
      is_running = CI_FALSE;
      break;
    default:
      break;
  }
}
#endif

int main(int argc, char *argv[])
{
  struct ci_options options;
  int                 optmask = 0;
  ci_channel_t     *channel;
  size_t              count;
  ci_status_t       status;

#ifdef _WIN32
  WORD    wVersionRequested = MAKEWORD(2, 2);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#endif

  if (argc != 2) {
    printf("Usage: %s domain\n", argv[0]);
    return 1;
  }

  status = (ci_status_t)ci_library_init(CI_LIB_INIT_ALL);
  if (status != CI_SUCCESS) {
    fprintf(stderr, "ci_library_init: %s\n", ci_strerror((int)status));
    return 1;
  }

  memset(&options, 0, sizeof(options));
  optmask                |= CI_OPT_EVENT_THREAD;
  options.evsys           = CI_EVSYS_DEFAULT;
  optmask                |= CI_OPT_QUERY_CACHE;
  options.qcache_max_ttl  = 0;

  status = (ci_status_t)ci_init_options(&channel, &options, optmask);
  if (status != CI_SUCCESS) {
    fprintf(stderr, "ci_init: %s\n", ci_strerror((int)status));
    return 1;
  }

#ifdef _WIN32
  SetConsoleCtrlHandler(ctrlc_handler, TRUE);
#else
  signal(SIGINT, ctrlc_handler);
#endif

  printf("Querying for %s every 1s, press CTRL-C to quit...\n", argv[1]);

  for (count = 1; is_running == CI_TRUE; count++) {
    struct ci_addrinfo_hints hints;
    char                      *servers = ci_get_servers_csv(channel);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    printf("Attempt %u using server list: %s ...\n", (unsigned int)count,
           servers);
    ci_free_string(servers);

    ci_getaddrinfo(channel, argv[1], NULL, &hints, ai_callback, argv[1]);
#ifdef _WIN32
    Sleep(1000);
#else
    sleep(1);
#endif
  }

  printf("CTRL-C captured, cleaning up...\n");
  ci_destroy(channel);
  ci_library_cleanup();

#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}
