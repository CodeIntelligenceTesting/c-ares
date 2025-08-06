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

#ifdef USE_WINSOCK
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  if defined(HAVE_IPHLPAPI_H)
#    include <iphlpapi.h>
#  endif
#  if defined(HAVE_NETIOAPI_H)
#    include <netioapi.h>
#  endif
#endif

#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_NET_IF_H
#  include <net/if.h>
#endif
#ifdef HAVE_IFADDRS_H
#  include <ifaddrs.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif


static ci_status_t ci_iface_ips_enumerate(ci_iface_ips_t *ips,
                                              const char       *name);

typedef struct {
  char                 *name;
  struct ci_addr      addr;
  unsigned char         netmask;
  unsigned int          ll_scope;
  ci_iface_ip_flags_t flags;
} ci_iface_ip_t;

struct ci_iface_ips {
  ci_array_t         *ips; /*!< Type is ci_iface_ip_t */
  ci_iface_ip_flags_t enum_flags;
};

static void ci_iface_ip_free_cb(void *arg)
{
  ci_iface_ip_t *ip = arg;
  if (ip == NULL) {
    return;
  }
  ci_free(ip->name);
}

static ci_iface_ips_t *ci_iface_ips_alloc(ci_iface_ip_flags_t flags)
{
  ci_iface_ips_t *ips = ci_malloc_zero(sizeof(*ips));
  if (ips == NULL) {
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  ips->enum_flags = flags;
  ips->ips = ci_array_create(sizeof(ci_iface_ip_t), ci_iface_ip_free_cb);
  if (ips->ips == NULL) {
    ci_free(ips); /* LCOV_EXCL_LINE: OutOfMemory */
    return NULL;    /* LCOV_EXCL_LINE: OutOfMemory */
  }
  return ips;
}

void ci_iface_ips_destroy(ci_iface_ips_t *ips)
{
  if (ips == NULL) {
    return;
  }

  ci_array_destroy(ips->ips);
  ci_free(ips);
}

ci_status_t ci_iface_ips(ci_iface_ips_t    **ips,
                             ci_iface_ip_flags_t flags, const char *name)
{
  ci_status_t status;

  if (ips == NULL) {
    return CI_EFORMERR;
  }

  *ips = ci_iface_ips_alloc(flags);
  if (*ips == NULL) {
    return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  status = ci_iface_ips_enumerate(*ips, name);
  if (status != CI_SUCCESS) {
    /* LCOV_EXCL_START: UntestablePath */
    ci_iface_ips_destroy(*ips);
    *ips = NULL;
    return status;
    /* LCOV_EXCL_STOP */
  }

  return CI_SUCCESS;
}

static ci_status_t
  ci_iface_ips_add(ci_iface_ips_t *ips, ci_iface_ip_flags_t flags,
                     const char *name, const struct ci_addr *addr,
                     unsigned char netmask, unsigned int ll_scope)
{
  ci_iface_ip_t *ip;
  ci_status_t    status;

  if (ips == NULL || name == NULL || addr == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* Don't want loopback */
  if (flags & CI_IFACE_IP_LOOPBACK &&
      !(ips->enum_flags & CI_IFACE_IP_LOOPBACK)) {
    return CI_SUCCESS;
  }

  /* Don't want offline */
  if (flags & CI_IFACE_IP_OFFLINE &&
      !(ips->enum_flags & CI_IFACE_IP_OFFLINE)) {
    return CI_SUCCESS;
  }

  /* Check for link-local */
  if (ci_addr_is_linklocal(addr)) {
    flags |= CI_IFACE_IP_LINKLOCAL;
  }
  if (flags & CI_IFACE_IP_LINKLOCAL &&
      !(ips->enum_flags & CI_IFACE_IP_LINKLOCAL)) {
    return CI_SUCCESS;
  }

  /* Set address flag based on address provided */
  if (addr->family == AF_INET) {
    flags |= CI_IFACE_IP_V4;
  }

  if (addr->family == AF_INET6) {
    flags |= CI_IFACE_IP_V6;
  }

  /* If they specified either v4 or v6 validate flags otherwise assume they
   * want to enumerate both */
  if (ips->enum_flags & (CI_IFACE_IP_V4 | CI_IFACE_IP_V6)) {
    if (flags & CI_IFACE_IP_V4 && !(ips->enum_flags & CI_IFACE_IP_V4)) {
      return CI_SUCCESS;
    }
    if (flags & CI_IFACE_IP_V6 && !(ips->enum_flags & CI_IFACE_IP_V6)) {
      return CI_SUCCESS;
    }
  }

  status = ci_array_insert_last((void **)&ip, ips->ips);
  if (status != CI_SUCCESS) {
    return status;
  }

  ip->flags   = flags;
  ip->netmask = netmask;
  if (flags & CI_IFACE_IP_LINKLOCAL) {
    ip->ll_scope = ll_scope;
  }
  memcpy(&ip->addr, addr, sizeof(*addr));
  ip->name = ci_strdup(name);
  if (ip->name == NULL) {
    ci_array_remove_last(ips->ips);
    return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  return CI_SUCCESS;
}

size_t ci_iface_ips_cnt(const ci_iface_ips_t *ips)
{
  if (ips == NULL) {
    return 0;
  }
  return ci_array_len(ips->ips);
}

const char *ci_iface_ips_get_name(const ci_iface_ips_t *ips, size_t idx)
{
  const ci_iface_ip_t *ip;

  if (ips == NULL) {
    return NULL;
  }

  ip = ci_array_at_const(ips->ips, idx);
  if (ip == NULL) {
    return NULL;
  }

  return ip->name;
}

const struct ci_addr *ci_iface_ips_get_addr(const ci_iface_ips_t *ips,
                                                size_t                  idx)
{
  const ci_iface_ip_t *ip;

  if (ips == NULL) {
    return NULL;
  }

  ip = ci_array_at_const(ips->ips, idx);
  if (ip == NULL) {
    return NULL;
  }

  return &ip->addr;
}

ci_iface_ip_flags_t ci_iface_ips_get_flags(const ci_iface_ips_t *ips,
                                               size_t                  idx)
{
  const ci_iface_ip_t *ip;

  if (ips == NULL) {
    return 0;
  }

  ip = ci_array_at_const(ips->ips, idx);
  if (ip == NULL) {
    return 0;
  }

  return ip->flags;
}

unsigned char ci_iface_ips_get_netmask(const ci_iface_ips_t *ips,
                                         size_t                  idx)
{
  const ci_iface_ip_t *ip;

  if (ips == NULL) {
    return 0;
  }

  ip = ci_array_at_const(ips->ips, idx);
  if (ip == NULL) {
    return 0;
  }

  return ip->netmask;
}

unsigned int ci_iface_ips_get_ll_scope(const ci_iface_ips_t *ips,
                                         size_t                  idx)
{
  const ci_iface_ip_t *ip;

  if (ips == NULL) {
    return 0;
  }

  ip = ci_array_at_const(ips->ips, idx);
  if (ip == NULL) {
    return 0;
  }

  return ip->ll_scope;
}


#ifdef USE_WINSOCK

#  if 0
static char *wcharp_to_charp(const wchar_t *in)
{
  char *out;
  int   len;

  len = WideCharToMultiByte(CP_UTF8, 0, in, -1, NULL, 0, NULL, NULL);
  if (len == -1) {
    return NULL;
  }

  out = ci_malloc_zero((size_t)len + 1);

  if (WideCharToMultiByte(CP_UTF8, 0, in, -1, out, len, NULL, NULL) == -1) {
    ci_free(out);
    return NULL;
  }

  return out;
}
#  endif

static ci_bool_t name_match(const char *name, const char *adapter_name,
                              unsigned int ll_scope)
{
  if (name == NULL || *name == 0) {
    return CI_TRUE;
  }

  if (ci_strcaseeq(name, adapter_name)) {
    return CI_TRUE;
  }

  if (ci_str_isnum(name) && (unsigned int)atoi(name) == ll_scope) {
    return CI_TRUE;
  }

  return CI_FALSE;
}

static ci_status_t ci_iface_ips_enumerate(ci_iface_ips_t *ips,
                                              const char       *name)
{
  ULONG myflags = GAA_FLAG_INCLUDE_PREFIX /*|GAA_FLAG_INCLUDE_ALL_INTERFACES */;
  ULONG outBufLen = 0;
  DWORD retval;
  IP_ADAPTER_ADDRESSES *addresses = NULL;
  IP_ADAPTER_ADDRESSES *address   = NULL;
  ci_status_t         status    = CI_SUCCESS;

  /* Get necessary buffer size */
  GetAdaptersAddresses(AF_UNSPEC, myflags, NULL, NULL, &outBufLen);
  if (outBufLen == 0) {
    status = CI_EFILE;
    goto done;
  }

  addresses = ci_malloc_zero(outBufLen);
  if (addresses == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  retval =
    GetAdaptersAddresses(AF_UNSPEC, myflags, NULL, addresses, &outBufLen);
  if (retval != ERROR_SUCCESS) {
    status = CI_EFILE;
    goto done;
  }

  for (address = addresses; address != NULL; address = address->Next) {
    IP_ADAPTER_UNICAST_ADDRESS *ipaddr     = NULL;
    ci_iface_ip_flags_t       addrflag   = 0;
    char                        ifname[64] = "";

#  if defined(HAVE_CONVERTINTERFACEINDEXTOLUID) && \
    defined(HAVE_CONVERTINTERFACELUIDTONAMEA)
    /* Retrieve name from interface index.
     * address->AdapterName appears to be a GUID/UUID of some sort, not a name.
     * address->FriendlyName is user-changeable.
     * That said, this doesn't appear to help us out on systems that don't
     * have if_nametoindex() or if_indextoname() as they don't have these
     * functions either! */
    NET_LUID luid;
    ConvertInterfaceIndexToLuid(address->IfIndex, &luid);
    ConvertInterfaceLuidToNameA(&luid, ifname, sizeof(ifname));
#  else
    ci_strcpy(ifname, address->AdapterName, sizeof(ifname));
#  endif

    if (address->OperStatus != IfOperStatusUp) {
      addrflag |= CI_IFACE_IP_OFFLINE;
    }

    if (address->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
      addrflag |= CI_IFACE_IP_LOOPBACK;
    }

    for (ipaddr = address->FirstUnicastAddress; ipaddr != NULL;
         ipaddr = ipaddr->Next) {
      struct ci_addr addr;

      if (ipaddr->Address.lpSockaddr->sa_family == AF_INET) {
        const struct sockaddr_in *sockaddr_in =
          (const struct sockaddr_in *)((void *)ipaddr->Address.lpSockaddr);
        addr.family = AF_INET;
        memcpy(&addr.addr.addr4, &sockaddr_in->sin_addr,
               sizeof(addr.addr.addr4));
      } else if (ipaddr->Address.lpSockaddr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sockaddr_in6 =
          (const struct sockaddr_in6 *)((void *)ipaddr->Address.lpSockaddr);
        addr.family = AF_INET6;
        memcpy(&addr.addr.addr6, &sockaddr_in6->sin6_addr,
               sizeof(addr.addr.addr6));
      } else {
        /* Unknown */
        continue;
      }

      /* Sometimes windows may use numerics to indicate a DNS server's adapter,
       * which corresponds to the index rather than the name.  Check and
       * validate both. */
      if (!name_match(name, ifname, address->Ipv6IfIndex)) {
        continue;
      }

      status = ci_iface_ips_add(ips, addrflag, ifname, &addr,
                                  ipaddr->OnLinkPrefixLength /* netmask */,
                                  address->Ipv6IfIndex /* ll_scope */);

      if (status != CI_SUCCESS) {
        goto done;
      }
    }
  }

done:
  ci_free(addresses);
  return status;
}

#elif defined(HAVE_GETIFADDRS)

static unsigned char count_addr_bits(const unsigned char *addr, size_t addr_len)
{
  size_t        i;
  unsigned char count = 0;

  for (i = 0; i < addr_len; i++) {
    count += ci_count_bits_u8(addr[i]);
  }
  return count;
}

static ci_status_t ci_iface_ips_enumerate(ci_iface_ips_t *ips,
                                              const char       *name)
{
  struct ifaddrs *ifap   = NULL;
  struct ifaddrs *ifa    = NULL;
  ci_status_t   status = CI_SUCCESS;

  if (getifaddrs(&ifap) != 0) {
    status = CI_EFILE;
    goto done;
  }

  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    ci_iface_ip_flags_t addrflag = 0;
    struct ci_addr      addr;
    unsigned char         netmask  = 0;
    unsigned int          ll_scope = 0;

    if (ifa->ifa_addr == NULL) {
      continue;
    }

    if (!(ifa->ifa_flags & IFF_UP)) {
      addrflag |= CI_IFACE_IP_OFFLINE;
    }

    if (ifa->ifa_flags & IFF_LOOPBACK) {
      addrflag |= CI_IFACE_IP_LOOPBACK;
    }

    if (ifa->ifa_addr->sa_family == AF_INET) {
      const struct sockaddr_in *sockaddr_in =
        (const struct sockaddr_in *)((void *)ifa->ifa_addr);
      addr.family = AF_INET;
      memcpy(&addr.addr.addr4, &sockaddr_in->sin_addr, sizeof(addr.addr.addr4));
      /* netmask */
      sockaddr_in = (struct sockaddr_in *)((void *)ifa->ifa_netmask);
      netmask     = count_addr_bits((const void *)&sockaddr_in->sin_addr, 4);
    } else if (ifa->ifa_addr->sa_family == AF_INET6) {
      const struct sockaddr_in6 *sockaddr_in6 =
        (const struct sockaddr_in6 *)((void *)ifa->ifa_addr);
      addr.family = AF_INET6;
      memcpy(&addr.addr.addr6, &sockaddr_in6->sin6_addr,
             sizeof(addr.addr.addr6));
      /* netmask */
      sockaddr_in6 = (struct sockaddr_in6 *)((void *)ifa->ifa_netmask);
      netmask = count_addr_bits((const void *)&sockaddr_in6->sin6_addr, 16);
#  ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
      ll_scope = sockaddr_in6->sin6_scope_id;
#  endif
    } else {
      /* unknown */
      continue;
    }

    /* Name mismatch */
    if (name != NULL && !ci_strcaseeq(ifa->ifa_name, name)) {
      continue;
    }

    status = ci_iface_ips_add(ips, addrflag, ifa->ifa_name, &addr, netmask,
                                ll_scope);
    if (status != CI_SUCCESS) {
      goto done;
    }
  }

done:
  freeifaddrs(ifap);
  return status;
}

#else

static ci_status_t ci_iface_ips_enumerate(ci_iface_ips_t *ips,
                                              const char       *name)
{
  (void)ips;
  (void)name;
  return CI_ENOTIMP;
}

#endif


unsigned int ci_os_if_nametoindex(const char *name)
{
#ifdef HAVE_IF_NAMETOINDEX
  if (name == NULL) {
    return 0;
  }
  return if_nametoindex(name);
#else
  ci_status_t     status;
  ci_iface_ips_t *ips = NULL;
  size_t            i;
  unsigned int      index = 0;

  if (name == NULL) {
    return 0;
  }

  status =
    ci_iface_ips(&ips, CI_IFACE_IP_V6 | CI_IFACE_IP_LINKLOCAL, name);
  if (status != CI_SUCCESS) {
    goto done;
  }

  for (i = 0; i < ci_iface_ips_cnt(ips); i++) {
    if (ci_iface_ips_get_flags(ips, i) & CI_IFACE_IP_LINKLOCAL) {
      index = ci_iface_ips_get_ll_scope(ips, i);
      goto done;
    }
  }

done:
  ci_iface_ips_destroy(ips);
  return index;
#endif
}

const char *ci_os_if_indextoname(unsigned int index, char *name, size_t name_len)
{
#ifdef HAVE_IF_INDEXTONAME
  if (name_len < IF_NAMESIZE) {
    return NULL;
  }
  return if_indextoname(index, name);
#else
  ci_status_t     status;
  ci_iface_ips_t *ips = NULL;
  size_t            i;
  const char       *ptr = NULL;

  if (name == NULL || name_len < IF_NAMESIZE) {
    goto done;
  }

  if (index == 0) {
    goto done;
  }

  status =
    ci_iface_ips(&ips, CI_IFACE_IP_V6 | CI_IFACE_IP_LINKLOCAL, NULL);
  if (status != CI_SUCCESS) {
    goto done;
  }

  for (i = 0; i < ci_iface_ips_cnt(ips); i++) {
    if (ci_iface_ips_get_flags(ips, i) & CI_IFACE_IP_LINKLOCAL &&
        ci_iface_ips_get_ll_scope(ips, i) == index) {
      ci_strcpy(name, ci_iface_ips_get_name(ips, i), name_len);
      ptr = name;
      goto done;
    }
  }

done:
  ci_iface_ips_destroy(ips);
  return ptr;
#endif
}
