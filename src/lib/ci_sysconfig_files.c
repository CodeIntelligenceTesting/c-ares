/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2007 Daniel Stenberg
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

#ifdef HAVE_SYS_PARAM_H
#  include <sys/param.h>
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif

#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#if defined(ANDROID) || defined(__ANDROID__)
#  include <sys/system_properties.h>
#  include "ci_android.h"
/* From the Bionic sources */
#  define DNS_PROP_NAME_PREFIX "net.dns"
#  define MAX_DNS_PROPERTIES   8
#endif

#if defined(CI_USE_LIBRESOLV)
#  include <resolv.h>
#endif

#if defined(USE_WINSOCK) && defined(HAVE_IPHLPAPI_H)
#  include <iphlpapi.h>
#endif

#include "ci_inet_net_pton.h"

static unsigned char ip_natural_mask(const struct ci_addr *addr)
{
  const unsigned char *ptr = NULL;
  /* This is an odd one.  If a raw ipv4 address is specified, then we take
   * what is called a natural mask, which means we look at the first octet
   * of the ip address and for values 0-127 we assume it is a class A (/8),
   * for values 128-191 we assume it is a class B (/16), and for 192-223
   * we assume it is a class C (/24).  223-239 is Class D which and 240-255 is
   * Class E, however, there is no pre-defined mask for this, so we'll use
   * /24 as well as that's what the old code did.
   *
   * For IPv6, we'll use /64.
   */

  if (addr->family == AF_INET6) {
    return 64;
  }

  ptr = (const unsigned char *)&addr->addr.addr4;
  if (*ptr < 128) {
    return 8;
  }

  if (*ptr < 192) {
    return 16;
  }

  return 24;
}

static ci_bool_t sortlist_append(struct apattern **sortlist, size_t *nsort,
                                   const struct apattern *pat)
{
  struct apattern *newsort;

  newsort = ci_realloc(*sortlist, (*nsort + 1) * sizeof(*newsort));
  if (newsort == NULL) {
    return CI_FALSE; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  *sortlist = newsort;

  memcpy(&(*sortlist)[*nsort], pat, sizeof(**sortlist));
  (*nsort)++;

  return CI_TRUE;
}

static ci_status_t parse_sort(ci_buf_t *buf, struct apattern *pat)
{
  ci_status_t       status;
  const unsigned char ip_charset[]             = "ABCDEFabcdef0123456789.:";
  char                ipaddr[INET6_ADDRSTRLEN] = "";
  size_t              addrlen;

  memset(pat, 0, sizeof(*pat));

  /* Consume any leading whitespace */
  ci_buf_consume_whitespace(buf, CI_TRUE);

  /* If no length, just ignore, return ENOTFOUND as an indicator */
  if (ci_buf_len(buf) == 0) {
    return CI_ENOTFOUND;
  }

  ci_buf_tag(buf);

  /* Consume ip address */
  if (ci_buf_consume_charset(buf, ip_charset, sizeof(ip_charset) - 1) == 0) {
    return CI_EBADSTR;
  }

  /* Fetch ip address */
  status = ci_buf_tag_fetch_string(buf, ipaddr, sizeof(ipaddr));
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Parse it to make sure its valid */
  pat->addr.family = AF_UNSPEC;
  if (ci_dns_pton(ipaddr, &pat->addr, &addrlen) == NULL) {
    return CI_EBADSTR;
  }

  /* See if there is a subnet mask */
  if (ci_buf_begins_with(buf, (const unsigned char *)"/", 1)) {
    char                maskstr[16];
    const unsigned char ipv4_charset[] = "0123456789.";


    /* Consume / */
    ci_buf_consume(buf, 1);

    ci_buf_tag(buf);

    /* Consume mask */
    if (ci_buf_consume_charset(buf, ipv4_charset, sizeof(ipv4_charset) - 1) ==
        0) {
      return CI_EBADSTR;
    }

    /* Fetch mask */
    status = ci_buf_tag_fetch_string(buf, maskstr, sizeof(maskstr));
    if (status != CI_SUCCESS) {
      return status;
    }

    if (ci_str_isnum(maskstr)) {
      /* Numeric mask */
      int mask = atoi(maskstr);
      if (mask < 0 || mask > 128) {
        return CI_EBADSTR;
      }
      if (pat->addr.family == AF_INET && mask > 32) {
        return CI_EBADSTR;
      }
      pat->mask = (unsigned char)mask;
    } else {
      /* Ipv4 subnet style mask */
      struct ci_addr     maskaddr;
      const unsigned char *ptr;

      memset(&maskaddr, 0, sizeof(maskaddr));
      maskaddr.family = AF_INET;
      if (ci_dns_pton(maskstr, &maskaddr, &addrlen) == NULL) {
        return CI_EBADSTR;
      }
      ptr       = (const unsigned char *)&maskaddr.addr.addr4;
      pat->mask = (unsigned char)(ci_count_bits_u8(ptr[0]) +
                                  ci_count_bits_u8(ptr[1]) +
                                  ci_count_bits_u8(ptr[2]) +
                                  ci_count_bits_u8(ptr[3]));
    }
  } else {
    pat->mask = ip_natural_mask(&pat->addr);
  }

  /* Consume any trailing whitespace */
  ci_buf_consume_whitespace(buf, CI_TRUE);

  /* If we have any trailing bytes other than whitespace, its a parse failure */
  if (ci_buf_len(buf) != 0) {
    return CI_EBADSTR;
  }

  return CI_SUCCESS;
}

ci_status_t ci_parse_sortlist(struct apattern **sortlist, size_t *nsort,
                                  const char *str)
{
  ci_buf_t   *buf    = NULL;
  ci_status_t status = CI_SUCCESS;
  ci_array_t *arr    = NULL;
  size_t        num    = 0;
  size_t        i;

  if (sortlist == NULL || nsort == NULL || str == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (*sortlist != NULL) {
    ci_free(*sortlist);
  }

  *sortlist = NULL;
  *nsort    = 0;

  buf = ci_buf_create_const((const unsigned char *)str, ci_strlen(str));
  if (buf == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  /* Split on space or semicolon */
  status = ci_buf_split(buf, (const unsigned char *)" ;", 2,
                          CI_BUF_SPLIT_NONE, 0, &arr);
  if (status != CI_SUCCESS) {
    goto done;
  }

  num = ci_array_len(arr);
  for (i = 0; i < num; i++) {
    ci_buf_t    **bufptr = ci_array_at(arr, i);
    ci_buf_t     *entry  = *bufptr;

    struct apattern pat;

    status = parse_sort(entry, &pat);
    if (status != CI_SUCCESS && status != CI_ENOTFOUND) {
      goto done;
    }

    if (status != CI_SUCCESS) {
      continue;
    }

    if (!sortlist_append(sortlist, nsort, &pat)) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  status = CI_SUCCESS;

done:
  ci_buf_destroy(buf);
  ci_array_destroy(arr);

  if (status != CI_SUCCESS) {
    ci_free(*sortlist);
    *sortlist = NULL;
    *nsort    = 0;
  }

  return status;
}

static ci_status_t config_search(ci_sysconfig_t *sysconfig, const char *str,
                                   size_t max_domains)
{
  if (sysconfig->domains && sysconfig->ndomains > 0) {
    /* if we already have some domains present, free them first */
    ci_strsplit_free(sysconfig->domains, sysconfig->ndomains);
    sysconfig->domains  = NULL;
    sysconfig->ndomains = 0;
  }

  sysconfig->domains = ci_strsplit(str, ", ", &sysconfig->ndomains);
  if (sysconfig->domains == NULL) {
    return CI_ENOMEM;
  }

  /* Truncate if necessary */
  if (max_domains && sysconfig->ndomains > max_domains) {
    size_t i;
    for (i = max_domains; i < sysconfig->ndomains; i++) {
      ci_free(sysconfig->domains[i]);
      sysconfig->domains[i] = NULL;
    }
    sysconfig->ndomains = max_domains;
  }

  return CI_SUCCESS;
}

static ci_status_t buf_fetch_string(ci_buf_t *buf, char *str,
                                      size_t str_len)
{
  ci_status_t status;
  ci_buf_tag(buf);
  ci_buf_consume(buf, ci_buf_len(buf));

  status = ci_buf_tag_fetch_string(buf, str, str_len);
  return status;
}

static ci_status_t config_lookup(ci_sysconfig_t *sysconfig, ci_buf_t *buf,
                                   const char *separators)
{
  ci_status_t status;
  char          lookupstr[32];
  size_t        lookupstr_cnt = 0;
  char        **lookups       = NULL;
  size_t        num           = 0;
  size_t        i;
  size_t        separators_len = ci_strlen(separators);

  status =
    ci_buf_split_str(buf, (const unsigned char *)separators, separators_len,
                       CI_BUF_SPLIT_TRIM, 0, &lookups, &num);
  if (status != CI_SUCCESS) {
    goto done;
  }

  for (i = 0; i < num; i++) {
    const char *value = lookups[i];
    char        ch;

    if (ci_strcaseeq(value, "dns") || ci_strcaseeq(value, "bind") ||
        ci_strcaseeq(value, "resolv") || ci_strcaseeq(value, "resolve")) {
      ch = 'b';
    } else if (ci_strcaseeq(value, "files") ||
               ci_strcaseeq(value, "file") ||
               ci_strcaseeq(value, "local")) {
      ch = 'f';
    } else {
      continue;
    }

    /* Look for a duplicate and ignore */
    if (memchr(lookupstr, ch, lookupstr_cnt) == NULL) {
      lookupstr[lookupstr_cnt++] = ch;
    }
  }

  if (lookupstr_cnt) {
    lookupstr[lookupstr_cnt] = 0;
    ci_free(sysconfig->lookups);
    sysconfig->lookups = ci_strdup(lookupstr);
    if (sysconfig->lookups == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  status = CI_SUCCESS;

done:
  if (status != CI_ENOMEM) {
    status = CI_SUCCESS;
  }
  ci_free_array(lookups, num, ci_free);
  return status;
}

static ci_status_t process_option(ci_sysconfig_t *sysconfig,
                                    ci_buf_t       *option)
{
  char        **kv  = NULL;
  size_t        num = 0;
  const char   *key;
  const char   *val;
  unsigned int  valint = 0;
  ci_status_t status;

  /* Split on : */
  status = ci_buf_split_str(option, (const unsigned char *)":", 1,
                              CI_BUF_SPLIT_TRIM, 2, &kv, &num);
  if (status != CI_SUCCESS) {
    goto done;
  }

  if (num < 1) {
    status = CI_EBADSTR;
    goto done;
  }

  key = kv[0];
  if (num == 2) {
    val    = kv[1];
    valint = (unsigned int)strtoul(val, NULL, 10);
  }

  if (ci_streq(key, "ndots")) {
    sysconfig->ndots = valint;
  } else if (ci_streq(key, "retrans") || ci_streq(key, "timeout")) {
    if (valint == 0) {
      return CI_EFORMERR;
    }
    sysconfig->timeout_ms = valint * 1000;
  } else if (ci_streq(key, "retry") || ci_streq(key, "attempts")) {
    if (valint == 0) {
      return CI_EFORMERR;
    }
    sysconfig->tries = valint;
  } else if (ci_streq(key, "rotate")) {
    sysconfig->rotate = CI_TRUE;
  } else if (ci_streq(key, "use-vc") || ci_streq(key, "usevc")) {
    sysconfig->usevc = CI_TRUE;
  }

done:
  ci_free_array(kv, num, ci_free);
  return status;
}

ci_status_t ci_sysconfig_set_options(ci_sysconfig_t *sysconfig,
                                         const char       *str)
{
  ci_buf_t   *buf     = NULL;
  ci_array_t *options = NULL;
  size_t        num;
  size_t        i;
  ci_status_t status;

  buf = ci_buf_create_const((const unsigned char *)str, ci_strlen(str));
  if (buf == NULL) {
    return CI_ENOMEM;
  }

  status = ci_buf_split(buf, (const unsigned char *)" \t", 2,
                          CI_BUF_SPLIT_TRIM, 0, &options);
  if (status != CI_SUCCESS) {
    goto done;
  }

  num = ci_array_len(options);
  for (i = 0; i < num; i++) {
    ci_buf_t **bufptr = ci_array_at(options, i);
    ci_buf_t  *valbuf = *bufptr;

    status = process_option(sysconfig, valbuf);
    /* Out of memory is the only fatal condition */
    if (status == CI_ENOMEM) {
      goto done; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  status = CI_SUCCESS;

done:
  ci_array_destroy(options);
  ci_buf_destroy(buf);
  return status;
}

ci_status_t ci_init_by_environment(ci_sysconfig_t *sysconfig)
{
  const char   *localdomain;
  const char   *res_options;
  ci_status_t status;

  localdomain = getenv("LOCALDOMAIN");
  if (localdomain) {
    char *temp = ci_strdup(localdomain);
    if (temp == NULL) {
      return CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
    status = config_search(sysconfig, temp, 1);
    ci_free(temp);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  res_options = getenv("RES_OPTIONS");
  if (res_options) {
    status = ci_sysconfig_set_options(sysconfig, res_options);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  return CI_SUCCESS;
}

/* Configuration Files:
 *  /etc/resolv.conf
 *    - All Unix-like systems
 *    - Comments start with ; or #
 *    - Lines have a keyword followed by a value that is interpreted specific
 *      to the keyword:
 *    - Keywords:
 *      - nameserver - IP address of nameserver with optional port (using a :
 *        prefix). If using an ipv6 address and specifying a port, the ipv6
 *        address must be encapsulated in brackets. For link-local ipv6
 *        addresses, the interface can also be specified with a % prefix. e.g.:
 *          "nameserver [fe80::1]:1234%iface"
 *        This keyword may be specified multiple times.
 *      - search - whitespace separated list of domains
 *      - domain - obsolete, same as search except only a single domain
 *      - lookup / hostresorder - local, bind, file, files
 *      - sortlist - whitespace separated ip-address/netmask pairs
 *      - options - options controlling resolver variables
 *        - ndots:n - set ndots option
 *        - timeout:n (retrans:n) - timeout per query attempt in seconds
 *        - attempts:n (retry:n) - number of times resolver will send query
 *        - rotate - round-robin selection of name servers
 *        - use-vc / usevc - force tcp
 *  /etc/nsswitch.conf
 *    - Modern Linux, FreeBSD, HP-UX, Solaris
 *    - Search order set via:
 *      "hosts: files dns mdns4_minimal mdns4"
 *      - files is /etc/hosts
 *      - dns is dns
 *      - mdns4_minimal does mdns only if ending in .local
 *      - mdns4 does not limit to domains ending in .local
 *  /etc/netsvc.conf
 *    - AIX
 *    - Search order set via:
 *      "hosts = local , bind"
 *      - bind is dns
 *      - local is /etc/hosts
 *  /etc/svc.conf
 *    - Tru64
 *    - Same format as /etc/netsvc.conf
 *  /etc/host.conf
 *    - Early FreeBSD, Early Linux
 *    - Not worth supporting, format varied based on system, FreeBSD used
 *      just a line per search order, Linux used "order " and a comma
 *      delimited list of "bind" and "hosts"
 */


/* This function will only return CI_SUCCESS or CI_ENOMEM.  Any other
 * conditions are ignored.  Users may mess up config files, but we want to
 * process anything we can. */
static ci_status_t parse_resolvconf_line(const ci_channel_t *channel,
                                           ci_sysconfig_t     *sysconfig,
                                           ci_buf_t           *line)
{
  char          option[32];
  char          value[512];
  ci_status_t status = CI_SUCCESS;

  /* Ignore lines beginning with a comment */
  if (ci_buf_begins_with(line, (const unsigned char *)"#", 1) ||
      ci_buf_begins_with(line, (const unsigned char *)";", 1)) {
    return CI_SUCCESS;
  }

  ci_buf_tag(line);

  /* Shouldn't be possible, but if it happens, ignore the line. */
  if (ci_buf_consume_nonwhitespace(line) == 0) {
    return CI_SUCCESS;
  }

  status = ci_buf_tag_fetch_string(line, option, sizeof(option));
  if (status != CI_SUCCESS) {
    return CI_SUCCESS;
  }

  ci_buf_consume_whitespace(line, CI_TRUE);

  status = buf_fetch_string(line, value, sizeof(value));
  if (status != CI_SUCCESS) {
    return CI_SUCCESS;
  }

  ci_str_trim(value);
  if (*value == 0) {
    return CI_SUCCESS;
  }

  /* At this point we have a string option and a string value, both trimmed
   * of leading and trailing whitespace.  Lets try to evaluate them */
  if (ci_streq(option, "domain")) {
    /* Domain is legacy, don't overwrite an existing config set by search */
    if (sysconfig->domains == NULL) {
      status = config_search(sysconfig, value, 1);
    }
  } else if (ci_streq(option, "lookup") ||
             ci_streq(option, "hostresorder")) {
    ci_buf_tag_rollback(line);
    status = config_lookup(sysconfig, line, " \t");
  } else if (ci_streq(option, "search")) {
    status = config_search(sysconfig, value, 0);
  } else if (ci_streq(option, "nameserver")) {
    status = ci_sconfig_append_fromstr(channel, &sysconfig->sconfig, value,
                                         CI_TRUE);
  } else if (ci_streq(option, "sortlist")) {
    /* Ignore all failures except ENOMEM.  If the sysadmin set a bad
     * sortlist, just ignore the sortlist, don't cause an inoperable
     * channel */
    status =
      ci_parse_sortlist(&sysconfig->sortlist, &sysconfig->nsortlist, value);
    if (status != CI_ENOMEM) {
      status = CI_SUCCESS;
    }
  } else if (ci_streq(option, "options")) {
    status = ci_sysconfig_set_options(sysconfig, value);
  }

  return status;
}

/* This function will only return CI_SUCCESS or CI_ENOMEM.  Any other
 * conditions are ignored.  Users may mess up config files, but we want to
 * process anything we can. */
static ci_status_t parse_nsswitch_line(const ci_channel_t *channel,
                                         ci_sysconfig_t     *sysconfig,
                                         ci_buf_t           *line)
{
  char          option[32];
  ci_status_t status = CI_SUCCESS;
  ci_array_t *sects  = NULL;
  ci_buf_t  **bufptr;
  ci_buf_t   *buf;

  (void)channel;

  /* Ignore lines beginning with a comment */
  if (ci_buf_begins_with(line, (const unsigned char *)"#", 1)) {
    return CI_SUCCESS;
  }

  /* database : values (space delimited) */
  status = ci_buf_split(line, (const unsigned char *)":", 1,
                          CI_BUF_SPLIT_TRIM, 2, &sects);

  if (status != CI_SUCCESS || ci_array_len(sects) != 2) {
    goto done;
  }

  bufptr = ci_array_at(sects, 0);
  buf    = *bufptr;

  status = buf_fetch_string(buf, option, sizeof(option));
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Only support "hosts:" */
  if (!ci_streq(option, "hosts")) {
    goto done;
  }

  /* Values are space separated */
  bufptr = ci_array_at(sects, 1);
  buf    = *bufptr;
  status = config_lookup(sysconfig, buf, " \t");

done:
  ci_array_destroy(sects);
  if (status != CI_ENOMEM) {
    status = CI_SUCCESS;
  }
  return status;
}

/* This function will only return CI_SUCCESS or CI_ENOMEM.  Any other
 * conditions are ignored.  Users may mess up config files, but we want to
 * process anything we can. */
static ci_status_t parse_svcconf_line(const ci_channel_t *channel,
                                        ci_sysconfig_t     *sysconfig,
                                        ci_buf_t           *line)
{
  char          option[32];
  ci_buf_t  **bufptr;
  ci_buf_t   *buf;
  ci_status_t status = CI_SUCCESS;
  ci_array_t *sects  = NULL;

  (void)channel;

  /* Ignore lines beginning with a comment */
  if (ci_buf_begins_with(line, (const unsigned char *)"#", 1)) {
    return CI_SUCCESS;
  }

  /* database = values (comma delimited)*/
  status = ci_buf_split(line, (const unsigned char *)"=", 1,
                          CI_BUF_SPLIT_TRIM, 2, &sects);

  if (status != CI_SUCCESS || ci_array_len(sects) != 2) {
    goto done;
  }

  bufptr = ci_array_at(sects, 0);
  buf    = *bufptr;
  status = buf_fetch_string(buf, option, sizeof(option));
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* Only support "hosts=" */
  if (!ci_streq(option, "hosts")) {
    goto done;
  }

  /* Values are comma separated */
  bufptr = ci_array_at(sects, 1);
  buf    = *bufptr;
  status = config_lookup(sysconfig, buf, ",");

done:
  ci_array_destroy(sects);
  if (status != CI_ENOMEM) {
    status = CI_SUCCESS;
  }
  return status;
}

typedef ci_status_t (*line_callback_t)(const ci_channel_t *channel,
                                         ci_sysconfig_t     *sysconfig,
                                         ci_buf_t           *line);

/* Should only return:
 *  CI_ENOTFOUND - file not found
 *  CI_EFILE     - error reading file (perms)
 *  CI_ENOMEM    - out of memory
 *  CI_SUCCESS   - file processed, doesn't necessarily mean it was a good
 *                   file, but we're not erroring out if we can't parse
 *                   something (or anything at all) */
static ci_status_t process_config_lines(const ci_channel_t *channel,
                                          const char           *filename,
                                          ci_sysconfig_t     *sysconfig,
                                          line_callback_t       cb)
{
  ci_status_t status = CI_SUCCESS;
  ci_array_t *lines  = NULL;
  ci_buf_t   *buf    = NULL;
  size_t        num;
  size_t        i;

  buf = ci_buf_create();
  if (buf == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  status = ci_buf_load_file(filename, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_buf_split(buf, (const unsigned char *)"\n", 1,
                          CI_BUF_SPLIT_TRIM, 0, &lines);
  if (status != CI_SUCCESS) {
    goto done;
  }

  num = ci_array_len(lines);
  for (i = 0; i < num; i++) {
    ci_buf_t **bufptr = ci_array_at(lines, i);
    ci_buf_t  *line   = *bufptr;

    status = cb(channel, sysconfig, line);
    if (status != CI_SUCCESS) {
      goto done;
    }
  }

done:
  ci_buf_destroy(buf);
  ci_array_destroy(lines);

  return status;
}

ci_status_t ci_init_sysconfig_files(const ci_channel_t *channel,
                                        ci_sysconfig_t     *sysconfig)
{
  ci_status_t status = CI_SUCCESS;

  /* Resolv.conf */
  status = process_config_lines(channel,
                                (channel->resolvconf_path != NULL)
                                  ? channel->resolvconf_path
                                  : PATH_RESOLV_CONF,
                                sysconfig, parse_resolvconf_line);
  if (status != CI_SUCCESS && status != CI_ENOTFOUND) {
    goto done;
  }

  /* Nsswitch.conf */
  status = process_config_lines(channel, "/etc/nsswitch.conf", sysconfig,
                                parse_nsswitch_line);
  if (status != CI_SUCCESS && status != CI_ENOTFOUND) {
    goto done;
  }

  /* netsvc.conf */
  status = process_config_lines(channel, "/etc/netsvc.conf", sysconfig,
                                parse_svcconf_line);
  if (status != CI_SUCCESS && status != CI_ENOTFOUND) {
    goto done;
  }

  /* svc.conf */
  status = process_config_lines(channel, "/etc/svc.conf", sysconfig,
                                parse_svcconf_line);
  if (status != CI_SUCCESS && status != CI_ENOTFOUND) {
    goto done;
  }

  status = CI_SUCCESS;

done:
  return status;
}
