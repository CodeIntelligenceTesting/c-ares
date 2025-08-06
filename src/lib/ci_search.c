/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
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

#include "ci_private.h"

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

struct search_query {
  /* Arguments passed to ci_search_dnsrec() */
  ci_channel_t      *channel;
  ci_callback_dnsrec callback;
  void                *arg;

  /* Duplicate of DNS record passed to ci_search_dnsrec() */
  ci_dns_record_t   *dnsrec;

  /* Search order for names */
  char               **names;
  size_t               names_cnt;

  /* State tracking progress through the search query */
  size_t               next_name_idx; /* next name index being attempted */
  size_t      timeouts;        /* number of timeouts we saw for this request */
  ci_bool_t ever_got_nodata; /* did we ever get CI_ENODATA along the way? */
};

static void squery_free(struct search_query *squery)
{
  if (squery == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }
  ci_strsplit_free(squery->names, squery->names_cnt);
  ci_dns_record_destroy(squery->dnsrec);
  ci_free(squery);
}

/* End a search query by invoking the user callback and freeing the
 * search_query structure.
 */
static void end_squery(struct search_query *squery, ci_status_t status,
                       const ci_dns_record_t *dnsrec)
{
  squery->callback(squery->arg, status, squery->timeouts, dnsrec);
  squery_free(squery);
}

static void search_callback(void *arg, ci_status_t status, size_t timeouts,
                            const ci_dns_record_t *dnsrec);

static ci_status_t ci_search_next(ci_channel_t      *channel,
                                      struct search_query *squery,
                                      ci_bool_t         *skip_cleanup)
{
  ci_status_t status;

  *skip_cleanup = CI_FALSE;

  /* Misuse check */
  if (squery->next_name_idx >= squery->names_cnt) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  status = ci_dns_record_query_set_name(
    squery->dnsrec, 0, squery->names[squery->next_name_idx++]);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_send_nolock(channel, NULL, 0, squery->dnsrec, search_callback,
                            squery, NULL);

  if (status != CI_EFORMERR) {
    *skip_cleanup = CI_TRUE;
  }

  return status;
}

static void search_callback(void *arg, ci_status_t status, size_t timeouts,
                            const ci_dns_record_t *dnsrec)
{
  struct search_query *squery  = (struct search_query *)arg;
  ci_channel_t      *channel = squery->channel;

  ci_status_t        mystatus;
  ci_bool_t          skip_cleanup = CI_FALSE;

  squery->timeouts += timeouts;

  if (dnsrec) {
    ci_dns_rcode_t rcode = ci_dns_record_get_rcode(dnsrec);
    size_t ancount = ci_dns_record_rr_cnt(dnsrec, CI_SECTION_ANSWER);
    mystatus       = ci_dns_query_reply_tostatus(rcode, ancount);
  } else {
    mystatus = status;
  }

  switch (mystatus) {
    case CI_ENODATA:
    case CI_ENOTFOUND:
      break;
    case CI_ESERVFAIL:
    case CI_EREFUSED:
      /* Issue #852, systemd-resolved may return SERVFAIL or REFUSED on a
       * single label domain name. */
      if (ci_name_label_cnt(squery->names[squery->next_name_idx - 1]) != 1) {
        end_squery(squery, mystatus, dnsrec);
        return;
      }
      break;
    default:
      end_squery(squery, mystatus, dnsrec);
      return;
  }

  /* If we ever get CI_ENODATA along the way, record that; if the search
   * should run to the very end and we got at least one CI_ENODATA,
   * then callers like ci_gethostbyname() may want to try a T_A search
   * even if the last domain we queried for T_AAAA resource records
   * returned CI_ENOTFOUND.
   */
  if (mystatus == CI_ENODATA) {
    squery->ever_got_nodata = CI_TRUE;
  }

  if (squery->next_name_idx < squery->names_cnt) {
    mystatus = ci_search_next(channel, squery, &skip_cleanup);
    if (mystatus != CI_SUCCESS && !skip_cleanup) {
      end_squery(squery, mystatus, NULL);
    }
    return;
  }

  /* We have no more domains to search, return an appropriate response. */
  if (mystatus == CI_ENOTFOUND && squery->ever_got_nodata) {
    end_squery(squery, CI_ENODATA, NULL);
    return;
  }

  end_squery(squery, mystatus, NULL);
}

/* Determine if the domain should be looked up as-is, or if it is eligible
 * for search by appending domains */
static ci_bool_t ci_search_eligible(const ci_channel_t *channel,
                                        const char           *name)
{
  size_t len = ci_strlen(name);

  /* Name ends in '.', cannot search */
  if (len && name[len - 1] == '.') {
    return CI_FALSE;
  }

  if (channel->flags & CI_FLAG_NOSEARCH) {
    return CI_FALSE;
  }

  return CI_TRUE;
}

size_t ci_name_label_cnt(const char *name)
{
  const char *p;
  size_t      ndots = 0;

  if (name == NULL) {
    return 0;
  }

  for (p = name; p != NULL && *p != 0; p++) {
    if (*p == '.') {
      ndots++;
    }
  }

  /* Label count is 1 greater than ndots */
  return ndots + 1;
}

ci_status_t ci_search_name_list(const ci_channel_t *channel,
                                    const char *name, char ***names,
                                    size_t *names_len)
{
  ci_status_t status;
  char        **list     = NULL;
  size_t        list_len = 0;
  char         *alias    = NULL;
  size_t        ndots    = 0;
  size_t        idx      = 0;
  size_t        i;

  /* Perform HOSTALIASES resolution */
  status = ci_lookup_hostaliases(channel, name, &alias);
  if (status == CI_SUCCESS) {
    /* If hostalias succeeds, there is no searching, it is used as-is */
    list_len = 1;
    list     = ci_malloc_zero(sizeof(*list) * list_len);
    if (list == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
    list[0] = alias;
    alias   = NULL;
    goto done;
  } else if (status != CI_ENOTFOUND) {
    goto done;
  }

  /* See if searching is eligible at all, if not, look up as-is only */
  if (!ci_search_eligible(channel, name)) {
    list_len = 1;
    list     = ci_malloc_zero(sizeof(*list) * list_len);
    if (list == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
    list[0] = ci_strdup(name);
    if (list[0] == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    } else {
      status = CI_SUCCESS;
    }
    goto done;
  }

  /* Count the number of dots in name, 1 less than label count */
  ndots = ci_name_label_cnt(name);
  if (ndots > 0) {
    ndots--;
  }

  /* Allocate an entry for each search domain, plus one for as-is */
  list_len = channel->ndomains + 1;
  list     = ci_malloc_zero(sizeof(*list) * list_len);
  if (list == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  /* Set status here, its possible there are no search domains at all, so
   * status may be CI_ENOTFOUND from ci_lookup_hostaliases(). */
  status = CI_SUCCESS;

  /* Try as-is first */
  if (ndots >= channel->ndots) {
    list[idx] = ci_strdup(name);
    if (list[idx] == NULL) {
      status = CI_ENOMEM;
      goto done;
    }
    idx++;
  }

  /* Append each search suffix to the name */
  for (i = 0; i < channel->ndomains; i++) {
    status = ci_cat_domain(name, channel->domains[i], &list[idx]);
    if (status != CI_SUCCESS) {
      goto done;
    }
    idx++;
  }

  /* Try as-is last */
  if (ndots < channel->ndots) {
    list[idx] = ci_strdup(name);
    if (list[idx] == NULL) {
      status = CI_ENOMEM;
      goto done;
    }
    idx++;
  }


done:
  if (status == CI_SUCCESS) {
    *names     = list;
    *names_len = list_len;
  } else {
    ci_strsplit_free(list, list_len);
  }

  ci_free(alias);
  return status;
}

static ci_status_t ci_search_int(ci_channel_t          *channel,
                                     const ci_dns_record_t *dnsrec,
                                     ci_callback_dnsrec callback, void *arg)
{
  struct search_query *squery = NULL;
  const char          *name;
  ci_status_t        status       = CI_SUCCESS;
  ci_bool_t          skip_cleanup = CI_FALSE;

  /* Extract the name for the search. Note that searches are only supported for
   * DNS records containing a single query.
   */
  if (ci_dns_record_query_cnt(dnsrec) != 1) {
    status = CI_EBADQUERY;
    goto fail;
  }

  status = ci_dns_record_query_get(dnsrec, 0, &name, NULL, NULL);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  /* Per RFC 7686, reject queries for ".onion" domain names with NXDOMAIN. */
  if (ci_is_onion_domain(name)) {
    status = CI_ENOTFOUND;
    goto fail;
  }

  /* Allocate a search_query structure to hold the state necessary for
   * doing multiple lookups.
   */
  squery = ci_malloc_zero(sizeof(*squery));
  if (squery == NULL) {
    status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto fail;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  squery->channel = channel;

  /* Duplicate DNS record since, name will need to be rewritten */
  squery->dnsrec = ci_dns_record_duplicate(dnsrec);
  if (squery->dnsrec == NULL) {
    status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto fail;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  squery->callback        = callback;
  squery->arg             = arg;
  squery->timeouts        = 0;
  squery->ever_got_nodata = CI_FALSE;

  status =
    ci_search_name_list(channel, name, &squery->names, &squery->names_cnt);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  status = ci_search_next(channel, squery, &skip_cleanup);
  if (status != CI_SUCCESS) {
    goto fail;
  }

  return status;

fail:
  if (!skip_cleanup) {
    squery_free(squery);
    callback(arg, status, 0, NULL);
  }
  return status;
}

/* Callback argument structure passed to ci_dnsrec_convert_cb(). */
typedef struct {
  ci_callback callback;
  void         *arg;
} dnsrec_convert_arg_t;

/*! Function to create callback arg for converting from ci_callback_dnsrec
 *  to ci_calback */
void *ci_dnsrec_convert_arg(ci_callback callback, void *arg)
{
  dnsrec_convert_arg_t *carg = ci_malloc_zero(sizeof(*carg));
  if (carg == NULL) {
    return NULL;
  }
  carg->callback = callback;
  carg->arg      = arg;
  return carg;
}

/*! Callback function used to convert from the ci_callback_dnsrec prototype to
 *  the ci_callback prototype, by writing the result and passing that to
 *  the inner callback.
 */
void ci_dnsrec_convert_cb(void *arg, ci_status_t status, size_t timeouts,
                            const ci_dns_record_t *dnsrec)
{
  dnsrec_convert_arg_t *carg = arg;
  unsigned char        *abuf = NULL;
  size_t                alen = 0;

  if (dnsrec != NULL) {
    ci_status_t mystatus = ci_dns_write(dnsrec, &abuf, &alen);
    if (mystatus != CI_SUCCESS) {
      status = mystatus;
    }
  }

  carg->callback(carg->arg, (int)status, (int)timeouts, abuf, (int)alen);

  ci_free(abuf);
  ci_free(carg);
}

/* Search for a DNS name with given class and type. Wrapper around
 * ci_search_int() where the DNS record to search is first constructed.
 */
void ci_search(ci_channel_t *channel, const char *name, int dnsclass,
                 int type, ci_callback callback, void *arg)
{
  ci_status_t      status;
  ci_dns_record_t *dnsrec = NULL;
  size_t             max_udp_size;
  ci_dns_flags_t   rd_flag;
  void              *carg = NULL;
  if (channel == NULL || name == NULL) {
    return;
  }

  /* For now, ci_search_int() uses the ci_callback prototype. We need to
   * wrap the callback passed to this function in ci_dnsrec_convert_cb, to
   * convert from ci_callback_dnsrec to ci_callback. Allocate the convert
   * arg structure here.
   */
  carg = ci_dnsrec_convert_arg(callback, arg);
  if (carg == NULL) {
    callback(arg, CI_ENOMEM, 0, NULL, 0);
    return;
  }

  rd_flag      = !(channel->flags & CI_FLAG_NORECURSE) ? CI_FLAG_RD : 0;
  max_udp_size = (channel->flags & CI_FLAG_EDNS) ? channel->ednspsz : 0;
  status       = ci_dns_record_create_query(
    &dnsrec, name, (ci_dns_class_t)dnsclass, (ci_dns_rec_type_t)type, 0,
    rd_flag, max_udp_size);
  if (status != CI_SUCCESS) {
    callback(arg, (int)status, 0, NULL, 0);
    ci_free(carg);
    return;
  }

  ci_channel_lock(channel);
  ci_search_int(channel, dnsrec, ci_dnsrec_convert_cb, carg);
  ci_channel_unlock(channel);

  ci_dns_record_destroy(dnsrec);
}

/* Search for a DNS record. Wrapper around ci_search_int(). */
ci_status_t ci_search_dnsrec(ci_channel_t          *channel,
                                 const ci_dns_record_t *dnsrec,
                                 ci_callback_dnsrec callback, void *arg)
{
  ci_status_t status;

  if (channel == NULL || dnsrec == NULL || callback == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ci_channel_lock(channel);
  status = ci_search_int(channel, dnsrec, callback, arg);
  ci_channel_unlock(channel);

  return status;
}

/* Concatenate two domains. */
ci_status_t ci_cat_domain(const char *name, const char *domain, char **s)
{
  size_t nlen = ci_strlen(name);
  size_t dlen = ci_strlen(domain);

  *s = ci_malloc(nlen + 1 + dlen + 1);
  if (!*s) {
    return CI_ENOMEM;
  }
  memcpy(*s, name, nlen);
  (*s)[nlen] = '.';
  if (ci_streq(domain, ".")) {
    /* Avoid appending the root domain to the separator, which would set *s to
       an ill-formed value (ending in two consecutive dots). */
    dlen = 0;
  }
  memcpy(*s + nlen + 1, domain, dlen);
  (*s)[nlen + 1 + dlen] = 0;
  return CI_SUCCESS;
}

ci_status_t ci_lookup_hostaliases(const ci_channel_t *channel,
                                      const char *name, char **alias)
{
  ci_status_t status      = CI_SUCCESS;
  const char   *hostaliases = NULL;
  ci_buf_t   *buf         = NULL;
  ci_array_t *lines       = NULL;
  size_t        num;
  size_t        i;

  if (channel == NULL || name == NULL || alias == NULL) {
    return CI_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *alias = NULL;

  /* Configuration says to not perform alias lookup */
  if (channel->flags & CI_FLAG_NOALIASES) {
    return CI_ENOTFOUND;
  }

  /* If a domain has a '.', its not allowed to perform an alias lookup */
  if (strchr(name, '.') != NULL) {
    return CI_ENOTFOUND;
  }

  hostaliases = getenv("HOSTALIASES");
  if (hostaliases == NULL) {
    status = CI_ENOTFOUND;
    goto done;
  }

  buf = ci_buf_create();
  if (buf == NULL) {
    status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  status = ci_buf_load_file(hostaliases, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* The HOSTALIASES file is structured as one alias per line.  The first
   * field in the line is the simple hostname with no periods, followed by
   * whitespace, then the full domain name, e.g.:
   *
   * c-ci  www.c-ci.org
   * curl    www.curl.se
   */

  status = ci_buf_split(buf, (const unsigned char *)"\n", 1,
                          CI_BUF_SPLIT_TRIM, 0, &lines);
  if (status != CI_SUCCESS) {
    goto done;
  }

  num = ci_array_len(lines);
  for (i = 0; i < num; i++) {
    ci_buf_t **bufptr       = ci_array_at(lines, i);
    ci_buf_t  *line         = *bufptr;
    char         hostname[64] = "";
    char         fqdn[256]    = "";

    /* Pull off hostname */
    ci_buf_tag(line);
    ci_buf_consume_nonwhitespace(line);
    if (ci_buf_tag_fetch_string(line, hostname, sizeof(hostname)) !=
        CI_SUCCESS) {
      continue;
    }

    /* Match hostname */
    if (!ci_strcaseeq(hostname, name)) {
      continue;
    }

    /* consume whitespace */
    ci_buf_consume_whitespace(line, CI_TRUE);

    /* pull off fqdn */
    ci_buf_tag(line);
    ci_buf_consume_nonwhitespace(line);
    if (ci_buf_tag_fetch_string(line, fqdn, sizeof(fqdn)) != CI_SUCCESS ||
        ci_strlen(fqdn) == 0) {
      continue;
    }

    /* Validate characterset */
    if (!ci_is_hostname(fqdn)) {
      continue;
    }

    *alias = ci_strdup(fqdn);
    if (*alias == NULL) {
      status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* Good! */
    status = CI_SUCCESS;
    goto done;
  }

  status = CI_ENOTFOUND;

done:
  ci_buf_destroy(buf);
  ci_array_destroy(lines);

  return status;
}
