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

struct ci_qcache {
  ci_htable_strvp_t *cache;
  ci_slist_t        *expire;
  unsigned int         max_ttl;
};

typedef struct {
  char              *key;
  ci_dns_record_t *dnsrec;
  time_t             expire_ts;
  time_t             insert_ts;
} ci_qcache_entry_t;

static char *ci_qcache_calc_key(const ci_dns_record_t *dnsrec)
{
  ci_buf_t      *buf = ci_buf_create();
  size_t           i;
  ci_status_t    status;
  ci_dns_flags_t flags;

  if (dnsrec == NULL || buf == NULL) {
    return NULL; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* Format is OPCODE|FLAGS[|QTYPE1|QCLASS1|QNAME1]... */

  status = ci_buf_append_str(
    buf, ci_dns_opcode_tostr(ci_dns_record_get_opcode(dnsrec)));
  if (status != CI_SUCCESS) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  status = ci_buf_append_byte(buf, '|');
  if (status != CI_SUCCESS) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  flags = ci_dns_record_get_flags(dnsrec);
  /* Only care about RD and CD */
  if (flags & CI_FLAG_RD) {
    status = ci_buf_append_str(buf, "rd");
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }
  if (flags & CI_FLAG_CD) {
    status = ci_buf_append_str(buf, "cd");
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  for (i = 0; i < ci_dns_record_query_cnt(dnsrec); i++) {
    const char         *name;
    size_t              name_len;
    ci_dns_rec_type_t qtype;
    ci_dns_class_t    qclass;

    status = ci_dns_record_query_get(dnsrec, i, &name, &qtype, &qclass);
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    status = ci_buf_append_byte(buf, '|');
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    status = ci_buf_append_str(buf, ci_dns_rec_type_tostr(qtype));
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    status = ci_buf_append_byte(buf, '|');
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    status = ci_buf_append_str(buf, ci_dns_class_tostr(qclass));
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    status = ci_buf_append_byte(buf, '|');
    if (status != CI_SUCCESS) {
      goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    /* On queries, a '.' may be appended to the name to indicate an explicit
     * name lookup without performing a search.  Strip this since its not part
     * of a cached response. */
    name_len = ci_strlen(name);
    if (name_len && name[name_len - 1] == '.') {
      name_len--;
    }

    if (name_len > 0) {
      status = ci_buf_append(buf, (const unsigned char *)name, name_len);
      if (status != CI_SUCCESS) {
        goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  return ci_buf_finish_str(buf, NULL);

/* LCOV_EXCL_START: OutOfMemory */
fail:
  ci_buf_destroy(buf);
  return NULL;
  /* LCOV_EXCL_STOP */
}

static void ci_qcache_expire(ci_qcache_t *cache, const ci_timeval_t *now)
{
  ci_slist_node_t *node;

  if (cache == NULL) {
    return;
  }

  while ((node = ci_slist_node_first(cache->expire)) != NULL) {
    const ci_qcache_entry_t *entry = ci_slist_node_val(node);

    /* If now is NULL, we're flushing everything, so don't break */
    if (now != NULL && entry->expire_ts > now->sec) {
      break;
    }

    ci_htable_strvp_remove(cache->cache, entry->key);
    ci_slist_node_destroy(node);
  }
}

void ci_qcache_flush(ci_qcache_t *cache)
{
  ci_qcache_expire(cache, NULL /* flush all */);
}

void ci_qcache_destroy(ci_qcache_t *cache)
{
  if (cache == NULL) {
    return;
  }

  ci_htable_strvp_destroy(cache->cache);
  ci_slist_destroy(cache->expire);
  ci_free(cache);
}

static int ci_qcache_entry_sort_cb(const void *arg1, const void *arg2)
{
  const ci_qcache_entry_t *entry1 = arg1;
  const ci_qcache_entry_t *entry2 = arg2;

  if (entry1->expire_ts > entry2->expire_ts) {
    return 1;
  }

  if (entry1->expire_ts < entry2->expire_ts) {
    return -1;
  }

  return 0;
}

static void ci_qcache_entry_destroy_cb(void *arg)
{
  ci_qcache_entry_t *entry = arg;
  if (entry == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ci_free(entry->key);
  ci_dns_record_destroy(entry->dnsrec);
  ci_free(entry);
}

ci_status_t ci_qcache_create(ci_rand_state *rand_state,
                                 unsigned int     max_ttl,
                                 ci_qcache_t  **cache_out)
{
  ci_status_t  status = CI_SUCCESS;
  ci_qcache_t *cache;

  cache = ci_malloc_zero(sizeof(*cache));
  if (cache == NULL) {
    status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  cache->cache = ci_htable_strvp_create(NULL);
  if (cache->cache == NULL) {
    status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  cache->expire = ci_slist_create(rand_state, ci_qcache_entry_sort_cb,
                                    ci_qcache_entry_destroy_cb);
  if (cache->expire == NULL) {
    status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  cache->max_ttl = max_ttl;

done:
  if (status != CI_SUCCESS) {
    *cache_out = NULL;
    ci_qcache_destroy(cache);
    return status;
  }

  *cache_out = cache;
  return status;
}

static unsigned int ci_qcache_calc_minttl(ci_dns_record_t *dnsrec)
{
  unsigned int minttl = 0xFFFFFFFF;
  size_t       sect;

  for (sect = CI_SECTION_ANSWER; sect <= CI_SECTION_ADDITIONAL; sect++) {
    size_t i;
    for (i = 0; i < ci_dns_record_rr_cnt(dnsrec, (ci_dns_section_t)sect);
         i++) {
      const ci_dns_rr_t *rr =
        ci_dns_record_rr_get(dnsrec, (ci_dns_section_t)sect, i);
      ci_dns_rec_type_t type = ci_dns_rr_get_type(rr);
      unsigned int        ttl  = ci_dns_rr_get_ttl(rr);

      /* TTL is meaningless on these record types */
      if (type == CI_REC_TYPE_OPT || type == CI_REC_TYPE_SOA ||
          type == CI_REC_TYPE_SIG) {
        continue;
      }

      if (ttl < minttl) {
        minttl = ttl;
      }
    }
  }

  return minttl;
}

static unsigned int ci_qcache_soa_minimum(ci_dns_record_t *dnsrec)
{
  size_t i;

  /* RFC 2308 Section 5 says its the minimum of MINIMUM and the TTL of the
   * record. */
  for (i = 0; i < ci_dns_record_rr_cnt(dnsrec, CI_SECTION_AUTHORITY); i++) {
    const ci_dns_rr_t *rr =
      ci_dns_record_rr_get(dnsrec, CI_SECTION_AUTHORITY, i);
    ci_dns_rec_type_t type = ci_dns_rr_get_type(rr);
    unsigned int        ttl;
    unsigned int        minimum;

    if (type != CI_REC_TYPE_SOA) {
      continue;
    }

    minimum = ci_dns_rr_get_u32(rr, CI_RR_SOA_MINIMUM);
    ttl     = ci_dns_rr_get_ttl(rr);

    if (ttl > minimum) {
      return minimum;
    }
    return ttl;
  }

  return 0;
}

/* On success, takes ownership of dnsrec */
static ci_status_t ci_qcache_insert_int(ci_qcache_t           *qcache,
                                            ci_dns_record_t       *qresp,
                                            const ci_dns_record_t *qreq,
                                            const ci_timeval_t    *now)
{
  ci_qcache_entry_t *entry;
  unsigned int         ttl;
  ci_dns_rcode_t     rcode = ci_dns_record_get_rcode(qresp);
  ci_dns_flags_t     flags = ci_dns_record_get_flags(qresp);

  if (qcache == NULL || qresp == NULL) {
    return CI_EFORMERR;
  }

  /* Only save NOERROR or NXDOMAIN */
  if (rcode != CI_RCODE_NOERROR && rcode != CI_RCODE_NXDOMAIN) {
    return CI_ENOTIMP;
  }

  /* Don't save truncated queries */
  if (flags & CI_FLAG_TC) {
    return CI_ENOTIMP;
  }

  /* Look at SOA for NXDOMAIN for minimum */
  if (rcode == CI_RCODE_NXDOMAIN) {
    ttl = ci_qcache_soa_minimum(qresp);
  } else {
    ttl = ci_qcache_calc_minttl(qresp);
  }

  if (ttl > qcache->max_ttl) {
    ttl = qcache->max_ttl;
  }

  /* Don't cache something that is already expired */
  if (ttl == 0) {
    return CI_EREFUSED;
  }

  entry = ci_malloc_zero(sizeof(*entry));
  if (entry == NULL) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  entry->dnsrec    = qresp;
  entry->expire_ts = (time_t)now->sec + (time_t)ttl;
  entry->insert_ts = (time_t)now->sec;

  /* We can't guarantee the server responded with the same flags as the
   * request had, so we have to re-parse the request in order to generate the
   * key for caching, but we'll only do this once we know for sure we really
   * want to cache it */
  entry->key = ci_qcache_calc_key(qreq);
  if (entry->key == NULL) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (!ci_htable_strvp_insert(qcache->cache, entry->key, entry)) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (ci_slist_insert(qcache->expire, entry) == NULL) {
    goto fail; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  return CI_SUCCESS;

/* LCOV_EXCL_START: OutOfMemory */
fail:
  if (entry != NULL && entry->key != NULL) {
    ci_htable_strvp_remove(qcache->cache, entry->key);
    ci_free(entry->key);
    ci_free(entry);
  }
  return CI_ENOMEM;
  /* LCOV_EXCL_STOP */
}

ci_status_t ci_qcache_fetch(ci_channel_t           *channel,
                                const ci_timeval_t     *now,
                                const ci_dns_record_t  *dnsrec,
                                const ci_dns_record_t **dnsrec_resp)
{
  char                *key = NULL;
  ci_qcache_entry_t *entry;
  ci_status_t        status = CI_SUCCESS;

  if (channel == NULL || dnsrec == NULL || dnsrec_resp == NULL) {
    return CI_EFORMERR;
  }

  if (channel->qcache == NULL) {
    return CI_ENOTFOUND;
  }

  ci_qcache_expire(channel->qcache, now);

  key = ci_qcache_calc_key(dnsrec);
  if (key == NULL) {
    status = CI_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  entry = ci_htable_strvp_get_direct(channel->qcache->cache, key);
  if (entry == NULL) {
    status = CI_ENOTFOUND;
    goto done;
  }

  ci_dns_record_ttl_decrement(entry->dnsrec,
                                (unsigned int)(now->sec - entry->insert_ts));

  *dnsrec_resp = entry->dnsrec;

done:
  ci_free(key);
  return status;
}

ci_status_t ci_qcache_insert(ci_channel_t       *channel,
                                 const ci_timeval_t *now,
                                 const ci_query_t   *query,
                                 ci_dns_record_t    *dnsrec)
{
  return ci_qcache_insert_int(channel->qcache, dnsrec, query->query, now);
}
