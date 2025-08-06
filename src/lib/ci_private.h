/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2010 Daniel Stenberg
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
#ifndef __CI_PRIVATE_H
#define __CI_PRIVATE_H

/* ============================================================================
 * NOTE: All c-ci source files should include ci_private.h as the first
 *       header.
 * ============================================================================
 */

#include "ci_setup.h"
#include "ci.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#include "ci_mem.h"
#include "ci_ipv6.h"
#include "util/ci_math.h"
#include "util/ci_time.h"
#include "util/ci_rand.h"
#include "ci_array.h"
#include "ci_llist.h"
#include "dsa/ci_slist.h"
#include "ci_htable_strvp.h"
#include "ci_htable_szvp.h"
#include "ci_htable_asvp.h"
#include "ci_htable_dict.h"
#include "ci_htable_vpvp.h"
#include "ci_htable_vpstr.h"
#include "record/ci_dns_multistring.h"
#include "ci_buf.h"
#include "record/ci_dns_private.h"
#include "util/ci_iface_ips.h"
#include "util/ci_threads.h"
#include "ci_socket.h"
#include "ci_conn.h"
#include "ci_str.h"
#include "str/ci_strsplit.h"
#include "util/ci_uri.h"

#ifndef HAVE_GETENV
#  include "ci_getenv.h"
#  define getenv(ptr) ci_getenv(ptr)
#endif

#define DEFAULT_TIMEOUT 2000 /* milliseconds */
#define DEFAULT_TRIES   3
#ifndef INADDR_NONE
#  define INADDR_NONE 0xffffffff
#endif

/* By using a double cast, we can get rid of the bogus warning of
 * warning: cast from 'const struct sockaddr *' to 'const struct sockaddr_in6 *'
 * increases required alignment from 1 to 4 [-Wcast-align]
 */
#define CI_INADDR_CAST(type, var) ((type)((const void *)var))

#if defined(USE_WINSOCK)

#  define WIN_NS_9X     "System\\CurrentControlSet\\Services\\VxD\\MSTCP"
#  define WIN_NS_NT_KEY "System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#  define WIN_DNSCLIENT "Software\\Policies\\Microsoft\\System\\DNSClient"
#  define WIN_NT_DNSCLIENT \
    "Software\\Policies\\Microsoft\\Windows NT\\DNSClient"
#  define NAMESERVER           "NameServer"
#  define DHCPNAMESERVER       "DhcpNameServer"
#  define DATABASEPATH         "DatabasePath"
#  define WIN_PATH_HOSTS       "\\hosts"
#  define SEARCHLIST_KEY       "SearchList"
#  define PRIMARYDNSSUFFIX_KEY "PrimaryDNSSuffix"
#  define INTERFACES_KEY       "Interfaces"
#  define DOMAIN_KEY           "Domain"
#  define DHCPDOMAIN_KEY       "DhcpDomain"
#  define PATH_RESOLV_CONF     ""
#elif defined(WATT32)

#  define PATH_RESOLV_CONF "/dev/ENV/etc/resolv.conf"
W32_FUNC const char *_w32_GetHostsFile(void);

#elif defined(NETWARE)

#  define PATH_RESOLV_CONF "sys:/etc/resolv.cfg"
#  define PATH_HOSTS       "sys:/etc/hosts"

#elif defined(__riscos__)

#  define PATH_RESOLV_CONF ""
#  define PATH_HOSTS       "InetDBase:Hosts"

#elif defined(__HAIKU__)

#  define PATH_RESOLV_CONF "/system/settings/network/resolv.conf"
#  define PATH_HOSTS       "/system/settings/network/hosts"

#else

#  define PATH_RESOLV_CONF "/etc/resolv.conf"
#  ifdef ETC_INET
#    define PATH_HOSTS "/etc/inet/hosts"
#  else
#    define PATH_HOSTS "/etc/hosts"
#  endif

#endif

/********* EDNS defines section ******/
#define EDNSPACKETSZ                                          \
  1232 /* Reasonable UDP payload size, as agreed by operators \
          https://www.dnsflagday.net/2020/#faq */
#define MAXENDSSZ   4096 /* Maximum (local) limit for edns packet size */
#define EDNSFIXEDSZ 11   /* Size of EDNS header */

/********* EDNS defines section ******/

/* Default values for server failover behavior. We retry failed servers with
 * a 10% probability and a minimum delay of 5 seconds between retries.
 */
#define DEFAULT_SERVER_RETRY_CHANCE 10
#define DEFAULT_SERVER_RETRY_DELAY  5000

struct ci_query;
typedef struct ci_query ci_query_t;

/* State to represent a DNS query */
struct ci_query {
  /* Query ID from qbuf, for faster lookup, and current timeout */
  unsigned short       qid; /* host byte order */
  ci_timeval_t       ts;  /*!< Timestamp query was sent */
  ci_timeval_t       timeout;
  ci_channel_t      *channel;

  /*
   * Node object for each list entry the query belongs to in order to
   * make removal operations O(1).
   */
  ci_slist_node_t   *node_queries_by_timeout;
  ci_llist_node_t   *node_queries_to_conn;
  ci_llist_node_t   *node_all_queries;

  /* connection handle query is associated with */
  ci_conn_t         *conn;

  /* Query */
  ci_dns_record_t   *query;

  ci_callback_dnsrec callback;
  void                *arg;

  /* Query status */
  size_t        try_count; /* Number of times we tried this query already. */
  size_t        cookie_try_count; /* Attempt count for cookie resends */
  ci_bool_t   using_tcp;
  ci_status_t error_status;
  size_t        timeouts;   /* number of timeouts we saw for this request */
  ci_bool_t   no_retries; /* do not perform any additional retries, this is
                             * set when a query is to be canceled */
};

struct apattern {
  struct ci_addr addr;
  unsigned char    mask;
};

struct ci_qcache;
typedef struct ci_qcache ci_qcache_t;

struct ci_hosts_file;
typedef struct ci_hosts_file ci_hosts_file_t;

struct ci_channeldata {
  /* Configuration data */
  unsigned int         flags;
  size_t               timeout; /* in milliseconds */
  size_t               tries;
  size_t               ndots;
  size_t               maxtimeout;                 /* in milliseconds */
  ci_bool_t          rotate;
  unsigned short       udp_port;                   /* stored in network order */
  unsigned short       tcp_port;                   /* stored in network order */
  int                  socket_send_buffer_size;    /* setsockopt takes int */
  int                  socket_receive_buffer_size; /* setsockopt takes int */
  char               **domains;
  size_t               ndomains;
  struct apattern     *sortlist;
  size_t               nsort;
  char                *lookups;
  size_t               ednspsz;
  unsigned int         qcache_max_ttl;
  ci_evsys_t         evsys;
  unsigned int         optmask;

  /* For binding to local devices and/or IP addresses.  Leave
   * them null/zero for no binding.
   */
  char                 local_dev_name[32];
  unsigned int         local_ip4;
  unsigned char        local_ip6[16];

  /* Thread safety lock */
  ci_thread_mutex_t *lock;

  /* Conditional to wake waiters when queue is empty */
  ci_thread_cond_t  *cond_empty;

  /* Server addresses and communications state. Sorted by least consecutive
   * failures, followed by the configuration order if failures are equal. */
  ci_slist_t        *servers;

  /* random state to use when generating new ids and generating retry penalties
   */
  ci_rand_state     *rand_state;

  /* All active queries in a single list */
  ci_llist_t        *all_queries;
  /* Queries bucketed by qid, for quickly dispatching DNS responses: */
  ci_htable_szvp_t  *queries_by_qid;

  /* Queries bucketed by timeout, for quickly handling timeouts: */
  ci_slist_t        *queries_by_timeout;

  /* Map linked list node member for connection to file descriptor.  We use
   * the node instead of the connection object itself so we can quickly look
   * up a connection and remove it if necessary (as otherwise we'd have to
   * scan all connections) */
  ci_htable_asvp_t  *connnode_by_socket;

  ci_sock_state_cb   sock_state_cb;
  void                *sock_state_cb_data;

  ci_sock_create_callback           sock_create_cb;
  void                               *sock_create_cb_data;

  ci_sock_config_callback           sock_config_cb;
  void                               *sock_config_cb_data;

  struct ci_socket_functions_ex     sock_funcs;
  void                               *sock_func_cb_data;
  const struct ci_socket_functions *legacy_sock_funcs;
  void                               *legacy_sock_funcs_cb_data;

  ci_pending_write_cb               notify_pending_write_cb;
  void                               *notify_pending_write_cb_data;
  ci_bool_t                         notify_pending_write;

  /* Path for resolv.conf file, configurable via ci_options */
  char                               *resolvconf_path;

  /* Path for hosts file, configurable via ci_options */
  char                               *hosts_path;

  /* Maximum UDP queries per connection allowed */
  size_t                              udp_max_queries;

  /* Cache of local hosts file */
  ci_hosts_file_t                  *hf;

  /* Query Cache */
  ci_qcache_t                      *qcache;

  /* Fields controlling server failover behavior.
   * The retry chance is the probability (1/N) by which we will retry a failed
   * server instead of the best server when selecting a server to send queries
   * to.
   * The retry delay is the minimum time in milliseconds to wait between doing
   * such retries (applied per-server).
   */
  unsigned short                      server_retry_chance;
  size_t                              server_retry_delay;

  /* Callback triggered when a server has a successful or failed response */
  ci_server_state_callback          server_state_cb;
  void                               *server_state_cb_data;

  /* TRUE if a reinit is pending.  Reinit spawns a thread to read the system
   * configuration and then apply the configuration since configuration
   * reading may block.  The thread handle is provided for waiting on thread
   * exit. */
  ci_bool_t                         reinit_pending;
  ci_thread_t                      *reinit_thread;

  /* Whether the system is up or not.  This is mainly to prevent deadlocks
   * and access violations during the cleanup process.  Some things like
   * system config changes might get triggered and we need a flag to make
   * sure we don't take action. */
  ci_bool_t                         sys_up;
};

/* Does the domain end in ".onion" or ".onion."? Case-insensitive. */
ci_bool_t   ci_is_onion_domain(const char *name);

/* Returns one of the normal ci status codes like CI_SUCCESS */
ci_status_t ci_send_query(ci_server_t *requested_server /* Optional */,
                              ci_query_t *query, const ci_timeval_t *now);
ci_status_t ci_requeue_query(ci_query_t *query, const ci_timeval_t *now,
                                 ci_status_t            status,
                                 ci_bool_t              inc_try_count,
                                 const ci_dns_record_t *dnsrec);

/*! Count the number of labels (dots+1) in a domain */
size_t        ci_name_label_cnt(const char *name);

/*! Retrieve a list of names to use for searching.  The first successful
 *  query in the list wins.  This function also uses the HOSTSALIASES file
 *  as well as uses channel configuration to determine the search order.
 *
 *  \param[in]  channel   initialized ci channel
 *  \param[in]  name      initial name being searched
 *  \param[out] names     array of names to attempt, use ci_strsplit_free()
 *                        when no longer needed.
 *  \param[out] names_len number of names in array
 *  \return CI_SUCCESS on success, otherwise one of the other error codes.
 */
ci_status_t ci_search_name_list(const ci_channel_t *channel,
                                    const char *name, char ***names,
                                    size_t *names_len);

/*! Function to create callback arg for converting from ci_callback_dnsrec
 *  to ci_calback */
void         *ci_dnsrec_convert_arg(ci_callback callback, void *arg);

/*! Callback function used to convert from the ci_callback_dnsrec prototype to
 *  the ci_callback prototype, by writing the result and passing that to
 *  the inner callback.
 */
void ci_dnsrec_convert_cb(void *arg, ci_status_t status, size_t timeouts,
                            const ci_dns_record_t *dnsrec);

void ci_free_query(ci_query_t *query);

unsigned short ci_generate_new_id(ci_rand_state *state);
ci_status_t  ci_expand_name_validated(const unsigned char *encoded,
                                          const unsigned char *abuf, size_t alen,
                                          char **s, size_t *enclen,
                                          ci_bool_t is_hostname);
ci_status_t  ci_expand_string_ex(const unsigned char *encoded,
                                     const unsigned char *abuf, size_t alen,
                                     unsigned char **s, size_t *enclen);
ci_status_t  ci_init_servers_state(ci_channel_t *channel);
ci_status_t  ci_init_by_options(ci_channel_t            *channel,
                                    const struct ci_options *options,
                                    int                        optmask);
ci_status_t  ci_init_by_sysconfig(ci_channel_t *channel);
void           ci_set_socket_functions_def(ci_channel_t *channel);

typedef struct {
  ci_llist_t    *sconfig;
  struct apattern *sortlist;
  size_t           nsortlist;
  char           **domains;
  size_t           ndomains;
  char            *lookups;
  size_t           ndots;
  size_t           tries;
  ci_bool_t      rotate;
  size_t           timeout_ms;
  ci_bool_t      usevc;
} ci_sysconfig_t;

ci_status_t ci_sysconfig_set_options(ci_sysconfig_t *sysconfig,
                                         const char       *str);

ci_status_t ci_init_by_environment(ci_sysconfig_t *sysconfig);

ci_status_t ci_init_sysconfig_files(const ci_channel_t *channel,
                                        ci_sysconfig_t     *sysconfig);
#ifdef __APPLE__
ci_status_t ci_init_sysconfig_macos(const ci_channel_t *channel,
                                        ci_sysconfig_t     *sysconfig);
#endif
#ifdef USE_WINSOCK
ci_status_t ci_init_sysconfig_windows(const ci_channel_t *channel,
                                          ci_sysconfig_t     *sysconfig);
#endif

ci_status_t ci_parse_sortlist(struct apattern **sortlist, size_t *nsort,
                                  const char *str);

/* Returns CI_SUCCESS if alias found, alias is set.  Returns CI_ENOTFOUND
 * if not alias found.  Returns other errors on critical failure like
 * CI_ENOMEM */
ci_status_t ci_lookup_hostaliases(const ci_channel_t *channel,
                                      const char *name, char **alias);

ci_status_t ci_cat_domain(const char *name, const char *domain, char **s);
ci_status_t ci_sortaddrinfo(ci_channel_t            *channel,
                                struct ci_addrinfo_node *ai_node);

void          ci_freeaddrinfo_nodes(struct ci_addrinfo_node *ai_node);
ci_bool_t   ci_is_localhost(const char *name);

struct ci_addrinfo_node    *
  ci_append_addrinfo_node(struct ci_addrinfo_node **ai_node);
void ci_addrinfo_cat_nodes(struct ci_addrinfo_node **head,
                             struct ci_addrinfo_node  *tail);

void ci_freeaddrinfo_cnames(struct ci_addrinfo_cname *ai_cname);

struct ci_addrinfo_cname             *
  ci_append_addrinfo_cname(struct ci_addrinfo_cname **ai_cname);

ci_status_t ci_append_ai_node(int aftype, unsigned short port,
                                  unsigned int ttl, const void *adata,
                                  struct ci_addrinfo_node **nodes);

void          ci_addrinfo_cat_cnames(struct ci_addrinfo_cname **head,
                                       struct ci_addrinfo_cname  *tail);

ci_status_t ci_parse_into_addrinfo(const ci_dns_record_t *dnsrec,
                                       ci_bool_t    cname_only_is_enodata,
                                       unsigned short port,
                                       struct ci_addrinfo *ai);
ci_status_t ci_parse_ptr_reply_dnsrec(const ci_dns_record_t *dnsrec,
                                          const void *addr, int addrlen,
                                          int family, struct hostent **host);

ci_status_t ci_addrinfo2hostent(const struct ci_addrinfo *ai, int family,
                                    struct hostent **host);
ci_status_t ci_addrinfo2addrttl(const struct ci_addrinfo *ai, int family,
                                    size_t                req_naddrttls,
                                    struct ci_addrttl  *addrttls,
                                    struct ci_addr6ttl *addr6ttls,
                                    size_t               *naddrttls);
ci_status_t ci_addrinfo_localhost(const char *name, unsigned short port,
                                      const struct ci_addrinfo_hints *hints,
                                      struct ci_addrinfo             *ai);

ci_status_t ci_servers_update(ci_channel_t *channel,
                                  ci_llist_t   *server_list,
                                  ci_bool_t     user_specified);
ci_status_t
  ci_sconfig_append(const ci_channel_t *channel, ci_llist_t **sconfig,
                      const struct ci_addr *addr, unsigned short udp_port,
                      unsigned short tcp_port, const char *ll_iface);
ci_status_t ci_sconfig_append_fromstr(const ci_channel_t *channel,
                                          ci_llist_t        **sconfig,
                                          const char           *str,
                                          ci_bool_t           ignore_invalid);
ci_status_t ci_in_addr_to_sconfig_llist(const struct in_addr *servers,
                                            size_t                nservers,
                                            ci_llist_t        **llist);
ci_status_t ci_get_server_addr(const ci_server_t *server,
                                   ci_buf_t          *buf);

struct ci_hosts_entry;
typedef struct ci_hosts_entry ci_hosts_entry_t;

void                            ci_hosts_file_destroy(ci_hosts_file_t *hf);
ci_status_t ci_hosts_search_ipaddr(ci_channel_t *channel,
                                       ci_bool_t use_env, const char *ipaddr,
                                       const ci_hosts_entry_t **entry);
ci_status_t ci_hosts_search_host(ci_channel_t *channel,
                                     ci_bool_t use_env, const char *host,
                                     const ci_hosts_entry_t **entry);
ci_status_t ci_hosts_entry_to_hostent(const ci_hosts_entry_t *entry,
                                          int family, struct hostent **hostent);
ci_status_t ci_hosts_entry_to_addrinfo(const ci_hosts_entry_t *entry,
                                           const char *name, int family,
                                           unsigned short        port,
                                           ci_bool_t           want_cnames,
                                           struct ci_addrinfo *ai);

/* Same as ci_query_dnsrec() except does not take a channel lock.  Use this
 * if a channel lock is already held */
ci_status_t ci_query_nolock(ci_channel_t *channel, const char *name,
                                ci_dns_class_t     dnsclass,
                                ci_dns_rec_type_t  type,
                                ci_callback_dnsrec callback, void *arg,
                                unsigned short *qid);

/*! Flags controlling behavior for ci_send_nolock() */
typedef enum {
  CI_SEND_FLAG_NOCACHE = 1 << 0, /*!< Do not query the cache */
  CI_SEND_FLAG_NORETRY = 1 << 1  /*!< Do not retry this query on error */
} ci_send_flags_t;

/* Similar to ci_send_dnsrec() except does not take a channel lock, allows
 * specifying a particular server to use, and also flags controlling behavior.
 */
ci_status_t ci_send_nolock(ci_channel_t *channel, ci_server_t *server,
                               ci_send_flags_t        flags,
                               const ci_dns_record_t *dnsrec,
                               ci_callback_dnsrec callback, void *arg,
                               unsigned short *qid);

/* Same as ci_gethostbyaddr() except does not take a channel lock.  Use this
 * if a channel lock is already held */
void ci_gethostbyaddr_nolock(ci_channel_t *channel, const void *addr,
                               int addrlen, int family,
                               ci_host_callback callback, void *arg);

/*! Parse a compressed DNS name as defined in RFC1035 starting at the current
 *  offset within the buffer.
 *
 *  It is assumed that either a const buffer is being used, or before
 *  the message processing was started that ci_buf_reclaim() was called.
 *
 *  \param[in]  buf        Initialized buffer object
 *  \param[out] name       Pointer passed by reference to be filled in with
 *                         allocated string of the parsed name that must be
 *                         ci_free()'d by the caller.
 *  \param[in] is_hostname if CI_TRUE, will validate the character set for
 *                         a valid hostname or will return error.
 *  \return CI_SUCCESS on success
 */
ci_status_t ci_dns_name_parse(ci_buf_t *buf, char **name,
                                  ci_bool_t is_hostname);

/*! Write the DNS name to the buffer in the DNS domain-name syntax as a
 *  series of labels.  The maximum domain name length is 255 characters with
 *  each label being a maximum of 63 characters.  If the validate_hostname
 *  flag is set, it will strictly validate the character set.
 *
 *  \param[in,out]  buf   Initialized buffer object to write name to
 *  \param[in,out]  list  Pointer passed by reference to maintain a list of
 *                        domain name to indexes used for name compression.
 *                        Pass NULL (not by reference) if name compression isn't
 *                        desired.  Otherwise the list will be automatically
 *                        created upon first entry.
 *  \param[in]      validate_hostname Validate the hostname character set.
 *  \param[in]      name              Name to write out, it may have escape
 *                                    sequences.
 *  \return CI_SUCCESS on success, most likely CI_EBADNAME if the name is
 *          bad.
 */
ci_status_t ci_dns_name_write(ci_buf_t *buf, ci_llist_t **list,
                                  ci_bool_t validate_hostname,
                                  const char *name);

/*! Check if the queue is empty, if so, wake any waiters.  This is only
 *  effective if built with threading support.
 *
 *  Must be holding a channel lock when calling this function.
 *
 *  \param[in]  channel Initialized ci channel object
 */
void          ci_queue_notify_empty(ci_channel_t *channel);

#define CI_CONFIG_CHECK(x)                                              \
  (x && x->lookups && ci_slist_len(x->servers) > 0 && x->timeout > 0 && \
   x->tries > 0)

ci_bool_t   ci_subnet_match(const struct ci_addr *addr,
                                const struct ci_addr *subnet,
                                unsigned char           netmask);
ci_bool_t   ci_addr_is_linklocal(const struct ci_addr *addr);

void          ci_qcache_destroy(ci_qcache_t *cache);
ci_status_t ci_qcache_create(ci_rand_state *rand_state,
                                 unsigned int     max_ttl,
                                 ci_qcache_t  **cache_out);
void          ci_qcache_flush(ci_qcache_t *cache);
ci_status_t ci_qcache_insert(ci_channel_t       *channel,
                                 const ci_timeval_t *now,
                                 const ci_query_t   *query,
                                 ci_dns_record_t    *dnsrec);
ci_status_t ci_qcache_fetch(ci_channel_t           *channel,
                                const ci_timeval_t     *now,
                                const ci_dns_record_t  *dnsrec,
                                const ci_dns_record_t **dnsrec_resp);

void   ci_metrics_record(const ci_query_t *query, ci_server_t *server,
                           ci_status_t status, const ci_dns_record_t *dnsrec);
size_t ci_metrics_server_timeout(const ci_server_t  *server,
                                   const ci_timeval_t *now);

ci_status_t ci_cookie_apply(ci_dns_record_t *dnsrec, ci_conn_t *conn,
                                const ci_timeval_t *now);
ci_status_t ci_cookie_validate(ci_query_t            *query,
                                   const ci_dns_record_t *dnsresp,
                                   ci_conn_t             *conn,
                                   const ci_timeval_t    *now);

ci_status_t ci_channel_threading_init(ci_channel_t *channel);
void          ci_channel_threading_destroy(ci_channel_t *channel);
void          ci_channel_lock(const ci_channel_t *channel);
void          ci_channel_unlock(const ci_channel_t *channel);

struct ci_event_thread;
typedef struct ci_event_thread ci_event_thread_t;

void          ci_event_thread_destroy(ci_channel_t *channel);
ci_status_t ci_event_thread_init(ci_channel_t *channel);


#ifdef _WIN32
#  define HOSTENT_ADDRTYPE_TYPE short
#  define HOSTENT_LENGTH_TYPE   short
#else
#  define HOSTENT_ADDRTYPE_TYPE int
#  define HOSTENT_LENGTH_TYPE   int
#endif

#endif /* __CI_PRIVATE_H */
