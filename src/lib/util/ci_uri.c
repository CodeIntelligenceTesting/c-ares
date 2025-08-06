/* MIT License
 *
 * Copyright (c) 2024 Brad house
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
#include "ci_uri.h"
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

struct ci_uri {
  char                scheme[16];
  char               *username;
  char               *password;
  unsigned short      port;
  char                host[256];
  char               *path;
  ci_htable_dict_t *query;
  char               *fragment;
};

/* RFC3986 character set notes:
 *    gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
 *    sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
 *                / "*" / "+" / "," / ";" / "="
 *    reserved    = gen-delims / sub-delims
 *    unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
 *    scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 *    authority   = [ userinfo "@" ] host [ ":" port ]
 *    userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )
 *    NOTE: Use of the format "user:password" in the userinfo field is
 *          deprecated.  Applications should not render as clear text any data
 *          after the first colon (":") character found within a userinfo
 *          subcomponent unless the data after the colon is the empty string
 *           (indicating no password).
 *    pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
 *    query       = *( pchar / "/" / "?" )
 *    fragment    = *( pchar / "/" / "?" )
 *
 *   NOTE: Due to ambiguity, "+" in a query must be percent-encoded, as old
 *         URLs used that for spaces.
 */


static ci_bool_t ci_uri_chis_subdelim(char x)
{
  switch (x) {
    case '!':
      return CI_TRUE;
    case '$':
      return CI_TRUE;
    case '&':
      return CI_TRUE;
    case '\'':
      return CI_TRUE;
    case '(':
      return CI_TRUE;
    case ')':
      return CI_TRUE;
    case '*':
      return CI_TRUE;
    case '+':
      return CI_TRUE;
    case ',':
      return CI_TRUE;
    case ';':
      return CI_TRUE;
    case '=':
      return CI_TRUE;
    default:
      break;
  }
  return CI_FALSE;
}

/* These don't actually appear to be referenced in any logic */
#if 0
static ci_bool_t ci_uri_chis_gendelim(char x)
{
  switch (x) {
    case ':':
      return CI_TRUE;
    case '/':
      return CI_TRUE;
    case '?':
      return CI_TRUE;
    case '#':
      return CI_TRUE;
    case '[':
      return CI_TRUE;
    case ']':
      return CI_TRUE;
    case '@':
      return CI_TRUE;
    default:
      break;
  }
  return CI_FALSE;
}


static ci_bool_t ci_uri_chis_reserved(char x)
{
  return ci_uri_chis_gendelim(x) || ci_uri_chis_subdelim(x);
}
#endif

static ci_bool_t ci_uri_chis_unreserved(char x)
{
  switch (x) {
    case '-':
      return CI_TRUE;
    case '.':
      return CI_TRUE;
    case '_':
      return CI_TRUE;
    case '~':
      return CI_TRUE;
    default:
      break;
  }
  return ci_isalpha(x) || ci_isdigit(x);
}

static ci_bool_t ci_uri_chis_scheme(char x)
{
  switch (x) {
    case '+':
      return CI_TRUE;
    case '-':
      return CI_TRUE;
    case '.':
      return CI_TRUE;
    default:
      break;
  }
  return ci_isalpha(x) || ci_isdigit(x);
}

static ci_bool_t ci_uri_chis_authority(char x)
{
  /* This one here isn't well defined.  We are going to include the valid
   * characters of the subfields plus known delimiters */
  return ci_uri_chis_unreserved(x) || ci_uri_chis_subdelim(x) || x == '%' ||
         x == '[' || x == ']' || x == '@' || x == ':';
}

static ci_bool_t ci_uri_chis_userinfo(char x)
{
  /* NOTE: we don't include ':' here since we are using that as our
   *       username/password delimiter */
  return ci_uri_chis_unreserved(x) || ci_uri_chis_subdelim(x);
}

static ci_bool_t ci_uri_chis_path(char x)
{
  switch (x) {
    case ':':
      return CI_TRUE;
    case '@':
      return CI_TRUE;
    /* '/' isn't in the spec as a path character since its technically a
     * delimiter but we're not splitting on '/' so we accept it as valid */
    case '/':
      return CI_TRUE;
    default:
      break;
  }
  return ci_uri_chis_unreserved(x) || ci_uri_chis_subdelim(x);
}

static ci_bool_t ci_uri_chis_path_enc(char x)
{
  return ci_uri_chis_path(x) || x == '%';
}

static ci_bool_t ci_uri_chis_query(char x)
{
  switch (x) {
    case '/':
      return CI_TRUE;
    case '?':
      return CI_TRUE;
    default:
      break;
  }

  /* Exclude & and = used as delimiters, they're valid characters in the
   * set, just not for the individual pieces */
  return ci_uri_chis_path(x) && x != '&' && x != '=';
}

static ci_bool_t ci_uri_chis_query_enc(char x)
{
  return ci_uri_chis_query(x) || x == '%';
}

static ci_bool_t ci_uri_chis_fragment(char x)
{
  switch (x) {
    case '/':
      return CI_TRUE;
    case '?':
      return CI_TRUE;
    default:
      break;
  }
  return ci_uri_chis_path(x);
}

static ci_bool_t ci_uri_chis_fragment_enc(char x)
{
  return ci_uri_chis_fragment(x) || x == '%';
}

ci_uri_t *ci_uri_create(void)
{
  ci_uri_t *uri = ci_malloc_zero(sizeof(*uri));

  if (uri == NULL) {
    return NULL;
  }

  uri->query = ci_htable_dict_create();
  if (uri->query == NULL) {
    ci_free(uri);
    return NULL;
  }

  return uri;
}

void ci_uri_destroy(ci_uri_t *uri)
{
  if (uri == NULL) {
    return;
  }

  ci_free(uri->username);
  ci_free(uri->password);
  ci_free(uri->path);
  ci_free(uri->fragment);
  ci_htable_dict_destroy(uri->query);
  ci_free(uri);
}

static ci_bool_t ci_uri_scheme_is_valid(const char *uri)
{
  size_t i;

  if (ci_strlen(uri) == 0) {
    return CI_FALSE;
  }

  if (!ci_isalpha(*uri)) {
    return CI_FALSE;
  }

  for (i = 0; uri[i] != 0; i++) {
    if (!ci_uri_chis_scheme(uri[i])) {
      return CI_FALSE;
    }
  }
  return CI_TRUE;
}

static ci_bool_t ci_uri_str_isvalid(const char *str, size_t max_len,
                                        ci_bool_t (*ischr)(char))
{
  size_t i;

  if (str == NULL) {
    return CI_FALSE;
  }

  for (i = 0; i != max_len && str[i] != 0; i++) {
    if (!ischr(str[i])) {
      return CI_FALSE;
    }
  }
  return CI_TRUE;
}

ci_status_t ci_uri_set_scheme(ci_uri_t *uri, const char *scheme)
{
  if (uri == NULL) {
    return CI_EFORMERR;
  }

  if (!ci_uri_scheme_is_valid(scheme)) {
    return CI_EBADSTR;
  }

  ci_strcpy(uri->scheme, scheme, sizeof(uri->scheme));
  ci_str_lower(uri->scheme);

  return CI_SUCCESS;
}

const char *ci_uri_get_scheme(const ci_uri_t *uri)
{
  if (uri == NULL) {
    return NULL;
  }

  return uri->scheme;
}

static ci_status_t ci_uri_set_username_own(ci_uri_t *uri, char *username)
{
  if (uri == NULL) {
    return CI_EFORMERR;
  }

  if (username != NULL && (!ci_str_isprint(username, ci_strlen(username)) ||
                           ci_strlen(username) == 0)) {
    return CI_EBADSTR;
  }


  ci_free(uri->username);
  uri->username = username;
  return CI_SUCCESS;
}

ci_status_t ci_uri_set_username(ci_uri_t *uri, const char *username)
{
  ci_status_t status;
  char         *temp = NULL;

  if (uri == NULL) {
    return CI_EFORMERR;
  }

  if (username != NULL) {
    temp = ci_strdup(username);
    if (temp == NULL) {
      return CI_ENOMEM;
    }
  }

  status = ci_uri_set_username_own(uri, temp);
  if (status != CI_SUCCESS) {
    ci_free(temp);
  }

  return status;
}

const char *ci_uri_get_username(const ci_uri_t *uri)
{
  if (uri == NULL) {
    return NULL;
  }

  return uri->username;
}

static ci_status_t ci_uri_set_password_own(ci_uri_t *uri, char *password)
{
  if (uri == NULL) {
    return CI_EFORMERR;
  }

  if (password != NULL && !ci_str_isprint(password, ci_strlen(password))) {
    return CI_EBADSTR;
  }

  ci_free(uri->password);
  uri->password = password;
  return CI_SUCCESS;
}

ci_status_t ci_uri_set_password(ci_uri_t *uri, const char *password)
{
  ci_status_t status;
  char         *temp = NULL;

  if (uri == NULL) {
    return CI_EFORMERR;
  }

  if (password != NULL) {
    temp = ci_strdup(password);
    if (temp == NULL) {
      return CI_ENOMEM;
    }
  }

  status = ci_uri_set_password_own(uri, temp);
  if (status != CI_SUCCESS) {
    ci_free(temp);
  }

  return status;
}

const char *ci_uri_get_password(const ci_uri_t *uri)
{
  if (uri == NULL) {
    return NULL;
  }

  return uri->password;
}

ci_status_t ci_uri_set_host(ci_uri_t *uri, const char *host)
{
  struct ci_addr addr;
  size_t           addrlen;
  char             hoststr[256];
  char            *ll_scope;

  if (uri == NULL || ci_strlen(host) == 0 ||
      ci_strlen(host) >= sizeof(hoststr)) {
    return CI_EFORMERR;
  }

  ci_strcpy(hoststr, host, sizeof(hoststr));

  /* Look for '%' which could be a link-local scope for ipv6 addresses and
   * parse it off */
  ll_scope = strchr(hoststr, '%');
  if (ll_scope != NULL) {
    *ll_scope = 0;
    ll_scope++;
    if (!ci_str_isalnum(ll_scope)) {
      return CI_EBADNAME;
    }
  }

  /* If its an IP address, normalize it */
  memset(&addr, 0, sizeof(addr));
  addr.family = AF_UNSPEC;
  if (ci_dns_pton(hoststr, &addr, &addrlen) != NULL) {
    char ipaddr[INET6_ADDRSTRLEN];
    ci_inet_ntop(addr.family, &addr.addr, ipaddr, sizeof(ipaddr));
    /* Only IPv6 is allowed to have a scope */
    if (ll_scope != NULL && addr.family != AF_INET6) {
      return CI_EBADNAME;
    }

    if (ll_scope != NULL) {
      snprintf(uri->host, sizeof(uri->host), "%s%%%s", ipaddr, ll_scope);
    } else {
      ci_strcpy(uri->host, ipaddr, sizeof(uri->host));
    }
    return CI_SUCCESS;
  }

  /* If its a hostname, make sure its a valid charset */
  if (!ci_is_hostname(host)) {
    return CI_EBADNAME;
  }

  ci_strcpy(uri->host, host, sizeof(uri->host));
  return CI_SUCCESS;
}

const char *ci_uri_get_host(const ci_uri_t *uri)
{
  if (uri == NULL) {
    return NULL;
  }

  return uri->host;
}

ci_status_t ci_uri_set_port(ci_uri_t *uri, unsigned short port)
{
  if (uri == NULL) {
    return CI_EFORMERR;
  }
  uri->port = port;
  return CI_SUCCESS;
}

unsigned short ci_uri_get_port(const ci_uri_t *uri)
{
  if (uri == NULL) {
    return 0;
  }
  return uri->port;
}

/* URI spec says path normalization is a requirement */
static char *ci_uri_path_normalize(const char *path)
{
  ci_status_t status;
  ci_array_t *arr     = NULL;
  ci_buf_t   *outpath = NULL;
  ci_buf_t   *inpath  = NULL;
  ci_ssize_t  i;
  size_t        j;
  size_t        len;

  inpath =
    ci_buf_create_const((const unsigned char *)path, ci_strlen(path));
  if (inpath == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  outpath = ci_buf_create();
  if (outpath == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  status = ci_buf_split_str_array(inpath, (const unsigned char *)"/", 1,
                                    CI_BUF_SPLIT_TRIM, 0, &arr);
  if (status != CI_SUCCESS) {
    return NULL;
  }

  for (i = 0; i < (ci_ssize_t)ci_array_len(arr); i++) {
    const char **strptr = ci_array_at(arr, (size_t)i);
    const char  *str    = *strptr;

    if (ci_streq(str, ".")) {
      ci_array_remove_at(arr, (size_t)i);
      i--;
    } else if (ci_streq(str, "..")) {
      if (i != 0) {
        ci_array_remove_at(arr, (size_t)i - 1);
        i--;
      }
      ci_array_remove_at(arr, (size_t)i);
      i--;
    }
  }

  status = ci_buf_append_byte(outpath, '/');
  if (status != CI_SUCCESS) {
    goto done;
  }

  len = ci_array_len(arr);
  for (j = 0; j < len; j++) {
    const char **strptr = ci_array_at(arr, j);
    const char  *str    = *strptr;
    status              = ci_buf_append_str(outpath, str);
    if (status != CI_SUCCESS) {
      goto done;
    }

    /* Path separator, but on the last entry, we need to check if it was
     * originally terminated or not because they have different meanings */
    if (j != len - 1 || path[ci_strlen(path) - 1] == '/') {
      status = ci_buf_append_byte(outpath, '/');
      if (status != CI_SUCCESS) {
        goto done;
      }
    }
  }

done:
  ci_array_destroy(arr);
  ci_buf_destroy(inpath);
  if (status != CI_SUCCESS) {
    ci_buf_destroy(outpath);
    return NULL;
  }

  return ci_buf_finish_str(outpath, NULL);
}

ci_status_t ci_uri_set_path(ci_uri_t *uri, const char *path)
{
  char *temp = NULL;

  if (uri == NULL) {
    return CI_EFORMERR;
  }

  if (path != NULL && !ci_str_isprint(path, ci_strlen(path))) {
    return CI_EBADSTR;
  }

  if (path != NULL) {
    temp = ci_uri_path_normalize(path);
    if (temp == NULL) {
      return CI_ENOMEM;
    }
  }

  ci_free(uri->path);
  uri->path = temp;

  return CI_SUCCESS;
}

const char *ci_uri_get_path(const ci_uri_t *uri)
{
  if (uri == NULL) {
    return NULL;
  }

  return uri->path;
}

ci_status_t ci_uri_set_query_key(ci_uri_t *uri, const char *key,
                                     const char *val)
{
  if (uri == NULL || key == NULL || *key == 0) {
    return CI_EFORMERR;
  }

  if (!ci_str_isprint(key, ci_strlen(key)) ||
      (val != NULL && !ci_str_isprint(val, ci_strlen(val)))) {
    return CI_EBADSTR;
  }

  if (!ci_htable_dict_insert(uri->query, key, val)) {
    return CI_ENOMEM;
  }
  return CI_SUCCESS;
}

ci_status_t ci_uri_del_query_key(ci_uri_t *uri, const char *key)
{
  if (uri == NULL || key == NULL || *key == 0 ||
      !ci_str_isprint(key, ci_strlen(key))) {
    return CI_EFORMERR;
  }

  if (!ci_htable_dict_remove(uri->query, key)) {
    return CI_ENOTFOUND;
  }

  return CI_SUCCESS;
}

const char *ci_uri_get_query_key(const ci_uri_t *uri, const char *key)
{
  if (uri == NULL || key == NULL || *key == 0 ||
      !ci_str_isprint(key, ci_strlen(key))) {
    return NULL;
  }

  return ci_htable_dict_get_direct(uri->query, key);
}

char **ci_uri_get_query_keys(const ci_uri_t *uri, size_t *num)
{
  if (uri == NULL || num == NULL) {
    return NULL;
  }

  return ci_htable_dict_keys(uri->query, num);
}

static ci_status_t ci_uri_set_fragment_own(ci_uri_t *uri, char *fragment)
{
  if (uri == NULL) {
    return CI_EFORMERR;
  }

  if (fragment != NULL && !ci_str_isprint(fragment, ci_strlen(fragment))) {
    return CI_EBADSTR;
  }

  ci_free(uri->fragment);
  uri->fragment = fragment;
  return CI_SUCCESS;
}

ci_status_t ci_uri_set_fragment(ci_uri_t *uri, const char *fragment)
{
  ci_status_t status;
  char         *temp = NULL;

  if (uri == NULL) {
    return CI_EFORMERR;
  }

  if (fragment != NULL) {
    temp = ci_strdup(fragment);
    if (temp == NULL) {
      return CI_ENOMEM;
    }
  }

  status = ci_uri_set_fragment_own(uri, temp);
  if (status != CI_SUCCESS) {
    ci_free(temp);
  }

  return status;
}

const char *ci_uri_get_fragment(const ci_uri_t *uri)
{
  if (uri == NULL) {
    return NULL;
  }
  return uri->fragment;
}

static ci_status_t ci_uri_encode_buf(ci_buf_t *buf, const char *str,
                                         ci_bool_t (*ischr)(char))
{
  size_t i;

  if (buf == NULL || str == NULL) {
    return CI_EFORMERR;
  }

  for (i = 0; str[i] != 0; i++) {
    if (ischr(str[i])) {
      if (ci_buf_append_byte(buf, (unsigned char)str[i]) != CI_SUCCESS) {
        return CI_ENOMEM;
      }
    } else {
      if (ci_buf_append_byte(buf, '%') != CI_SUCCESS) {
        return CI_ENOMEM;
      }
      if (ci_buf_append_num_hex(buf, (size_t)str[i], 2) != CI_SUCCESS) {
        return CI_ENOMEM;
      }
    }
  }
  return CI_SUCCESS;
}

static ci_status_t ci_uri_write_scheme(const ci_uri_t *uri,
                                           ci_buf_t       *buf)
{
  ci_status_t status;

  status = ci_buf_append_str(buf, uri->scheme);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_buf_append_str(buf, "://");

  return status;
}

static ci_status_t ci_uri_write_authority(const ci_uri_t *uri,
                                              ci_buf_t       *buf)
{
  ci_status_t status;
  ci_bool_t   is_ipv6 = CI_FALSE;

  if (ci_strlen(uri->username)) {
    status = ci_uri_encode_buf(buf, uri->username, ci_uri_chis_userinfo);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  if (ci_strlen(uri->password)) {
    status = ci_buf_append_byte(buf, ':');
    if (status != CI_SUCCESS) {
      return status;
    }

    status = ci_uri_encode_buf(buf, uri->password, ci_uri_chis_userinfo);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  if (ci_strlen(uri->username) || ci_strlen(uri->password)) {
    status = ci_buf_append_byte(buf, '@');
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  /* We need to write ipv6 addresses with [ ] */
  if (strchr(uri->host, '%') != NULL) {
    /* If we have a % in the name, it must be ipv6 link local scope, so we
     * don't need to check anything else */
    is_ipv6 = CI_TRUE;
  } else {
    /* Parse the host to see if it is an ipv6 address */
    struct ci_addr addr;
    size_t           addrlen;
    memset(&addr, 0, sizeof(addr));
    addr.family = AF_INET6;
    if (ci_dns_pton(uri->host, &addr, &addrlen) != NULL) {
      is_ipv6 = CI_TRUE;
    }
  }

  if (is_ipv6) {
    status = ci_buf_append_byte(buf, '[');
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  status = ci_buf_append_str(buf, uri->host);
  if (status != CI_SUCCESS) {
    return status;
  }

  if (is_ipv6) {
    status = ci_buf_append_byte(buf, ']');
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  if (uri->port > 0) {
    status = ci_buf_append_byte(buf, ':');
    if (status != CI_SUCCESS) {
      return status;
    }
    status = ci_buf_append_num_dec(buf, uri->port, 0);
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  return status;
}

static ci_status_t ci_uri_write_path(const ci_uri_t *uri, ci_buf_t *buf)
{
  ci_status_t status;

  if (ci_strlen(uri->path) == 0) {
    return CI_SUCCESS;
  }

  if (*uri->path != '/') {
    status = ci_buf_append_byte(buf, '/');
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  status = ci_uri_encode_buf(buf, uri->path, ci_uri_chis_path);
  if (status != CI_SUCCESS) {
    return status;
  }

  return CI_SUCCESS;
}

static ci_status_t ci_uri_write_query(const ci_uri_t *uri,
                                          ci_buf_t       *buf)
{
  ci_status_t status;
  char        **keys;
  size_t        num_keys = 0;
  size_t        i;

  if (ci_htable_dict_num_keys(uri->query) == 0) {
    return CI_SUCCESS;
  }

  keys = ci_uri_get_query_keys(uri, &num_keys);
  if (keys == NULL || num_keys == 0) {
    return CI_ENOMEM;
  }

  status = ci_buf_append_byte(buf, '?');
  if (status != CI_SUCCESS) {
    goto done;
  }

  for (i = 0; i < num_keys; i++) {
    const char *val;

    if (i != 0) {
      status = ci_buf_append_byte(buf, '&');
      if (status != CI_SUCCESS) {
        goto done;
      }
    }

    status = ci_uri_encode_buf(buf, keys[i], ci_uri_chis_query);
    if (status != CI_SUCCESS) {
      goto done;
    }

    val = ci_uri_get_query_key(uri, keys[i]);
    if (val != NULL) {
      status = ci_buf_append_byte(buf, '=');
      if (status != CI_SUCCESS) {
        goto done;
      }

      status = ci_uri_encode_buf(buf, val, ci_uri_chis_query);
      if (status != CI_SUCCESS) {
        goto done;
      }
    }
  }

done:
  ci_free_array(keys, num_keys, ci_free);
  return status;
}

static ci_status_t ci_uri_write_fragment(const ci_uri_t *uri,
                                             ci_buf_t       *buf)
{
  ci_status_t status;

  if (!ci_strlen(uri->fragment)) {
    return CI_SUCCESS;
  }

  status = ci_buf_append_byte(buf, '#');
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_uri_encode_buf(buf, uri->fragment, ci_uri_chis_fragment);
  if (status != CI_SUCCESS) {
    return status;
  }

  return CI_SUCCESS;
}

ci_status_t ci_uri_write_buf(const ci_uri_t *uri, ci_buf_t *buf)
{
  ci_status_t status;
  size_t        orig_len;

  if (uri == NULL || buf == NULL) {
    return CI_EFORMERR;
  }

  if (ci_strlen(uri->scheme) == 0 || ci_strlen(uri->host) == 0) {
    return CI_ENODATA;
  }

  orig_len = ci_buf_len(buf);

  status = ci_uri_write_scheme(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_write_authority(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_write_path(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_write_query(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_write_fragment(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

done:
  if (status != CI_SUCCESS) {
    ci_buf_set_length(buf, orig_len);
  }
  return status;
}

ci_status_t ci_uri_write(char **out, const ci_uri_t *uri)
{
  ci_buf_t   *buf;
  ci_status_t status;

  if (out == NULL || uri == NULL) {
    return CI_EFORMERR;
  }

  *out = NULL;

  buf = ci_buf_create();
  if (buf == NULL) {
    return CI_ENOMEM;
  }

  status = ci_uri_write_buf(uri, buf);
  if (status != CI_SUCCESS) {
    ci_buf_destroy(buf);
    return status;
  }

  *out = ci_buf_finish_str(buf, NULL);
  return CI_SUCCESS;
}

#define xdigit_val(x)     \
  ((x >= '0' && x <= '9') \
     ? (x - '0')          \
     : ((x >= 'A' && x <= 'F') ? (x - 'A' + 10) : (x - 'a' + 10)))

static ci_status_t ci_uri_decode_inplace(char *str, ci_bool_t is_query,
                                             ci_bool_t must_be_printable,
                                             size_t     *out_len)
{
  size_t i;
  size_t len = 0;

  for (i = 0; str[i] != 0; i++) {
    if (is_query && str[i] == '+') {
      str[len++] = ' ';
      continue;
    }

    if (str[i] != '%') {
      str[len++] = str[i];
      continue;
    }

    if (!ci_isxdigit(str[i + 1]) || !ci_isxdigit(str[i + 2])) {
      return CI_EBADSTR;
    }

    str[len] = (char)(xdigit_val(str[i + 1]) << 4 | xdigit_val(str[i + 2]));

    if (must_be_printable && !ci_isprint(str[len])) {
      return CI_EBADSTR;
    }

    len++;

    i += 2;
  }

  str[len] = 0;

  *out_len = len;
  return CI_SUCCESS;
}

static ci_status_t ci_uri_parse_scheme(ci_uri_t *uri, ci_buf_t *buf)
{
  ci_status_t status;
  size_t        bytes;
  char          scheme[sizeof(uri->scheme)];

  ci_buf_tag(buf);

  bytes =
    ci_buf_consume_until_seq(buf, (const unsigned char *)"://", 3, CI_TRUE);
  if (bytes == SIZE_MAX || bytes > sizeof(uri->scheme)) {
    return CI_EBADSTR;
  }

  status = ci_buf_tag_fetch_string(buf, scheme, sizeof(scheme));
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_uri_set_scheme(uri, scheme);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Consume :// */
  ci_buf_consume(buf, 3);

  return CI_SUCCESS;
}

static ci_status_t ci_uri_parse_userinfo(ci_uri_t *uri, ci_buf_t *buf)
{
  size_t        userinfo_len;
  size_t        username_len;
  ci_bool_t   has_password = CI_FALSE;
  char         *temp         = NULL;
  ci_status_t status;
  size_t        len;

  ci_buf_tag(buf);

  /* Search for @, if its not found, return */
  userinfo_len = ci_buf_consume_until_charset(buf, (const unsigned char *)"@",
                                                1, CI_TRUE);

  if (userinfo_len == SIZE_MAX) {
    return CI_SUCCESS;
  }

  /* Rollback since now we know there really is userinfo */
  ci_buf_tag_rollback(buf);

  /* Search for ':', if it isn't found or its past the '@' then we only have
   * a username and no password */
  ci_buf_tag(buf);
  username_len = ci_buf_consume_until_charset(buf, (const unsigned char *)":",
                                                1, CI_TRUE);
  if (username_len < userinfo_len) {
    has_password = CI_TRUE;
    status       = ci_buf_tag_fetch_strdup(buf, &temp);
    if (status != CI_SUCCESS) {
      goto done;
    }

    status = ci_uri_decode_inplace(temp, CI_FALSE, CI_TRUE, &len);
    if (status != CI_SUCCESS) {
      goto done;
    }

    status = ci_uri_set_username_own(uri, temp);
    if (status != CI_SUCCESS) {
      goto done;
    }
    temp = NULL;

    /* Consume : */
    ci_buf_consume(buf, 1);
  }

  ci_buf_tag(buf);
  ci_buf_consume_until_charset(buf, (const unsigned char *)"@", 1, CI_TRUE);
  status = ci_buf_tag_fetch_strdup(buf, &temp);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_decode_inplace(temp, CI_FALSE, CI_TRUE, &len);
  if (status != CI_SUCCESS) {
    goto done;
  }

  if (has_password) {
    status = ci_uri_set_password_own(uri, temp);
  } else {
    status = ci_uri_set_username_own(uri, temp);
  }
  if (status != CI_SUCCESS) {
    goto done;
  }
  temp = NULL;

  /* Consume @ */
  ci_buf_consume(buf, 1);

done:
  ci_free(temp);
  return status;
}

static ci_status_t ci_uri_parse_hostport(ci_uri_t *uri, ci_buf_t *buf)
{
  unsigned char b;
  char          host[256];
  char          port[6];
  size_t        len;
  ci_status_t status;

  status = ci_buf_peek_byte(buf, &b);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Bracketed syntax for ipv6 addresses */
  if (b == '[') {
    ci_buf_consume(buf, 1);
    ci_buf_tag(buf);
    len = ci_buf_consume_until_charset(buf, (const unsigned char *)"]", 1,
                                         CI_TRUE);
    if (len == SIZE_MAX) {
      return CI_EBADSTR;
    }

    status = ci_buf_tag_fetch_string(buf, host, sizeof(host));
    if (status != CI_SUCCESS) {
      return status;
    }
    /* Consume ']' */
    ci_buf_consume(buf, 1);
  } else {
    /* Either ipv4 or hostname */
    ci_buf_tag(buf);
    ci_buf_consume_until_charset(buf, (const unsigned char *)":", 1,
                                   CI_FALSE);

    status = ci_buf_tag_fetch_string(buf, host, sizeof(host));
    if (status != CI_SUCCESS) {
      return status;
    }
  }

  status = ci_uri_set_host(uri, host);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* No port if nothing left to consume */
  if (!ci_buf_len(buf)) {
    return status;
  }

  status = ci_buf_peek_byte(buf, &b);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Only valid extra character at this point is ':' */
  if (b != ':') {
    return CI_EBADSTR;
  }
  ci_buf_consume(buf, 1);

  len = ci_buf_len(buf);
  if (len == 0 || len > sizeof(port) - 1) {
    return CI_EBADSTR;
  }

  status = ci_buf_fetch_bytes(buf, (unsigned char *)port, len);
  if (status != CI_SUCCESS) {
    return status;
  }
  port[len] = 0;

  if (!ci_str_isnum(port)) {
    return CI_EBADSTR;
  }

  status = ci_uri_set_port(uri, (unsigned short)atoi(port));
  if (status != CI_SUCCESS) {
    return status;
  }

  return CI_SUCCESS;
}

static ci_status_t ci_uri_parse_authority(ci_uri_t *uri, ci_buf_t *buf)
{
  ci_status_t        status;
  size_t               bytes;
  ci_buf_t          *auth = NULL;
  const unsigned char *ptr;
  size_t               ptr_len;

  ci_buf_tag(buf);

  bytes = ci_buf_consume_until_charset(buf, (const unsigned char *)"/?#", 3,
                                         CI_FALSE);
  if (bytes == 0) {
    return CI_EBADSTR;
  }

  status = ci_buf_tag_fetch_constbuf(buf, &auth);
  if (status != CI_SUCCESS) {
    goto done;
  }

  ptr = ci_buf_peek(auth, &ptr_len);
  if (!ci_uri_str_isvalid((const char *)ptr, ptr_len,
                            ci_uri_chis_authority)) {
    status = CI_EBADSTR;
    goto done;
  }

  status = ci_uri_parse_userinfo(uri, auth);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_parse_hostport(uri, auth);
  if (status != CI_SUCCESS) {
    goto done;
  }

  /* NOTE: the /, ?, or # is still in the buffer at this point so it can
   *       be used to determine what parser should be called next */

done:
  ci_buf_destroy(auth);
  return status;
}

static ci_status_t ci_uri_parse_path(ci_uri_t *uri, ci_buf_t *buf)
{
  unsigned char b;
  char         *path = NULL;
  ci_status_t status;
  size_t        len;

  if (ci_buf_len(buf) == 0) {
    return CI_SUCCESS;
  }

  status = ci_buf_peek_byte(buf, &b);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Not a path, must be one of the others */
  if (b != '/') {
    return CI_SUCCESS;
  }

  ci_buf_tag(buf);
  ci_buf_consume_until_charset(buf, (const unsigned char *)"?#", 2,
                                 CI_FALSE);
  status = ci_buf_tag_fetch_strdup(buf, &path);
  if (status != CI_SUCCESS) {
    goto done;
  }

  if (!ci_uri_str_isvalid(path, SIZE_MAX, ci_uri_chis_path_enc)) {
    status = CI_EBADSTR;
    goto done;
  }

  status = ci_uri_decode_inplace(path, CI_FALSE, CI_TRUE, &len);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_set_path(uri, path);
  if (status != CI_SUCCESS) {
    goto done;
  }

done:
  ci_free(path);
  return status;
}

static ci_status_t ci_uri_parse_query_buf(ci_uri_t *uri, ci_buf_t *buf)
{
  ci_status_t status = CI_SUCCESS;
  char         *key    = NULL;
  char         *val    = NULL;

  while (ci_buf_len(buf) > 0) {
    unsigned char b = 0;
    size_t        len;

    ci_buf_tag(buf);

    /* Its valid to have only a key with no value, so we search for both
     * delims */
    len = ci_buf_consume_until_charset(buf, (const unsigned char *)"&=", 2,
                                         CI_FALSE);
    if (len == 0) {
      /* If we're here, we have a zero length key which is invalid */
      status = CI_EBADSTR;
      goto done;
    }

    if (ci_buf_len(buf) > 0) {
      /* Determine if we stopped on & or = */
      status = ci_buf_peek_byte(buf, &b);
      if (status != CI_SUCCESS) {
        goto done;
      }
    }

    status = ci_buf_tag_fetch_strdup(buf, &key);
    if (status != CI_SUCCESS) {
      goto done;
    }

    if (!ci_uri_str_isvalid(key, SIZE_MAX, ci_uri_chis_query_enc)) {
      status = CI_EBADSTR;
      goto done;
    }

    status = ci_uri_decode_inplace(key, CI_TRUE, CI_TRUE, &len);
    if (status != CI_SUCCESS) {
      goto done;
    }

    /* Fetch Value */
    if (b == '=') {
      /* Skip delimiter */
      ci_buf_consume(buf, 1);
      ci_buf_tag(buf);
      len = ci_buf_consume_until_charset(buf, (const unsigned char *)"&", 1,
                                           CI_FALSE);
      if (len > 0) {
        status = ci_buf_tag_fetch_strdup(buf, &val);
        if (status != CI_SUCCESS) {
          goto done;
        }

        if (!ci_uri_str_isvalid(val, SIZE_MAX, ci_uri_chis_query_enc)) {
          status = CI_EBADSTR;
          goto done;
        }

        status = ci_uri_decode_inplace(val, CI_TRUE, CI_TRUE, &len);
        if (status != CI_SUCCESS) {
          goto done;
        }
      }
    }

    if (b != 0) {
      /* Consume '&' */
      ci_buf_consume(buf, 1);
    }

    status = ci_uri_set_query_key(uri, key, val);
    if (status != CI_SUCCESS) {
      goto done;
    }

    ci_free(key);
    key = NULL;
    ci_free(val);
    val = NULL;
  }

done:
  ci_free(key);
  ci_free(val);
  return status;
}

static ci_status_t ci_uri_parse_query(ci_uri_t *uri, ci_buf_t *buf)
{
  unsigned char b;
  ci_status_t status;
  ci_buf_t   *query = NULL;
  size_t        len;

  if (ci_buf_len(buf) == 0) {
    return CI_SUCCESS;
  }

  status = ci_buf_peek_byte(buf, &b);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Not a query, must be one of the others */
  if (b != '?') {
    return CI_SUCCESS;
  }

  /* Only possible terminator is fragment indicator of '#' */
  ci_buf_consume(buf, 1);
  ci_buf_tag(buf);
  len = ci_buf_consume_until_charset(buf, (const unsigned char *)"#", 1,
                                       CI_FALSE);
  if (len == 0) {
    /* No data, return */
    return CI_SUCCESS;
  }

  status = ci_buf_tag_fetch_constbuf(buf, &query);
  if (status != CI_SUCCESS) {
    return status;
  }

  status = ci_uri_parse_query_buf(uri, query);
  ci_buf_destroy(query);

  return status;
}

static ci_status_t ci_uri_parse_fragment(ci_uri_t *uri, ci_buf_t *buf)
{
  unsigned char b;
  char         *fragment = NULL;
  ci_status_t status;
  size_t        len;

  if (ci_buf_len(buf) == 0) {
    return CI_SUCCESS;
  }

  status = ci_buf_peek_byte(buf, &b);
  if (status != CI_SUCCESS) {
    return status;
  }

  /* Not a fragment, must be one of the others */
  if (b != '#') {
    return CI_SUCCESS;
  }

  ci_buf_consume(buf, 1);

  if (ci_buf_len(buf) == 0) {
    return CI_SUCCESS;
  }

  /* Rest of the buffer is the fragment */
  status = ci_buf_fetch_str_dup(buf, ci_buf_len(buf), &fragment);
  if (status != CI_SUCCESS) {
    goto done;
  }

  if (!ci_uri_str_isvalid(fragment, SIZE_MAX, ci_uri_chis_fragment_enc)) {
    status = CI_EBADSTR;
    goto done;
  }

  status = ci_uri_decode_inplace(fragment, CI_FALSE, CI_TRUE, &len);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_set_fragment_own(uri, fragment);
  if (status != CI_SUCCESS) {
    goto done;
  }
  fragment = NULL;

done:
  ci_free(fragment);
  return status;
}

ci_status_t ci_uri_parse_buf(ci_uri_t **out, ci_buf_t *buf)
{
  ci_status_t status;
  ci_uri_t   *uri = NULL;
  size_t        orig_pos;

  if (out == NULL || buf == NULL) {
    return CI_EFORMERR;
  }

  *out = NULL;

  orig_pos = ci_buf_get_position(buf);

  uri = ci_uri_create();
  if (uri == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  status = ci_uri_parse_scheme(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_parse_authority(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_parse_path(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_parse_query(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_parse_fragment(uri, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

done:
  if (status != CI_SUCCESS) {
    ci_buf_set_position(buf, orig_pos);
    ci_uri_destroy(uri);
  } else {
    *out = uri;
  }
  return status;
}

ci_status_t ci_uri_parse(ci_uri_t **out, const char *str)
{
  ci_status_t status;
  ci_buf_t   *buf = NULL;

  if (out == NULL || str == NULL) {
    return CI_EFORMERR;
  }

  *out = NULL;

  buf = ci_buf_create();
  if (buf == NULL) {
    status = CI_ENOMEM;
    goto done;
  }

  status = ci_buf_append_str(buf, str);
  if (status != CI_SUCCESS) {
    goto done;
  }

  status = ci_uri_parse_buf(out, buf);
  if (status != CI_SUCCESS) {
    goto done;
  }

done:
  ci_buf_destroy(buf);

  return status;
}
