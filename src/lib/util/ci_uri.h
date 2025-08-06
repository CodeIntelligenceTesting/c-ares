/* MIT License
 *
 * Copyright (c) 2024 Brad House
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
#ifndef __CI_URI_H
#define __CI_URI_H

/*! \addtogroup ci_uri URI parser and writer implementation
 *
 * This is a fairly complete URI parser and writer implementation (RFC 3986) for
 * schemes which use the :// syntax. Does not currently support URIs without an
 * authority section, such as "mailto:person@example.com".
 *
 * Its implementation is overkill for our current needs to be able to express
 * DNS server configuration, but there was really no reason not to support
 * a greater subset of the specification.
 *
 * @{
 */


struct ci_uri;

/*! URI object */
typedef struct ci_uri ci_uri_t;

/*! Create a new URI object
 *
 *  \return new ci_uri_t, must be freed with ci_uri_destroy()
 */
ci_uri_t             *ci_uri_create(void);

/*! Destroy an initialized URI object
 *
 *  \param[in] uri  Initialized URI object
 */
void                    ci_uri_destroy(ci_uri_t *uri);

/*! Set the URI scheme.  Automatically lower-cases the scheme provided.
 *  Only allows Alpha, Digit, +, -, and . characters.  Maximum length is
 *  15 characters.  This is required to be set to write a URI.
 *
 *  \param[in] uri    Initialized URI object
 *  \param[in] scheme Scheme to set the object to use
 *  \return CI_SUCCESS on success
 */
ci_status_t  ci_uri_set_scheme(ci_uri_t *uri, const char *scheme);

/*! Retrieve the currently configured URI scheme.
 *
 *  \param[in] uri    Initialized URI object
 *  \return string containing URI scheme
 */
const char    *ci_uri_get_scheme(const ci_uri_t *uri);

/*! Set the username in the URI object
 *
 *  \param[in] uri      Initialized URI object
 *  \param[in] username Username to set. May be NULL to unset existing username.
 *  \return CI_SUCCESS on success
 */
ci_status_t  ci_uri_set_username(ci_uri_t *uri, const char *username);

/*! Retrieve the currently configured username.
 *
 *  \param[in] uri    Initialized URI object
 *  \return string containing username, maybe NULL if not set.
 */
const char    *ci_uri_get_username(const ci_uri_t *uri);

/*! Set the password in the URI object
 *
 *  \param[in] uri      Initialized URI object
 *  \param[in] password Password to set. May be NULL to unset existing password.
 *  \return CI_SUCCESS on success
 */
ci_status_t  ci_uri_set_password(ci_uri_t *uri, const char *password);

/*! Retrieve the currently configured password.
 *
 *  \param[in] uri    Initialized URI object
 *  \return string containing password, maybe NULL if not set.
 */
const char    *ci_uri_get_password(const ci_uri_t *uri);

/*! Set the host or ip address in the URI object.  This is required to be
 *  set to write a URI.  The character set is strictly validated.
 *
 *  \param[in] uri      Initialized URI object
 *  \param[in] host     IPv4, IPv6, or hostname to set.
 *  \return CI_SUCCESS on success
 */
ci_status_t  ci_uri_set_host(ci_uri_t *uri, const char *host);

/*! Retrieve the currently configured host (or ip address).  IPv6 addresses
 *  May include a link-local scope (e.g. fe80::b542:84df:1719:65e3%en0).
 *
 *  \param[in] uri    Initialized URI object
 *  \return string containing host, maybe NULL if not set.
 */
const char    *ci_uri_get_host(const ci_uri_t *uri);

/*! Set the port to use in the URI object.  A port value of 0 will omit
 *  the port from the URI when written, thus using the scheme's default.
 *
 *  \param[in] uri  Initialized URI object
 *  \param[in] port Port to set. Use 0 to unset.
 *  \return CI_SUCCESS on success
 */
ci_status_t  ci_uri_set_port(ci_uri_t *uri, unsigned short port);

/*! Retrieve the currently configured port
 *
 *  \param[in] uri    Initialized URI object
 *  \return port number, or 0 if not set.
 */
unsigned short ci_uri_get_port(const ci_uri_t *uri);

/*! Set the path in the URI object.  Unsupported characters will be URI-encoded
 *  when written.
 *
 *  \param[in] uri  Initialized URI object
 *  \param[in] path Path to set. May be NULL to unset existing path.
 *  \return CI_SUCCESS on success
 */
ci_status_t  ci_uri_set_path(ci_uri_t *uri, const char *path);

/*! Retrieves the path in the URI object.  If retrieved after parse, this
 *  value will be URI-decoded already.
 *
 *  \param[in] uri Initialized URI object
 *  \return path string, or NULL if not set.
 */
const char    *ci_uri_get_path(const ci_uri_t *uri);

/*! Set a new query key/value pair.  There is no set order for query keys
 *  when output in the URI, they will be emitted in a random order.  Keys are
 *  case-insensitive. Query keys and values will be automatically URI-encoded
 *  when written.
 *
 *  \param[in] uri  Initialized URI object
 *  \param[in] key  Query key to use, must be non-zero length.
 *  \param[in] val  Query value to use, may be NULL.
 *  \return CI_SUCCESS on success
 */
ci_status_t  ci_uri_set_query_key(ci_uri_t *uri, const char *key,
                                      const char *val);

/*! Delete a specific query key.
 *
 *  \param[in] uri Initialized URI object
 *  \param[in] key Key to delete.
 *  \return CI_SUCCESS if deleted, CI_ENOTFOUND if not found
 */
ci_status_t  ci_uri_del_query_key(ci_uri_t *uri, const char *key);

/*! Retrieve the value associted with a query key. Keys are case-insensitive.
 *
 *  \param[in] uri Initialized URI object
 *  \param[in] key Key to retrieve.
 *  \return string representing value, may be NULL if either not found or
 *          NULL value set.  There is currently no way to indicate the
 *          difference.
 */
const char    *ci_uri_get_query_key(const ci_uri_t *uri, const char *key);

/*! Retrieve a complete list of query keys.
 *
 *  \param[in]  uri Initialized URI object
 *  \param[out] num Number of keys.
 *  \return NULL on failure or no keys. Use
 *          ci_free_array(keys, num, ci_free) when done with array.
 */
char         **ci_uri_get_query_keys(const ci_uri_t *uri, size_t *num);

/*! Set the fragment in the URI object.  Unsupported characters will be
 *  URI-encoded when written.
 *
 *  \param[in] uri      Initialized URI object
 *  \param[in] fragment Fragment to set. May be NULL to unset existing fragment.
 *  \return CI_SUCCESS on success
 */
ci_status_t  ci_uri_set_fragment(ci_uri_t *uri, const char *fragment);

/*! Retrieves the fragment in the URI object.  If retrieved after parse, this
 *  value will be URI-decoded already.
 *
 *  \param[in] uri Initialized URI object
 *  \return fragment string, or NULL if not set.
 */
const char    *ci_uri_get_fragment(const ci_uri_t *uri);

/*! Parse the provided URI buffer into a new URI object.
 *
 *  \param[out] out  Returned new URI object. free with ci_uri_destroy().
 *  \param[in]  buf  Buffer object containing the URI
 *  \return CI_SUCCESS on successful parse. On failure the 'buf' object will
 *          be restored to its initial state in case another parser needs to
 *          be attempted.
 */
ci_status_t  ci_uri_parse_buf(ci_uri_t **out, ci_buf_t *buf);

/*! Parse the provided URI string into a new URI object.
 *
 *  \param[out] out  Returned new URI object. free with ci_uri_destroy().
 *  \param[in]  uri  URI string to parse
 *  \return CI_SUCCESS on successful parse
 */
ci_status_t  ci_uri_parse(ci_uri_t **out, const char *uri);

/*! Write URI object to a new string buffer.  Requires at least the scheme
 *  and host to be set for this to succeed.
 *
 *  \param[out] out  Returned new URI string. Free with ci_free().
 *  \param[in]  uri  Initialized URI object.
 *  \return CI_SUCCESS on successful write.
 */
ci_status_t  ci_uri_write(char **out, const ci_uri_t *uri);

/*! Write URI object to an existing ci_buf_t object.  Requires at least the
 *  scheme and host to be set for this to succeed.
 *
 *  \param[in]     uri  Initialized URI object.
 *  \param[in,out] buf  Destination buf object.
 *  \return CI_SUCCESS on successful write.
 */
ci_status_t  ci_uri_write_buf(const ci_uri_t *uri, ci_buf_t *buf);

/*! @} */

#endif /* __CI_URI_H */
