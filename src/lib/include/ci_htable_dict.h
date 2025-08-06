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
#ifndef __CI__HTABLE_DICT_H
#define __CI__HTABLE_DICT_H

/*! \addtogroup ci_htable_dict HashTable with case-insensitive string Key and
 *  string value
 *
 * This data structure wraps the base ci_htable data structure in order to
 * split the key and value data types as string and string, respectively.
 *
 * Average time complexity:
 *  - Insert: O(1)
 *  - Search: O(1)
 *  - Delete: O(1)
 *
 * @{
 */

struct ci_htable_dict;

/*! Opaque data type for string key, string value hash table
 * implementation */
typedef struct ci_htable_dict ci_htable_dict_t;

/*! Destroy hashtable
 *
 *  \param[in] htable  Initialized hashtable
 */
CI_EXTERN void ci_htable_dict_destroy(ci_htable_dict_t *htable);

/*! Create void pointer key, string value hash table
 *
 */
CI_EXTERN ci_htable_dict_t *ci_htable_dict_create(void);

/*! Insert key/value into hash table
 *
 *  \param[in] htable Initialized hash table
 *  \param[in] key    key to associate with value
 *  \param[in] val    value to store (duplicates).
 *  \return CI_TRUE on success, CI_FALSE on failure or out of memory
 */
CI_EXTERN ci_bool_t ci_htable_dict_insert(ci_htable_dict_t *htable,
                                                 const char         *key,
                                                 const char         *val);

/*! Retrieve value from hashtable based on key
 *
 *  \param[in]  htable  Initialized hash table
 *  \param[in]  key     key to use to search
 *  \param[out] val     Optional.  Pointer to store value.
 *  \return CI_TRUE on success, CI_FALSE on failure
 */
CI_EXTERN ci_bool_t ci_htable_dict_get(const ci_htable_dict_t *htable,
                                              const char               *key,
                                              const char              **val);

/*! Retrieve value from hashtable directly as return value.  Caveat to this
 *  function over ci_htable_dict_get() is that if a NULL value is stored
 *  you cannot determine if the key is not found or the value is NULL.
 *
 *  \param[in] htable  Initialized hash table
 *  \param[in] key     key to use to search
 *  \return value associated with key in hashtable or NULL
 */
CI_EXTERN const char *
  ci_htable_dict_get_direct(const ci_htable_dict_t *htable,
                              const char               *key);

/*! Remove a value from the hashtable by key
 *
 *  \param[in] htable  Initialized hash table
 *  \param[in] key     key to use to search
 *  \return CI_TRUE if found, CI_FALSE if not
 */
CI_EXTERN ci_bool_t ci_htable_dict_remove(ci_htable_dict_t *htable,
                                                 const char         *key);

/*! Retrieve the number of keys stored in the hash table
 *
 *  \param[in] htable  Initialized hash table
 *  \return count
 */
CI_EXTERN size_t ci_htable_dict_num_keys(const ci_htable_dict_t *htable);

/*! Retrieve an array of keys from the hashtable.
 *
 *  \param[in]  htable   Initialized hashtable
 *  \param[out] num      Count of returned keys
 *  \return Array of keys in the hashtable. Must be free'd with
 *          ci_free_array(strs, num, ci_free);
 */
CI_EXTERN char **ci_htable_dict_keys(const ci_htable_dict_t *htable,
                                          size_t                   *num);


/*! @} */

#endif /* __CI__HTABLE_DICT_H */
