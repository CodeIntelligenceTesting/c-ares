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
#include "ci_llist.h"

struct ci_llist {
  ci_llist_node_t      *head;
  ci_llist_node_t      *tail;
  ci_llist_destructor_t destruct;
  size_t                  cnt;
};

struct ci_llist_node {
  void              *data;
  ci_llist_node_t *prev;
  ci_llist_node_t *next;
  ci_llist_t      *parent;
};

ci_llist_t *ci_llist_create(ci_llist_destructor_t destruct)
{
  ci_llist_t *list = ci_malloc_zero(sizeof(*list));

  if (list == NULL) {
    return NULL;
  }

  list->destruct = destruct;

  return list;
}

void ci_llist_replace_destructor(ci_llist_t           *list,
                                   ci_llist_destructor_t destruct)
{
  if (list == NULL) {
    return;
  }

  list->destruct = destruct;
}

typedef enum {
  CI__LLIST_INSERT_HEAD,
  CI__LLIST_INSERT_TAIL,
  CI__LLIST_INSERT_BEFORE
} ci_llist_insert_type_t;

static void ci_llist_attach_at(ci_llist_t            *list,
                                 ci_llist_insert_type_t type,
                                 ci_llist_node_t *at, ci_llist_node_t *node)
{
  if (list == NULL || node == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  node->parent = list;

  if (type == CI__LLIST_INSERT_BEFORE && (at == list->head || at == NULL)) {
    type = CI__LLIST_INSERT_HEAD;
  }

  switch (type) {
    case CI__LLIST_INSERT_HEAD:
      node->next = list->head;
      node->prev = NULL;
      if (list->head) {
        list->head->prev = node;
      }
      list->head = node;
      break;
    case CI__LLIST_INSERT_TAIL:
      node->next = NULL;
      node->prev = list->tail;
      if (list->tail) {
        list->tail->next = node;
      }
      list->tail = node;
      break;
    case CI__LLIST_INSERT_BEFORE:
      node->next = at;
      node->prev = at->prev;
      at->prev   = node;
      break;
  }
  if (list->tail == NULL) {
    list->tail = node;
  }
  if (list->head == NULL) {
    list->head = node;
  }

  list->cnt++;
}

static ci_llist_node_t *ci_llist_insert_at(ci_llist_t            *list,
                                               ci_llist_insert_type_t type,
                                               ci_llist_node_t *at, void *val)
{
  ci_llist_node_t *node = NULL;

  if (list == NULL || val == NULL) {
    return NULL; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  node = ci_malloc_zero(sizeof(*node));

  if (node == NULL) {
    return NULL;
  }

  node->data = val;
  ci_llist_attach_at(list, type, at, node);

  return node;
}

ci_llist_node_t *ci_llist_insert_first(ci_llist_t *list, void *val)
{
  return ci_llist_insert_at(list, CI__LLIST_INSERT_HEAD, NULL, val);
}

ci_llist_node_t *ci_llist_insert_last(ci_llist_t *list, void *val)
{
  return ci_llist_insert_at(list, CI__LLIST_INSERT_TAIL, NULL, val);
}

ci_llist_node_t *ci_llist_insert_before(ci_llist_node_t *node, void *val)
{
  if (node == NULL) {
    return NULL;
  }

  return ci_llist_insert_at(node->parent, CI__LLIST_INSERT_BEFORE, node,
                              val);
}

ci_llist_node_t *ci_llist_insert_after(ci_llist_node_t *node, void *val)
{
  if (node == NULL) {
    return NULL;
  }

  if (node->next == NULL) {
    return ci_llist_insert_last(node->parent, val);
  }

  return ci_llist_insert_at(node->parent, CI__LLIST_INSERT_BEFORE,
                              node->next, val);
}

ci_llist_node_t *ci_llist_node_first(ci_llist_t *list)
{
  if (list == NULL) {
    return NULL;
  }
  return list->head;
}

ci_llist_node_t *ci_llist_node_idx(ci_llist_t *list, size_t idx)
{
  ci_llist_node_t *node;
  size_t             cnt;

  if (list == NULL) {
    return NULL;
  }
  if (idx >= list->cnt) {
    return NULL;
  }

  node = list->head;
  for (cnt = 0; node != NULL && cnt < idx; cnt++) {
    node = node->next;
  }

  return node;
}

ci_llist_node_t *ci_llist_node_last(ci_llist_t *list)
{
  if (list == NULL) {
    return NULL;
  }
  return list->tail;
}

ci_llist_node_t *ci_llist_node_next(ci_llist_node_t *node)
{
  if (node == NULL) {
    return NULL;
  }
  return node->next;
}

ci_llist_node_t *ci_llist_node_prev(ci_llist_node_t *node)
{
  if (node == NULL) {
    return NULL;
  }
  return node->prev;
}

void *ci_llist_node_val(ci_llist_node_t *node)
{
  if (node == NULL) {
    return NULL;
  }

  return node->data;
}

size_t ci_llist_len(const ci_llist_t *list)
{
  if (list == NULL) {
    return 0;
  }
  return list->cnt;
}

ci_llist_t *ci_llist_node_parent(ci_llist_node_t *node)
{
  if (node == NULL) {
    return NULL;
  }
  return node->parent;
}

void *ci_llist_first_val(ci_llist_t *list)
{
  return ci_llist_node_val(ci_llist_node_first(list));
}

void *ci_llist_last_val(ci_llist_t *list)
{
  return ci_llist_node_val(ci_llist_node_last(list));
}

static void ci_llist_node_detach(ci_llist_node_t *node)
{
  ci_llist_t *list;

  if (node == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  list = node->parent;

  if (node->prev) {
    node->prev->next = node->next;
  }

  if (node->next) {
    node->next->prev = node->prev;
  }

  if (node == list->head) {
    list->head = node->next;
  }

  if (node == list->tail) {
    list->tail = node->prev;
  }

  node->parent = NULL;
  list->cnt--;
}

void *ci_llist_node_claim(ci_llist_node_t *node)
{
  void *val;

  if (node == NULL) {
    return NULL;
  }

  val = node->data;
  ci_llist_node_detach(node);
  ci_free(node);

  return val;
}

void ci_llist_node_destroy(ci_llist_node_t *node)
{
  ci_llist_destructor_t destruct;
  void                   *val;

  if (node == NULL) {
    return;
  }

  destruct = node->parent->destruct;

  val = ci_llist_node_claim(node);
  if (val != NULL && destruct != NULL) {
    destruct(val);
  }
}

void ci_llist_node_replace(ci_llist_node_t *node, void *val)
{
  ci_llist_destructor_t destruct;

  if (node == NULL) {
    return;
  }

  destruct = node->parent->destruct;
  if (destruct != NULL) {
    destruct(node->data);
  }

  node->data = val;
}

void ci_llist_clear(ci_llist_t *list)
{
  ci_llist_node_t *node;

  if (list == NULL) {
    return;
  }

  while ((node = ci_llist_node_first(list)) != NULL) {
    ci_llist_node_destroy(node);
  }
}

void ci_llist_destroy(ci_llist_t *list)
{
  if (list == NULL) {
    return;
  }
  ci_llist_clear(list);
  ci_free(list);
}

void ci_llist_node_mvparent_last(ci_llist_node_t *node,
                                   ci_llist_t      *new_parent)
{
  if (node == NULL || new_parent == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ci_llist_node_detach(node);
  ci_llist_attach_at(new_parent, CI__LLIST_INSERT_TAIL, NULL, node);
}

void ci_llist_node_mvparent_first(ci_llist_node_t *node,
                                    ci_llist_t      *new_parent)
{
  if (node == NULL || new_parent == NULL) {
    return; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ci_llist_node_detach(node);
  ci_llist_attach_at(new_parent, CI__LLIST_INSERT_HEAD, NULL, node);
}
