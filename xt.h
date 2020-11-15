/*
 * X Tables Control
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NET_XT_H
#define NET_XT_H  1

#include <stddef.h>

/* xt rule */

struct xt_rule *xt_rule_alloc (const char *domain);
void xt_rule_free (struct xt_rule *o);

/* xt core */

struct xt *xt_alloc (void);
void xt_free (struct xt *o);

const char *xt_error (struct xt *o);

int xt_is_chain (struct xt *o, const char *chain);

int xt_create_chain (struct xt *o, const char *chain, const char *policy);
int xt_delete_chain (struct xt *o, const char *chain);

int xt_set_policy   (struct xt *o, const char *chain, const char *policy);
int xt_flush_chain  (struct xt *o, const char *chain);

int xt_append_rule  (struct xt *o, const char *chain, struct xt_rule *r);

/* xt info */

typedef int (xt_cb) (struct xt *o, const char *chain, void *cookie);

int xt_iterate (struct xt *o, xt_cb *cb, void *cookie);

#endif  /* NET_XT_H */
