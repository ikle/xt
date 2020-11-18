/*
 * X Tables Control
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <data/hash.h>
#include <data/ht.h>
#include <data/seq.h>

#include "xt.h"

/* xt chain */

SEQ_DECLARE (xt_rule)

struct xt_chain {
	char name[XT_NAME_LEN];
	char policy[XT_NAME_LEN];
	struct xt_rule_seq rules;
};

struct xt_chain *xt_chain_alloc (const char *name, const char *policy)
{
	struct xt_chain *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	if (!xt_name_init (o->name, name))
		goto no_name;

	if (!xt_name_init (o->policy, policy == NULL ? "" : policy))
		goto no_policy;

	xt_rule_seq_init (&o->rules);
	return o;
no_policy:
no_name:
	free (o);
	return 0;
}

static void xt_chain_free (void *O)
{
	struct xt_chain *o = O;

	if (o == NULL)
		return;

	xt_rule_seq_fini (&o->rules, xt_rule_free);
	free (o);
}

static int xt_chain_eq (const void *O, const void *K)
{
	const struct xt_chain *o = O;
	const struct xt_chain *k = K;

	return strcmp (o->name, k->name) == 0;
}

static size_t xt_chain_hash (const void *O)
{
	const struct xt_chain *o = O;

	return hash (0, o->name, strlen (o->name));
}

static const struct data_type xt_chain_type = {
	.free	= xt_chain_free,
	.eq	= xt_chain_eq,
	.hash	= xt_chain_hash,
};

/* xt core */

struct xt {
	char table[XT_NAME_LEN];
	struct ht ht;
};

struct xt *xt_alloc (const char *table)
{
	struct xt *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	if (!xt_name_init (o->table, table))
		goto no_table;

	if (!ht_init (&o->ht, &xt_chain_type))
		goto no_ht;

	return o;
no_ht:
no_table:
	free (o);
	return NULL;
}

void xt_free (struct xt *o)
{
	if (o == NULL)
		return;

	ht_fini (&o->ht);
	free (o);
}

const char *xt_error (struct xt *o)
{
	return strerror (errno);
}

int xt_commit (struct xt *o)
{
	errno = ENOSYS;
	return 0;
}

int xt_is_chain (struct xt *o, const char *chain)
{
	struct xt_chain key;

	if (!xt_name_init (key.name, chain))
		return 0;

	return ht_lookup (&o->ht, &key) != NULL;
}

int xt_create_chain (struct xt *o, const char *chain, const char *policy)
{
	struct xt_chain *c;
	
	if ((c = xt_chain_alloc (chain, policy)) == NULL)
		return 0;

	if (ht_insert (&o->ht, c, 0))
		return 1;

	xt_chain_free (c);
	return 0;
}

int xt_delete_chain (struct xt *o, const char *chain)
{
	struct xt_chain key;

	if (!xt_name_init (key.name, chain))
		return 0;

	ht_remove (&o->ht, &key);
	return 1;
}

int xt_set_policy (struct xt *o, const char *chain, const char *policy)
{
	struct xt_chain *c, key;

	if (!xt_name_init (key.name, chain))
		return 0;

	if ((c = ht_lookup (&o->ht, &key)) == NULL) {
		errno = ENOENT;
		return 0;
	}

	return xt_name_init (c->policy, policy);
}

int xt_flush_chain (struct xt *o, const char *chain)
{
	struct xt_chain *c, key;

	if (!xt_name_init (key.name, chain))
		return 0;

	if ((c = ht_lookup (&o->ht, &key)) == NULL) {
		errno = ENOENT;
		return 0;
	}

	xt_rule_seq_fini (&c->rules, xt_rule_free);
	xt_rule_seq_init (&c->rules);
	return 1;
}

int xt_append_rule (struct xt *o, const char *chain, struct xt_rule *r)
{
	struct xt_chain *c, key;

	if (!xt_name_init (key.name, chain))
		return 0;

	if ((c = ht_lookup (&o->ht, &key)) == NULL) {
		errno = ENOENT;
		return 0;
	}

	xt_rule_seq_enqueue (&c->rules, r);
	return 1;
}

int xt_iterate (struct xt *o, xt_cb *cb, void *cookie)
{
	size_t i;
	struct xt_chain *c;

	ht_foreach (i, c, &o->ht)
		if (!cb (o, c->name, cookie))
			return 0;

	return 1;
}
