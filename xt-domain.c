/*
 * X Tables Rule Options
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <data/hash.h>
#include <data/ht.h>

#include "xt-domain.h"

/* generic helpers */

static int xt_name_init (char *name, const char *value)
{
	if (snprintf (name, XT_NAME_LEN, "%s", name) < XT_NAME_LEN)
		return 1;

	errno = EINVAL;
	return 0;
}

/* xt opt */

static int xt_opt_eq (const void *O, const void *K)
{
	const struct xt_opt *o = O;
	const struct xt_opt *k = K;

	return strcmp (o->name, k->name) == 0;
}

static size_t xt_opt_hash (const void *O)
{
	const struct xt_opt *o = O;

	return hash (0, o->name, strlen (o->name));
}

static const struct data_type xt_opt_type = {
	.eq	= xt_opt_eq,
	.hash	= xt_opt_hash,
};

/* xt domain: set of options */

struct xt_domain {
	char name[XT_NAME_LEN];
	struct ht opts;
};

static struct xt_domain *xt_domain_alloc (const char *name)
{
	struct xt_domain *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	if (!xt_name_init (o->name, name))
		goto no_name;

	if (!ht_init (&o->opts, &xt_opt_type))
		goto no_ht;

	return o;
no_ht:
no_name:
	free (o);
	return NULL;
}

static void xt_domain_free (void *O)
{
	struct xt_domain *o = O;

	ht_fini (&o->opts);
	free (o);
}

static int xt_domain_eq (const void *O, const void *K)
{
	const struct xt_domain *o = O;
	const struct xt_domain *k = K;

	return strcmp (o->name, k->name) == 0;
}

static size_t xt_domain_hash (const void *O)
{
	const struct xt_domain *o = O;

	return hash (0, o->name, strlen (o->name));
}

static const struct data_type xt_domain_type = {
	.eq	= xt_domain_eq,
	.hash	= xt_domain_hash,
};

/* xt hive: set of domains */

struct xt_hive {
	struct ht domains;
};

static struct xt_hive *xt_hive_alloc (void)
{
	struct xt_hive *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	if (!ht_init (&o->domains, &xt_domain_type))
		goto no_ht;

	return o;
no_ht:
	free (o);
	return NULL;
}

/* main logic */

static struct xt_hive *hive;

int xt_domain_setup (const char *domain, struct xt_opt *seq)
{
	struct xt_domain key, *d;
	int ok;

	if (hive == NULL && (hive = xt_hive_alloc ()) == NULL)
		return 0;

	if (!xt_name_init (key.name, domain))
		return 0;

	if ((d = ht_lookup (&hive->domains, &key)) == NULL) {
		if ((d = xt_domain_alloc (domain)) == NULL)
			return 0;

		if (!ht_insert (&hive->domains, d, 0))
			goto no_insert;
	}

	for (ok = 1; seq->name != NULL; ++seq)
		ok &= ht_insert (&d->opts, seq, 0);

	return ok;
no_insert:
	xt_domain_free (d);
	return 0;
}

static struct xt_domain *xt_domain_lookup (const char *domain)
{
	struct xt_domain key;

	if (!xt_name_init (key.name, domain))
		return 0;

	return ht_lookup (&hive->domains, &key);
}

struct xt_opt *xt_opt_lookup (const char *domain, const char *name)
{
	struct xt_domain *d;
	struct xt_opt key = { name };

	if ((d = xt_domain_lookup (domain)) == NULL)
		return NULL;

	return ht_lookup (&d->opts, &key);
}
