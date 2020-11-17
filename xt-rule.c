/*
 * X Tables Rule
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "xt-domain.h"
#include "xt-rule.h"

static int xt_rule_build (struct xt_rule *o, const char *domain, va_list ap)
{
	const char *name, *arg;
	struct xt_opt *opt;
	int inv;

	while ((name = va_arg (ap, const char *)) != NULL) {
		if (strncmp (name, "no-", 3) == 0)
			inv = 1, name += 3;
		else
			inv = 0;

		if ((opt = xt_opt_lookup (domain, name)) == NULL) {
			errno = ENOENT;
			return 0;
		}

		if (opt->flags > 0) {
			if ((arg = va_arg (ap, const char *)) == NULL) {
				errno = EINVAL;
				return 0;
			}
		}
		else
			arg = NULL;

		if (!opt->set (o, inv, arg))
			return 0;
	}

	return 1;
}

struct xt_rule *xt_rule_alloc (const char *domain, ...)
{
	struct xt_rule *o;
	va_list ap;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	o->next = NULL;

	xt_item_seq_init (&o->matches);
	xt_item_seq_init (&o->watchers);

	o->target = NULL;
	o->last = NULL;
	va_start (ap, domain);

	if (!xt_rule_build (o, domain, ap))
		goto no_build;

	va_end (ap);
	return o;
no_build:
	va_end (ap);
	xt_rule_free (o);
	return NULL;
}

static void xt_item_free (struct xt_item *o)
{
	free (o);
}

void xt_rule_free (struct xt_rule *o)
{
	if (o == NULL)
		return;

	xt_item_seq_fini (&o->matches,  xt_item_free);
	xt_item_seq_fini (&o->watchers, xt_item_free);
	free (o->target);
	free (o);
}

/*
 * Rule builder helper. Finds the last module by its name in the rule.
 * If the module is not found, it creates a new one with the specified
 * size for additional data and adds it to the end of the rule.
 */
struct xt_item *xt_get_match (struct xt_rule *o, const char *name, size_t size)
{
	struct xt_item *p;

	if (o->last != NULL && strcmp (o->last->name, name) == 0)
		return o->last;  /* found in cache */

	for (p = o->matches.head; p != NULL; p = p->next)
		if (strcmp (p->name, name) == 0)
			goto found;

	if ((p = calloc (1, sizeof (*p) + size)) == NULL)
		return NULL;

	xt_item_seq_enqueue (&o->matches, p);
found:
	o->last = p;  /* cache result */
	return p;
}
