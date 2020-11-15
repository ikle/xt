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

#include "xt-rule.h"

extern struct xt_rule_ops xt_rule_ip;

static struct xt_rule_ops *get_ops (const char *domain)
{
	if (strcmp (domain, "ip") == 0)
		return &xt_rule_ip;

	errno = ENOSYS;
	return NULL;
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

	if ((o->ops = get_ops (domain)) == NULL)
		goto no_ops;

	va_start (ap, domain);

	if (!o->ops->build (o, ap))
		goto no_build;

	va_end (ap);
	return o;
no_build:
	va_end (ap);
no_ops:
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
