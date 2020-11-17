/*
 * X Tables Rule
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef XT_RULE_H
#define XT_RULE_H  1

#include <stdarg.h>
#include <stddef.h>

#include <data/seq.h>

#define XT_NAME_LEN  32

/*
 * Note that matches, watchers and targets MUST NOT reference non-constant
 * external objects and MUST be allocated with standard malloc. The structures
 * below represent the standard headers for such objects. The interpretation
 * of other data following the header is left to the specific type of object.
 */

struct xt_item {
	struct xt_item *next;
	char name[XT_NAME_LEN];
};

SEQ_DECLARE (xt_item)

struct xt_target {
	char name[XT_NAME_LEN];
};

struct xt_rule {
	struct xt_rule		*next;
	struct xt_item_seq	matches;
	struct xt_item_seq	watchers;
	struct xt_target	*target;

	struct xt_item		*last;	/* used to cache access */
};

struct xt_rule *xt_rule_alloc (const char *domain, ...);
void xt_rule_free (struct xt_rule *o);

#endif  /* XT_RULE_H */
