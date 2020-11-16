/*
 * X Tables Rule Options
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef XT_OPT_H
#define XT_OPT_H  1

#include "xt-rule.h"

struct xt_opt {
	const char *name;
	int flags;
	int (*set) (struct xt_rule *o, int inv, const char *arg);
};

int xt_opt_setup (const char *domain, struct xt_opt *seq);

struct xt_opt *xt_opt_lookup (const char *domain, const char *name);

#endif  /* XT_OPT_H */
