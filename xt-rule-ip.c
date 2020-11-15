/*
 * IP Tables Rule
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>

#include <linux/netfilter_ipv4/ip_tables.h>

#include "xt-rule.h"

struct xt_match_ip {
	struct xt_item	head;
	struct ipt_ip	data;
};

static int ip_build (struct xt_rule *o, va_list ap)
{
	return 0;
}

static size_t ip_parse (struct xt_rule *o, const char *from, size_t size)
{
	return 0;
}

static size_t ip_read (struct xt_rule *o, const void *from, size_t size)
{
	return 0;
}

static size_t ip_show (const struct xt_rule *o, char *to, size_t size)
{
	return 0;
}

static size_t ip_write (const struct xt_rule *o, void *to, size_t size)
{
	return 0;
}

struct xt_rule_ops xt_rule_ip = {
	.build	= ip_build,
	.parse	= ip_parse,
	.read	= ip_read,
	.show	= ip_show,
	.write	= ip_write,
};
