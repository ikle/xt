/*
 * IP Tables Rule
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <linux/netfilter_ipv4/ip_tables.h>

#include "inet.h"
#include "xt-domain.h"

struct xt_match_ip {
	struct xt_item	head;
	struct ipt_ip	data;
};

static const struct xt_item_ops xt_ip_ops = {

};

static struct ipt_ip *get_match (struct xt_rule *o, const char *name)
{
	struct xt_match_ip *m;

	m = (void *) xt_get_match (o, name, &xt_ip_ops, sizeof (m->data));
	if (m == NULL)
		return NULL;

	return &m->data;
}

static int ip_set_src (struct xt_rule *o, int inv, const char *arg)
{
	struct ipt_ip *m = get_match (o, "");

	if (m == NULL)
		return 0;

	if (inv)
		m->invflags |= IPT_INV_SRCIP;

	return get_ipv4 (arg, &m->src);
}

static int ip_set_dst (struct xt_rule *o, int inv, const char *arg)
{
	struct ipt_ip *m = get_match (o, "");

	if (m == NULL)
		return 0;

	if (inv)
		m->invflags |= IPT_INV_DSTIP;

	return get_ipv4 (arg, &m->dst);
}

static int set_iface (const char *iface, char *name, unsigned char *mask)
{
	const size_t size = IFNAMSIZ;
	size_t i;
	int plus = 0;

	memset (name, 0, size);
	memset (mask, 0, size);

	for (i = 0; *iface != '\0'; ++i, ++iface) {
		if (i == size) {
			errno = EINVAL;
			return 0;
		}

		name[i] = *iface;
		mask[i] = 0xff;
		plus = *iface == '+';
	}

	if (!plus && i < size)
		mask[i] = 0xff;

	return 1;
}

static int ip_set_in (struct xt_rule *o, int inv, const char *arg)
{
	struct ipt_ip *m = get_match (o, "");

	if (m == NULL)
		return 0;

	if (inv)
		m->invflags |= IPT_INV_VIA_IN;

	return set_iface (arg, m->iniface, m->iniface_mask);
}

static int ip_set_out (struct xt_rule *o, int inv, const char *arg)
{
	struct ipt_ip *m = get_match (o, "");

	if (m == NULL)
		return 0;

	if (inv)
		m->invflags |= IPT_INV_VIA_OUT;

	return set_iface (arg, m->outiface, m->outiface_mask);
}

static int ip_set_proto (struct xt_rule *o, int inv, const char *arg)
{
	struct ipt_ip *m = get_match (o, "");
	unsigned proto;

	if (m == NULL)
		return 0;

	if (inv)
		m->invflags |= IPT_INV_PROTO;

	if (!get_proto (arg, &proto))
		return 0;

	m->proto = proto;
	return 1;
}

static int ip_set_frag (struct xt_rule *o, int inv, const char *arg)
{
	struct ipt_ip *m = get_match (o, "");

	if (m == NULL)
		return 0;

	if (inv)
		m->invflags |= IPT_INV_FRAG;

	m->flags |= IPT_F_FRAG;

	return 1;
}

static int ip_set_jump (struct xt_rule *o, int inv, const char *arg)
{
	char target[XT_NAME_LEN];
	const struct xt_opt *opt;

	if (inv ||
	    snprintf (target, XT_NAME_LEN, "jump-%s", arg) >= XT_NAME_LEN) {
		errno = EINVAL;
		return 0;
	}

	if ((opt = xt_opt_lookup ("ip", target)) != NULL)
		return opt->set (o, 0, NULL);

	return xt_rule_link (o, arg);
}

static int ip_set_goto (struct xt_rule *o, int inv, const char *arg)
{
	struct ipt_ip *m = get_match (o, "");

	m->flags |= IPT_F_GOTO;

	return ip_set_jump (o, inv, arg);
}

const struct xt_opt xt_ip_opts[] = {
	{ "src",	1,	ip_set_src	},
	{ "dst",	1,	ip_set_dst	},
	{ "in",		1,	ip_set_in	},
	{ "out",	1,	ip_set_out	},
	{ "proto",	1,	ip_set_proto	},
	{ "frag",	0,	ip_set_frag	},

	{ "jump",	1,	ip_set_jump	},
	{ "goto",	1,	ip_set_goto	},

	{}
};

#define __init __attribute__ ((constructor))

static void __init module_init (void)
{
	(void) xt_domain_setup ("ip", xt_ip_opts);
}
