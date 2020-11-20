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

static const char *get_inv (int inv)
{
	return inv ? "no-" : "";
}

static size_t show_addr (char *to, size_t size, int inv, const char *prefix,
			 const struct in_addr *o, const struct in_addr *mask)
{
	struct ipv4_masked a = { *o, *mask, 0 };
	size_t len;

	if (o->s_addr == 0)
		return 0;

	len = snprintf (to, size, " %s%s ", get_inv (inv), prefix);
	size = size > len ? size - len : 0;
	to += len;

	return len + print_ipv4_masked (to, size, &a);
}

static size_t show_iface (char *to, size_t size, int inv, const char *prefix,
			  const char *name, const unsigned char *mask)
{
	char pattern[IFNAMSIZ + 1];
	size_t i;

	if (mask[0] == 0)
		return 0;

	for (i = 0; i < IFNAMSIZ;) {
		pattern[i] = (name[i] | mask[i]) == 0 ? '+' : name[i];

		if (mask[i++] == 0)
			break;
	}

	pattern[i] = '\0';
	return snprintf (to, size, " %s%s %s", get_inv (inv), prefix, pattern);
}

#include <netdb.h>

static size_t show_proto (char *to, size_t size, int inv, unsigned proto)
{
	struct protoent *pe;

	if (proto == 0)
		return 0;

	pe = getprotobynumber (proto);
	endprotoent ();

	if (pe == NULL)
		return snprintf (to, size, " %sproto %u", get_inv (inv), proto);

	return snprintf (to, size, " %sproto %s", get_inv (inv), pe->p_name);
}

static size_t show_frag (char *to, size_t size, int inv, int frag)
{
	if (frag == 0)
		return 0;

	return snprintf (to, size, " %sfrag", get_inv (inv));
}

#define WRITE_OPT(type, ...)						\
	do {								\
		size_t len = show_##type (to, size, __VA_ARGS__);	\
		size = size > len ? size - len : 0;			\
		to += len, total += len;				\
	}								\
	while (0)

static size_t xt_ip_show (const struct xt_item *xi, char *to, size_t size)
{
	const struct xt_match_ip *m = (const void *) xi;
	const struct ipt_ip *o = &m->data;
	size_t total = 0;

#define INV(name)  (o->invflags & IPT_INV_##name)

	WRITE_OPT (addr,  INV (SRCIP),   "src", &o->src, &o->smsk);
	WRITE_OPT (addr,  INV (DSTIP),   "dst", &o->dst, &o->dmsk);
	WRITE_OPT (iface, INV (VIA_IN),  "in",  o->iniface,  o->iniface_mask);
	WRITE_OPT (iface, INV (VIA_OUT), "out", o->outiface, o->outiface_mask);
	WRITE_OPT (proto, INV (PROTO),   o->proto);
	WRITE_OPT (frag,  INV (FRAG),    o->flags & IPT_F_FRAG);

#undef INV

	return total;
}

static size_t xt_ip_write (const struct xt_item *xi, void *to, size_t size)
{
	const struct xt_match_ip *m = (const void *) xi;
	const struct ipt_ip *o = &m->data;

	if (size > sizeof (*o))
		size = sizeof (*o);

	memcpy (to, o, size);
	return size;
}

static const struct xt_item_ops xt_ip_ops = {
	xt_ip_show,
	xt_ip_write,
};

static struct ipt_ip *get_match (struct xt_rule *o, const char *name)
{
	struct xt_match_ip *m;

	m = (void *) xt_get_match (o, name, &xt_ip_ops, sizeof (m->data));
	if (m == NULL)
		return NULL;

	return &m->data;
}

#define DECLARE_OP(type, name, flag, ...)				\
static int ip_set_##name (struct xt_rule *o, int inv, const char *arg)	\
{									\
	struct ipt_ip *m = get_match (o, "");				\
									\
	if (m == NULL)							\
		return 0;						\
									\
	if (inv)							\
		m->invflags |= IPT_INV_##flag;				\
									\
	return set_##type (arg, __VA_ARGS__);				\
}

static int set_addr (const char *v, struct in_addr *addr, struct in_addr *mask)
{
	struct ipv4_masked a;

	if (!scan_ipv4_masked (v, &a))
		return 0;

	*addr = a.addr;
	*mask = a.mask;
	return 1;
}

DECLARE_OP (addr, src, SRCIP, &m->src, &m->smsk)
DECLARE_OP (addr, dst, DSTIP, &m->dst, &m->dmsk)

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

DECLARE_OP (iface, in,  VIA_IN,  m->iniface,  m->iniface_mask)
DECLARE_OP (iface, out, VIA_OUT, m->outiface, m->outiface_mask)

static int set_proto (const char *arg, unsigned short *to)
{
	unsigned proto;

	if (!get_proto (arg, &proto))
		return 0;

	*to = proto;
	return 1;
}

DECLARE_OP (proto, proto, PROTO, &m->proto)

static int set_frag (const char *arg, unsigned char *flags)
{
	*flags |= IPT_F_FRAG;
	return 1;
}

DECLARE_OP (frag, frag, FRAG, &m->flags)

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
