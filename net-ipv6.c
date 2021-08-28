/*
 * IPv6 address helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <strings.h>

#include <arpa/inet.h>

#include "net-ipv6.h"

/*
 * We hard code maximum address length to be in sync with scanf format.
 * (Thus we cannot use INET6_ADDRSTRLEN.)
 */
#define IPV6_LEN  46
#define IPV6_FORMAT  "%45[.0-9:A-Fa-f]"

int scan_ipv6 (const char *from, struct in6_addr *to)
{
	return inet_pton (AF_INET6, from, to) > 0;
}

static int make_mask (unsigned prefix, struct in6_addr *mask)
{
	if (prefix > 128)
		return 0;

	if (prefix > 96) {
		mask->s6_addr32[0] = htonl (~0L << (128 - prefix));
		goto m96;
	}

	mask->s6_addr32[0] = ~0L;

	if (prefix > 64) {
		mask->s6_addr32[1] = htonl (~0L << (96 - prefix));
		goto m64;
	}

	mask->s6_addr32[1] = ~0L;

	if (prefix > 32) {
		mask->s6_addr32[2] = htonl (~0L << (64 - prefix));
		goto m32;
	}

	mask->s6_addr32[2] = ~0L;
	mask->s6_addr32[3] = htonl (~0L << (32 - prefix));
	return 1;
m96:	mask->s6_addr32[1] = 0;
m64:	mask->s6_addr32[2] = 0;
m32:	mask->s6_addr32[3] = 0;
	return 1;
}

static int calc_prefix (const struct in6_addr *mask, unsigned *prefix)
{
	uint32_t a = ntohl (mask->s6_addr[0]);
	uint32_t b = ntohl (mask->s6_addr[1]);
	uint32_t c = ntohl (mask->s6_addr[2]);
	uint32_t d = ntohl (mask->s6_addr[3]);

	if (~a != 0) {
		if (a == 0 || ~(a | (a - 1) | b | c | d) != 0)
			goto error;

		*prefix = 33 - ffs (a);  /* NOTE: on POSIX sizeof (int) >= 32 */
		return 1;
	}

	if (~b != 0) {
		if (~(b | (b - 1) | c | d) != 0)
			goto error;

		*prefix = 65 - ffs (b);
		return 1;
	}

	if (~c != 0) {
		if (~(c | (c - 1) | d) != 0)
			goto error;

		*prefix = 97 - ffs (c);
		return 1;
	}

	if (~(d | (d - 1)) != 0)
		goto error;

	*prefix = 129 - ffs (d);
	return 1;
error:
	*prefix = 0;  /* prefix zero or can not be calculated */
	return 1;
}

int scan_ipv6_masked (const char *from, struct ipv6_masked *to)
{
	char addr[IPV6_LEN], mask[IPV6_LEN], tail;

	if (sscanf (from, IPV6_FORMAT "%c", addr, &tail) == 1)
		goto plain;

	if (sscanf (from, IPV6_FORMAT "/%u%c",
		    addr, &to->prefix, &tail) == 2)
		goto cidr;

	if (sscanf (from, IPV6_FORMAT "/" IPV6_FORMAT "%c",
		    addr, mask, &tail) == 2)
		goto classic;

	return 0;
plain:
	to->prefix = 128;
cidr:
	return make_mask (to->prefix, &to->mask) && scan_ipv6 (addr, &to->addr);
classic:
	return scan_ipv6 (addr, &to->addr) && scan_ipv6 (mask, &to->mask) &&
	       calc_prefix (&to->mask, &to->prefix);
}

static int ipv6_le (const struct in6_addr *a, const struct in6_addr *b)
{
	uint32_t l = ntohl (a->s6_addr32[0]), r = ntohl (b->s6_addr32[0]);

	if (l != r)
		return l < r;

	l = ntohl (a->s6_addr32[1]), r = ntohl (b->s6_addr32[1]);

	if (l != r)
		return l < r;

	l = ntohl (a->s6_addr32[2]), r = ntohl (b->s6_addr32[2]);

	if (l != r)
		return l < r;

	l = ntohl (a->s6_addr32[3]), r = ntohl (b->s6_addr32[3]);
	return l <= r;
}

int scan_ipv6_range (const char *from, struct ipv6_range *to)
{
	char start[IPV6_LEN], stop[IPV6_LEN], tail;

	if (sscanf (from, IPV6_FORMAT "-" IPV6_FORMAT "%c",
		    start, stop, &tail) != 2)
		return 0;

	return scan_ipv6 (start, &to->start) && scan_ipv6 (stop, &to->stop) &&
	       ipv6_le (&to->start, &to->stop);
}

size_t print_ipv6 (char *to, size_t size, const struct in6_addr *from)
{
	char addr[IPV6_LEN];

	(void) inet_ntop (AF_INET6, from, to, sizeof (addr));

	return snprintf (to, size, "%s", addr);
}

size_t print_ipv6_masked (char *to, size_t size, const struct ipv6_masked *o)
{
	unsigned prefix = 0;
	size_t len;

	if (o->prefix == 0)
		calc_prefix (&o->mask, &prefix);

	len = print_ipv6 (to, size, &o->addr);

	if (prefix == 128)
		return len;  /* it is a host address */

	size = size > len ? size - len : 0;
	to += len;

	if (prefix != 0)
		return len + snprintf (to, size, "/%u", prefix);

	snprintf (to, size, "/");
	size = size > 1 ? size - 1 : 0;
	to += 1;

	return len + 1 + print_ipv6 (to, size, &o->mask);
}

size_t print_ipv6_range (char *to, size_t size, const struct ipv6_range *o)
{
	size_t len;

	len = print_ipv6 (to, size, &o->start);
	size = size > len ? size - len : 0;
	to += len;

	snprintf (to, size, "-");
	size = size > 1 ? size - 1 : 0;
	to += 1;

	return len + 1 + print_ipv6 (to, size, &o->stop);
}
