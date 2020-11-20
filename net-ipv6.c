/*
 * IPv6 address helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

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
	return inet_pton (AF_INET6, from, to);
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
	to->prefix = 0;
	return scan_ipv6 (addr, &to->addr) && scan_ipv6 (mask, &to->mask);
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
