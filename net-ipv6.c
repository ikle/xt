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

int get_ipv6 (const char *from, struct in6_addr *to)
{
	return inet_pton (AF_INET6, from, to);
}

int get_ipv6_masked (const char *from, struct ipv6_masked *to)
{
	char addr[IPV6_LEN], tail;

	if (sscanf (from, IPV6_FORMAT "/%u%c",
		    addr, &to->mask, &tail) != 2)
		return 0;

	return to->mask <= 128 && get_ipv6 (addr, &to->addr);
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

int get_ipv6_range (const char *from, struct ipv6_range *to)
{
	char start[IPV6_LEN], stop[IPV6_LEN], tail;

	if (sscanf (from, IPV6_FORMAT "-" IPV6_FORMAT "%c",
		    start, stop, &tail) != 2)
		return 0;

	return get_ipv6 (start, &to->start) && get_ipv6 (stop, &to->stop) &&
	       ipv6_le (&to->start, &to->stop);
}
