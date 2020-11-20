/*
 * IPv4 address helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include <arpa/inet.h>

#include "net-ipv4.h"

/*
 * We hard code maximum address length to be in sync with scanf format.
 * (Thus we cannot use INET_ADDRSTRLEN.)
 */
#define IPV4_LEN  16
#define IPV4_FORMAT  "%15[.0-9]"

int scan_ipv4 (const char *from, struct in_addr *to)
{
	return inet_pton (AF_INET, from, to);
}

static int make_mask (unsigned prefix, struct in_addr *mask)
{
	if (prefix > 32)
		return 0;

	mask->s_addr = htonl (~0L << (32 - prefix));
	return 1;
}

int scan_ipv4_masked (const char *from, struct ipv4_masked *to)
{
	char addr[IPV4_LEN], mask[IPV4_LEN], tail;

	if (sscanf (from, IPV4_FORMAT "%c", addr, &tail) == 1)
		goto plain;

	if (sscanf (from, IPV4_FORMAT "/%u%c",
		    addr, &to->prefix, &tail) == 2)
		goto cidr;

	if (sscanf (from, IPV4_FORMAT "/" IPV4_FORMAT "%c",
		    addr, mask, &tail) == 2)
		goto classic;

	return 0;
plain:
	to->prefix = 32;
cidr:
	return make_mask (to->prefix, &to->mask) && scan_ipv4 (addr, &to->addr);
classic:
	to->prefix = 0;
	return scan_ipv4 (addr, &to->addr) && scan_ipv4 (mask, &to->mask);
}

int scan_ipv4_range (const char *from, struct ipv4_range *to)
{
	char start[IPV4_LEN], stop[IPV4_LEN], tail;

	if (sscanf (from, IPV4_FORMAT "-" IPV4_FORMAT "%c",
		    start, stop, &tail) != 2)
		return 0;

	return scan_ipv4 (start, &to->start) && scan_ipv4 (stop, &to->stop) &&
	       ntohl (to->start.s_addr) <= ntohl (to->stop.s_addr);
}

size_t print_ipv4 (char *to, size_t size, const struct in_addr *from)
{
	char addr[IPV4_LEN];

	(void) inet_ntop (AF_INET, from, to, sizeof (addr));

	return snprintf (to, size, "%s", addr);
}
