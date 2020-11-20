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

int scan_ipv4_masked (const char *from, struct ipv4_masked *to)
{
	char addr[IPV4_LEN], tail;

	if (sscanf (from, IPV4_FORMAT "/%u%c",
		    addr, &to->mask, &tail) != 2)
		return 0;

	return to->mask <= 32 && scan_ipv4 (addr, &to->addr);
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
