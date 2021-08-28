/*
 * IPv4 address helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <strings.h>

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
	return inet_pton (AF_INET, from, to) > 0;
}

static int make_mask (unsigned prefix, struct in_addr *mask)
{
	if (prefix > 32)
		return 0;

	mask->s_addr = htonl (~0L << (32 - prefix));
	return 1;
}

static int calc_prefix (const struct in_addr *mask, unsigned *prefix)
{
	uint32_t m = ntohl (mask->s_addr);

	if (m == 0 || ~(m | (m - 1)) != 0) {
		*prefix = 0;  /* prefix zero or can not be calculated */
		return 1;
	}

	*prefix = 33 - ffs (m);  /* NOTE: on POSIX sizeof (int) >= 32 */
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
	return scan_ipv4 (addr, &to->addr) && scan_ipv4 (mask, &to->mask) &&
	       calc_prefix (&to->mask, &to->prefix);
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

size_t print_ipv4_masked (char *to, size_t size, const struct ipv4_masked *o)
{
	unsigned prefix = 0;
	size_t len;

	if (o->prefix == 0)
		calc_prefix (&o->mask, &prefix);

	len = print_ipv4 (to, size, &o->addr);

	if (prefix == 32)
		return len;  /* it is a host address */

	size = size > len ? size - len : 0;
	to += len;

	if (prefix != 0)
		return len + snprintf (to, size, "/%u", prefix);

	snprintf (to, size, "/");
	size = size > 1 ? size - 1 : 0;
	to += 1;

	return len + 1 + print_ipv4 (to, size, &o->mask);
}

size_t print_ipv4_range (char *to, size_t size, const struct ipv4_range *o)
{
	size_t len;

	len = print_ipv4 (to, size, &o->start);
	size = size > len ? size - len : 0;
	to += len;

	snprintf (to, size, "-");
	size = size > 1 ? size - 1 : 0;
	to += 1;

	return len + 1 + print_ipv4 (to, size, &o->stop);
}
