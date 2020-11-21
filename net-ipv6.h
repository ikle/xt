/*
 * IPv6 address helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NET_IPV6_H
#define NET_IPV6_H  1

#include <netinet/in.h>

struct ipv6_masked {
	struct in6_addr addr, mask;
	unsigned prefix;
};

struct ipv6_range {
	struct in6_addr start;
	struct in6_addr stop;
};

int scan_ipv6 (const char *from, struct in6_addr *to);
int scan_ipv6_masked (const char *from, struct ipv6_masked *to);
int scan_ipv6_range (const char *from, struct ipv6_range *to);

size_t print_ipv6 (char *to, size_t size, const struct in6_addr *from);
size_t print_ipv6_masked (char *to, size_t size, const struct ipv6_masked *o);
size_t print_ipv6_range  (char *to, size_t size, const struct ipv6_range  *o);

#endif  /* NET_IPV6_H */
