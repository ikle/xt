/*
 * IPv4 address helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef NET_IPV4_H
#define NET_IPV4_H  1

#include <netinet/in.h>

struct ipv4_masked {
	struct in_addr addr, mask;
	unsigned prefix;
};

struct ipv4_range {
	struct in_addr start;
	struct in_addr stop;
};

int scan_ipv4 (const char *from, struct in_addr *to);
int scan_ipv4_masked (const char *from, struct ipv4_masked *to);
int scan_ipv4_range (const char *from, struct ipv4_range *to);

size_t print_ipv4 (char *to, size_t size, const struct in_addr *from);
size_t print_ipv4_masked (char *to, size_t size, const struct ipv4_masked *o);
size_t print_ipv4_range  (char *to, size_t size, const struct ipv4_range  *o);

#endif  /* NET_IPV4_H */
