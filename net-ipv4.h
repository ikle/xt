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
	struct in_addr addr;
	unsigned mask;
};

struct ipv4_range {
	struct in_addr start;
	struct in_addr stop;
};

int get_ipv4 (const char *from, struct in_addr *to);
int get_ipv4_masked (const char *from, struct ipv4_masked *to);
int get_ipv4_range (const char *from, struct ipv4_range *to);

#endif  /* NET_IPV4_H */
