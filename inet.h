/*
 * Internet address helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef JANUS_INET_H
#define JANUS_INET_H  1

#include <netinet/in.h>

#include "net-ipv4.h"
#include "net-ipv6.h"

struct ip_port_range {
	unsigned short start, stop;
};

int get_proto   (const char *from, unsigned *to);
int get_service (const char *from, unsigned *to);
int get_port_range (const char *from, struct ip_port_range *to);

#endif  /* JANUS_INET_H */
