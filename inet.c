/*
 * Internet address helpers
 *
 * Copyright (c) 2017-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>

#include <netdb.h>

#include "inet.h"

int get_proto (const char *from, unsigned *to)
{
	struct protoent *p;
	char tail;

	if (strcmp (from, "any") == 0) {
		*to = 0;
		return 1;
	}

	if (sscanf (from, "%u%c", to, &tail) == 1)
		return 1;

	p = getprotobyname (from);
	endprotoent ();

	if (p == NULL)
		return 0;

	*to = p->p_proto;
	return 1;
}

int get_service (const char *from, unsigned *to)
{
	struct addrinfo hints, *res, *p;
	struct sockaddr_in  *s4;
	struct sockaddr_in6 *s6;

	memset (&hints, 0, sizeof (hints));

	if (getaddrinfo (NULL, from, &hints, &res) != 0)
		return 0;

	for (p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET) {
			s4 = (void *) p->ai_addr;
			*to = s4->sin_port;
			goto found;
		}

		if (p->ai_family == AF_INET6) {
			s6 = (void *) p->ai_addr;
			*to = s6->sin6_port;
			goto found;
		}
	}

	freeaddrinfo (res);
	return 0;
found:
	freeaddrinfo (res);
	return 1;
}

int get_port_range (const char *from, struct ip_port_range *to)
{
	char tail;

	if (sscanf (from, "%hu-%hu%c", &to->start, &to->stop, &tail) != 2)
		return 0;

	return to->start <= to->stop;
}
