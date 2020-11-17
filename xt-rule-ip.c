/*
 * IP Tables Rule
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>

#include <linux/netfilter_ipv4/ip_tables.h>

#include "xt-rule.h"

struct xt_match_ip {
	struct xt_item	head;
	struct ipt_ip	data;
};
