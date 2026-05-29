/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ev.h>

struct dns_ctx;

struct dns
{
	struct dns_ctx *dns;
	struct ev_timer dns_timeout;
	struct ev_io io_in;
	int socket;
};

void udns_io_in_cb(EV_P_ struct ev_io *w, int revents);
void udns_timeout_cb(EV_P_ struct ev_timer *w, int revents);
void udns_set_timeout_cb(struct dns_ctx *ctx, int timeout, void *data);
