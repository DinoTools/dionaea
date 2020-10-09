/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdbool.h>
#include <stdlib.h>
#include <udns.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "dionaea.h"
#include "dns.h"


void udns_io_in_cb(EV_P_ struct ev_io *w, int revents)
{
//	puts(__PRETTY_FUNCTION__);
	dns_ioevent(g_dionaea->dns->dns, 0);
}


void udns_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
//	puts(__PRETTY_FUNCTION__);
//	int dns_timeouts(ctx, int maxwait, time_t now)
	int ret = dns_timeouts(g_dionaea->dns->dns, 3, 0);
	if( ret == -1 )
	{
		ev_timer_stop(EV_A_ &g_dionaea->dns->dns_timeout);
	} else
	{
		ev_timer_stop(EV_A_ &g_dionaea->dns->dns_timeout);
		ev_timer_init(&g_dionaea->dns->dns_timeout, udns_timeout_cb, ret*1.0, 0.);
		ev_timer_start(EV_A_ &g_dionaea->dns->dns_timeout);
	}
}

void udns_set_timeout_cb(struct dns_ctx *ctx, int timeout, void *data)
{
//	puts(__PRETTY_FUNCTION__);
	struct ev_loop *loop = data;
	if( ctx == NULL )
	{
//		printf("removing DNS timeout %s:%i\n", __FILE__,  __LINE__);
		ev_timer_stop(loop, &g_dionaea->dns->dns_timeout);
	} else
	{
		if( timeout < 0 )
		{
			ev_timer_stop(loop, &g_dionaea->dns->dns_timeout);
//			printf("removing DNS timeout %s:%i\n", __FILE__,  __LINE__);
		} else
			if( timeout == 0 )
		{
//			printf("immediate DNS timeout  %s:%i\n", __FILE__,  __LINE__);
			ev_timer_stop(loop, &g_dionaea->dns->dns_timeout);
			ev_timer_init(&g_dionaea->dns->dns_timeout, udns_timeout_cb, 0.0, 0.);
			ev_timer_start(loop, &g_dionaea->dns->dns_timeout);
		} else
			if( timeout > 0 )
		{
//			printf("resetting DNS timeout to %i  %s:%i\n", timeout, __FILE__,  __LINE__);
			ev_timer_stop(loop, &g_dionaea->dns->dns_timeout);
			ev_timer_init(&g_dionaea->dns->dns_timeout, udns_timeout_cb, (double)timeout, 0.);
			ev_timer_start(loop, &g_dionaea->dns->dns_timeout);
		}
	}
}
