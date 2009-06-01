/********************************************************************************
 *                               Dionaea
 *                           - catches bugs -
 *
 *
 *
 * Copyright (C) 2009  Paul Baecher & Markus Koetter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * 
 *             contact nepenthesdev@gmail.com  
 *
 *******************************************************************************/

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



