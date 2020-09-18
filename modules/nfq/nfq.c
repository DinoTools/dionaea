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

#include <glib.h>
#include <stdio.h>
#include <ev.h>
#include <stdint.h>

#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <limits.h>

#include <linux/netfilter_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "connection.h"
#include "dionaea.h"
#include "incident.h"
#include "modules.h"
#include "pchild.h"
#include "log.h"
#include "util.h"

#define D_LOG_DOMAIN "nfq"
#define BUFSIZE		2048
#define PAYLOADSIZE	80

static void nfq_io_cb(struct ev_loop *loop, struct ev_io *w, int revents);
static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

// iptables -t mangle -A PREROUTING -i eth0 -p tcp -m socket -j ACCEPT
// iptables -t mangle -A PREROUTING -i eth0 -p tcp --syn -m state --state NEW -j NFQUEUE --queue-num 30

static struct 
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd,rv;
	int queuenum;
	struct ev_io io;
} nfq_runtime;

bool nfq_config(void)
{
	GError *error = NULL;
	g_debug("%s %s", __PRETTY_FUNCTION__, __FILE__);
	memset(&nfq_runtime, 0, sizeof(nfq_runtime));

	nfq_runtime.queuenum  = g_key_file_get_integer(g_dionaea->config, "module.nfq", "queue", &error);

	g_info("nfq on queue %i", nfq_runtime.queuenum);

	return true;
}

bool nfq_prepare(void)
{
	g_debug("%s %p", __PRETTY_FUNCTION__, g_dionaea);

	nfq_runtime.h = nfq_open();
	if( !nfq_runtime.h )
	{
		g_warning("Error during nfq_open()");
		return false;
	}

	int families[] =  {AF_INET, AF_INET6};

	for( int i=0;i<sizeof(families)/sizeof(int); i++)
	{
		int family = families[i];
		if( nfq_unbind_pf(nfq_runtime.h, family) < 0 )
		{
			g_warning("error during nfq_unbind_pf() family %i", family);
			return false;
		}
	
		if( nfq_bind_pf(nfq_runtime.h, family) < 0 )
		{
			g_warning("Error during nfq_bind_pf() family %i", family);
			return false;
		}
	}

	g_debug("binding to queue '%hd'", nfq_runtime.queuenum);
	nfq_runtime.qh = nfq_create_queue(nfq_runtime.h,  nfq_runtime.queuenum, &nfqueue_cb, NULL);
	if( !nfq_runtime.qh )
	{
		g_debug("error during nfq_create_queue()");
		return false;
	}

	if( nfq_set_mode(nfq_runtime.qh, NFQNL_COPY_PACKET, PAYLOADSIZE) < 0 )
	{
		g_warning("can't set packet_copy mode");
		return false;
	}

	nfq_runtime.nh = nfq_nfnlh(nfq_runtime.h);
	nfq_runtime.fd = nfnl_fd(nfq_runtime.nh);
	return true;
}

static bool nfq_start(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);

	ev_io_init(&nfq_runtime.io, nfq_io_cb, nfq_runtime.fd, EV_READ);
	ev_io_start(g_dionaea->loop, &nfq_runtime.io);
	return true;
}

struct module_api *module_init(struct dionaea *d)
{
    g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, d);
	static struct module_api nfq_api =
	{
		.config = &nfq_config,
		.start = &nfq_start,
		.prepare = &nfq_prepare,
		.free = NULL,
		.hup = NULL,
	};

    return &nfq_api;
}

static void nfq_backend(int fd)
{
	g_debug("%s fd %i", __PRETTY_FUNCTION__, fd);
	int id;
	int nf;
	if( recv(fd, &id, sizeof(int), 0) > 0  && 
		recv(fd, &nf, sizeof(int), 0) > 0)
	{
		g_debug("allowing packet %i", id);
		nfq_set_verdict(nfq_runtime.qh, id, nf, 0, NULL);
	}
}


static void nfq_io_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
	g_debug("%s loop %p w %p revents %i", __PRETTY_FUNCTION__, loop, w, revents);

	int rv;
	char buf[BUFSIZE];
	while( (rv = recv(nfq_runtime.fd, buf, sizeof(buf), 0)) >= 0 )
	{
		nfq_handle_packet(nfq_runtime.h, buf, rv);
		break;
	}
}

static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	g_debug("%s qh %p nfmsg %p nfa %p,  data %p", __PRETTY_FUNCTION__, qh, nfmsg, nfa, data);

	int id=0;
	int nf=0;

	struct nfqnl_msg_packet_hdr *ph;
	#ifdef NF_QUEUE_PRE_1_0_0
	char *payload;
	#else
	unsigned char *payload;
	#endif
	int len;

	if( (ph = nfq_get_msg_packet_hdr(nfa)) == NULL)
	{
		g_warning("NFQUEUE: can't get msg packet header.");
		return 1;		// from nfqueue source: 0 = ok, >0 = soft error, <0 hard error
	}

	len = nfq_get_payload(nfa, &payload);

	if( len <= 0 )
		return 0;

	if( len <=  sizeof(struct iphdr) )
		return 0;

	struct iphdr * ip = (struct iphdr *) payload;
	if( ip->version == IPVERSION )
	{ /* IPv4 */
		if( len >= ip->ihl * 4 + sizeof(struct tcphdr) )
		{
			struct tcphdr * tcp = (struct tcphdr *) (payload + ip->ihl * 4);

			struct connection *con = connection_new(connection_transport_tcp);
			con->protocol.name = g_strdup("nfq");

			sockaddr_storage_from(&con->local.addr,AF_INET, &ip->daddr, ntohs(tcp->th_dport));
			sockaddr_storage_from(&con->remote.addr, AF_INET, &ip->saddr, ntohs(tcp->th_sport));

			node_info_set(&con->local, &con->local.addr);
			node_info_set(&con->remote, &con->remote.addr);
			g_debug("pending local:'%s' remote:'%s'", con->local.node_string,  con->remote.node_string);

			struct incident *i = incident_new("dionaea.connection.tcp.pending");
			incident_value_con_set(i, "con", con);
			incident_value_int_set(i, "nfaction", NF_ACCEPT);
			incident_report(i);

			long int nfr;
			incident_value_int_get(i, "nfaction", &nfr);
			nf = nfr;

			incident_free(i);

			connection_free_cb(g_dionaea->loop, &con->events.free, 0, true);
		}
	
	}else
	{ /* IPv6 needs some love */
		g_warning("FIXME: nfq is not implemented for IPv6.");
		nf = NF_ACCEPT;
	}

	id = ntohl(ph->packet_id);
	uintptr_t cmd = (uintptr_t)nfq_backend;
	send(g_dionaea->pchild->fd, &cmd, sizeof(uintptr_t), 0);
	send(g_dionaea->pchild->fd, &id, sizeof(id), 0);
	send(g_dionaea->pchild->fd, &nf, sizeof(nf), 0);
	return 0;
}
