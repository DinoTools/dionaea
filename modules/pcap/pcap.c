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

#include <string.h>
#include <glib.h>
#include <stdio.h>

#include <lcfg/lcfg.h>
#include <lcfgx/lcfgx_tree.h>

#include <pcap.h>
#include <pcap/sll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <ev.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>


#include "modules.h"
#include "dionaea.h"
#include "connection.h"
#include "incident.h"
#include "util.h"
#include "log.h"
#include "util.h"

#define D_LOG_DOMAIN "pcap"


/**
 * I hate compatibility defines, but defining ETHERTYPE_IPV6 
 * seems optional, and we really need it.
 */
#ifndef ETHERTYPE_IPV6
#define	ETHERTYPE_IPV6		0x86dd		/* IP protocol version 6 */
#endif


struct pcap_device 
{
	pcap_t *pcap;
	char *name;
	int linktype;
	struct ev_io io_in;
};

#define PDEVOFF_IO_IN(x)  					((struct pcap_device *)(((void *)x) - offsetof (struct pcap_device, io_in)))

static struct 
{
	struct lcfgx_tree_node *config;
	GHashTable *devices;
} pcap_runtime;


static void pcap_io_in_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
//	g_message("%s loop %p w %p revents %i", __PRETTY_FUNCTION__, loop, w, revents);
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	int retval;
	
	struct pcap_device *dev = PDEVOFF_IO_IN(w);
	retval = pcap_next_ex(dev->pcap,&pkt_header, &pkt_data);
	
	if ( retval != 1 )
		return;

//	g_debug("++");

	int offset;
	int family = -1;
	void *local;
	void *remote;
	if( dev->linktype == DLT_LINUX_SLL )
	{
		struct sll_header *h = (void *)pkt_data;
		offset = 16;

		if( ntohs(h->sll_protocol) == ETHERTYPE_IP )
			family = PF_INET;
		else
		if( ntohs(h->sll_protocol) == ETHERTYPE_IPV6 )
			family = PF_INET6;
		else
			return;
	}else
	if( dev->linktype == DLT_EN10MB )
	{
		struct ether_header *h = (void *)pkt_data;
//		g_debug("ethernet 0x%02x %i", ntohs(h->ether_type), ntohs(h->ether_type));

		offset = 14;
		if( ntohs(h->ether_type) == ETHERTYPE_IP )
			family = PF_INET;
		else
		if( ntohs(h->ether_type) == ETHERTYPE_IPV6 )
			family = PF_INET6;
		else
			return;
	}else
	{
		g_warning("unknown linktype on %s %i", dev->name, dev->linktype);
		return;
	}

	const u_char *ipdata = pkt_data + offset;
	const struct tcphdr* tcp;

	if( family == PF_INET )
	{
//		g_debug("ipv4");
		struct ip *ipv4 = (void *)ipdata;
		local = &ipv4->ip_src;
		remote = &ipv4->ip_dst;

		if( ipv4->ip_p != IPPROTO_TCP )
			return;

		tcp = (struct tcphdr *) ((u_char *)ipdata+ipv4->ip_hl*4);
	}else
	if( family == PF_INET6 )
	{
//		g_debug("ipv6");
		struct ip6_hdr *ipv6 = (void *)ipdata;
//		g_debug("header %p", ipv6);

		local = &ipv6->ip6_src;
		remote = &ipv6->ip6_dst;

		if( ipv6->ip6_nxt != IPPROTO_TCP )
			return;

		tcp = (struct tcphdr *) ((u_char *)ipdata+sizeof(struct ip6_hdr));
	}else
	{
		g_warning("unknown familiy %i", family);
		return;
	}

#ifndef HAVE_PCAP_IPV6_TCP
	if( !(tcp->th_flags & TH_RST) || tcp->th_seq != 0 )
		return;
#endif

#ifdef DEBUG
	char lname[128];
	char rname[128];
	g_debug("%s:%i -> %s:%i", inet_ntop(family, local, lname, 128), ntohs(tcp->th_sport), inet_ntop(family, remote, rname, 128), ntohs(tcp->th_dport));
#endif

	struct connection *con = connection_new(connection_transport_tcp);
	con->protocol.name = g_strdup("pcap");
	sockaddr_storage_from(&con->local.addr, family, local, ntohs(tcp->th_sport));
	sockaddr_storage_from(&con->remote.addr, family, remote, ntohs(tcp->th_dport));

	node_info_set(&con->local, &con->local.addr);
	node_info_set(&con->remote, &con->remote.addr);
	g_debug("reject local:'%s' remote:'%s'", con->local.node_string,  con->remote.node_string);

	struct incident *i = incident_new("dionaea.connection.tcp.reject");
	incident_value_con_set(i, "con", con);
	incident_report(i);
	connection_free_cb(g_dionaea->loop, &con->events.free, 0);
}

static bool pcap_config(struct lcfgx_tree_node *node)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	pcap_runtime.config = node;
	return true;
}

static bool pcap_prepare(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);

	pcap_runtime.devices = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	char errbuf[PCAP_ERRBUF_SIZE];

	g_message("pcap version %s",pcap_lib_version());

	pcap_if_t *alldevsp = NULL;

	if( pcap_findalldevs(&alldevsp,errbuf) == -1 )
	{
		g_warning("pcap_findalldevs failed %s",errbuf);
		return false;
	}

	struct lcfgx_tree_node *v;
	for( v = pcap_runtime.config->value.elements; v != NULL; v = v->next )
	{
		g_debug("node %s", (char *)v->key);
		struct pcap_device *dev = malloc(sizeof(struct pcap_device));
		dev->name = g_strdup(v->key);

		if( (dev->pcap = pcap_open_live(dev->name, 80, 1, 50, errbuf)) == NULL )
		{
			g_warning("Could not open raw listener on device %s '%s'", dev->name, errbuf);
			return false;
		}

		GString *bpf_filter_string = g_string_new("");
		GString *bpf_filter_string_addition = g_string_new("");

		for( pcap_if_t *alldev = alldevsp;alldev != NULL;alldev = alldev->next )
		{
			if( strcmp(dev->name, "any") != 0 && strcmp(alldev->name, dev->name) != 0 )
				continue;

			if( alldev->name )
				g_debug("name %s",alldev->name);
			if( alldev->description )
				g_debug("\tdescription %s",alldev->description);

			g_debug("\tflags %i",alldev->flags);


			char name[128];

			for( pcap_addr_t *addr = alldev->addresses; addr != NULL; addr = addr->next )
			{
				if( addr->addr == NULL )
					continue;

				switch( addr->addr->sa_family )
				{
				case PF_INET:
				case PF_INET6:
					g_debug("\t\t%s", (addr->addr->sa_family == PF_INET) ? "PF_INET" : "PF_INET6");
					if( addr->addr )
						g_debug("\t\t\taddr %s", inet_ntop(addr->addr->sa_family, ADDROFFSET(addr->addr), name, 128));
					if( addr->netmask )
						g_debug("\t\t\tnetmask %s", inet_ntop(addr->addr->sa_family, ADDROFFSET(addr->addr), name, 128));
					if( addr->broadaddr )
						g_debug("\t\t\tbcast %s", inet_ntop(addr->addr->sa_family, ADDROFFSET(addr->addr), name, 128));
					if( addr->dstaddr )
						g_debug("\t\t\tdstaddr %s", inet_ntop(addr->addr->sa_family, ADDROFFSET(addr->addr), name, 128));
					g_string_append_printf(bpf_filter_string_addition, "or src host %s ", inet_ntop(addr->addr->sa_family, ADDROFFSET(addr->addr), name, 128));
					break;

				default:
					break;
					g_debug("\t\tAF_ not supported %i",addr->addr->sa_family);

				}
				g_debug(" ");
			}
		}
#undef ADDROFFSET

#ifdef HAVE_PCAP_IPV6_TCP
		g_string_append_printf(bpf_filter_string, "%s", bpf_filter_string_addition->str+3);
#else
		g_string_append_printf(bpf_filter_string, "tcp[tcpflags] & tcp-rst != 0 and tcp[4:4] = 0  and ( %s )", bpf_filter_string_addition->str+3);
#endif

		struct bpf_program filter;

		g_debug("bpf filter %s: %s",dev->name, bpf_filter_string->str);

		if( pcap_compile(dev->pcap, &filter,  (char *)bpf_filter_string->str, 0, 0) == -1 )
		{
			g_warning("pcap_compile failed for %s: %s.", dev->name, pcap_geterr(dev->pcap));
			return false;
		}

		if( pcap_setfilter(dev->pcap, &filter) == -1 )
		{
			g_warning("pcap_setfilter failed for %s: %s", dev->name, pcap_geterr(dev->pcap));
			return false;
		}
		if( pcap_setnonblock(dev->pcap, 1, errbuf) == -1 )
		{
			g_warning("pcap_setnonblock failed for %s: %s.", dev->name, errbuf);
			return false;
		}

		int i;
		i = pcap_getnonblock(dev->pcap, errbuf);

		if( i == -1 )
		{
			g_warning("pcap_getnonblock failed for %s: %s", dev->name, errbuf);
			return false;
		} else
		{
			g_debug("pcap_device %s is nonblocking ", dev->name);
		}

		dev->linktype = pcap_datalink(dev->pcap);

		switch( dev->linktype )
		{
		case DLT_EN10MB:
#ifdef DLT_LINUX_SLL
		case DLT_LINUX_SLL:
#endif
			g_debug("linktype %s %s",
				   pcap_datalink_val_to_name(dev->linktype),
				   pcap_datalink_val_to_description(dev->linktype));
			break;

		default:
			g_warning("linktype  %s %s not supported",
					  pcap_datalink_val_to_name(dev->linktype),
					  pcap_datalink_val_to_description(dev->linktype));
			return false;
		}
		g_string_free(bpf_filter_string, TRUE);
		g_string_free(bpf_filter_string_addition, TRUE);
		g_hash_table_insert(pcap_runtime.devices, dev->name, dev);
	}
	pcap_freealldevs(alldevsp);

	return true;
}

static bool pcap_new(struct dionaea *d)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, pcap_runtime.devices);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		struct pcap_device *dev = value;
		g_debug("starting pcap_device %s %p", (char *)key, dev);
		ev_io_init(&dev->io_in, pcap_io_in_cb, pcap_get_selectable_fd(dev->pcap), EV_READ);
		ev_io_start(g_dionaea->loop, &dev->io_in);
	}
	return true;
}

static bool pcap_free(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, pcap_runtime.devices);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		struct pcap_device *dev = value;
		g_debug("stopping %s", (char *)key);
		ev_io_stop(g_dionaea->loop, &dev->io_in);
	}

	g_hash_table_destroy(pcap_runtime.devices);
	return true;
}

static bool pcap_hup(struct lcfgx_tree_node *node)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

struct module_api *module_init(struct dionaea *d)
{
	g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, d);
	static struct module_api pcap_api =
	{
		.config = &pcap_config,
		.prepare = &pcap_prepare,
		.new = &pcap_new,
		.free = &pcap_free,
		.hup = &pcap_hup
	};

    return &pcap_api;
}

