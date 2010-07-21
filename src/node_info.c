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

#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <glib.h>

#include "node_info.h"
#include "util.h"
#include "log.h"

#define D_LOG_DOMAIN "node_info"


bool node_info_set(struct node_info *node, struct sockaddr_storage *sa)
{
	void *addroff = NULL;
//	socklen_t sizeof_sa = sizeof(struct sockaddr_storage);

	if( sa->ss_family == PF_INET6 )
	{
		struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)&node->addr;
		node->port = si6->sin6_port;
		addroff = &si6->sin6_addr;
	} else
		if( sa->ss_family == PF_INET )
	{
		struct sockaddr_in *si = (struct sockaddr_in *)&node->addr;
		node->port = si->sin_port;
		addroff = &si->sin_addr;
	} else
	{
		if( sa->ss_family == PF_UNIX )
		{
			struct sockaddr_un *su = (struct sockaddr_un *)&node->addr;
			addroff = &su->sun_path;
		} else

			return false;
	}

	if( sa->ss_family == PF_UNIX )
	{
		snprintf(node->ip_string, 108, "un://%s", (char *)addroff);
	} else
		if( inet_ntop(sa->ss_family, addroff, (void *)&node->ip_string, INET6_ADDRSTRLEN) == NULL )
	{
		g_warning("inet_ntop failed (%s)", strerror(errno));
		return false;
	}

	if( sa->ss_family == PF_INET6 )
	{
		if( ipv6_addr_linklocal(&((struct sockaddr_in6 *)sa)->sin6_addr) )
		{
			snprintf(node->node_string,NODE_STRLEN,"[%s%s%s]:%i",node->ip_string, 
					 node->iface_scope[0]?"%":"",node->iface_scope[0]?node->iface_scope:"", 
					 ntohs(node->port));
		} else
		{
			snprintf(node->node_string,NODE_STRLEN,"[%s]:%i",node->ip_string, 
					 ntohs(node->port));
		}
	} else
		if( sa->ss_family == PF_INET )
	{
		snprintf(node->node_string,NODE_STRLEN,"%s:%i",node->ip_string, ntohs(node->port));
	} else
		if( sa->ss_family == PF_UNIX )
	{
		snprintf(node->node_string,NODE_STRLEN,"%s",node->ip_string);
	}

	snprintf(node->port_string,7,"%i", ntohs(node->port));

	return true;
}

void node_info_add_addr(struct node_info *node, const char *addr)
{
	node->dns.resolved_addresses = g_realloc(node->dns.resolved_addresses,( node->dns.resolved_address_count + 2) *(sizeof(char *)));
	node->dns.resolved_addresses[node->dns.resolved_address_count] = g_strdup(addr);
	node->dns.resolved_address_count++;
}


const char *node_info_get_next_addr(struct node_info *node)
{
	if( node->dns.resolved_address_count == node->dns.current_address )
		return NULL;
	else
		return node->dns.resolved_addresses[node->dns.current_address++];
}

void node_info_addr_clear(struct node_info *node)
{
	int i;
	for( i=0;i<node->dns.resolved_address_count; i++ )
	{
		g_free(node->dns.resolved_addresses[i]);
	}
	g_free(node->dns.resolved_addresses);
	node->dns.resolved_addresses = NULL;
	node->dns.resolved_address_count = 0;
	node->dns.current_address=0;
	if( node->hostname != NULL )
		g_free(node->hostname);
}

char *node_info_get_ip_string(struct node_info *node)
{
	return node->ip_string;
}

char *node_info_get_port_string(struct node_info *node)
{
	return node->port_string;
}

void node_info_set_port(struct node_info *node, uint16_t port)
{
	socklen_t sizeof_sa;
	node->port = htons(port);
	if( !parse_addr(node->ip_string, node->iface_scope, ntohs(node->port), &node->addr, &node->domain, &sizeof_sa) )
		g_debug("error parsing new addr ...\n");
	else
	{
		node_info_set(node, &node->addr);
		g_debug("new node info %s\n", node->node_string);
	}
}

void node_info_set_addr(struct node_info *node, char *addr)
{
	socklen_t sizeof_sa;
	if( !parse_addr(addr, node->iface_scope, ntohs(node->port), &node->addr, &node->domain, &sizeof_sa) )
		g_debug("error parsing new addr ...\n");
	else
	{
		node_info_set(node, &node->addr);
		g_debug("new node info %s\n", node->node_string);
	}
}
