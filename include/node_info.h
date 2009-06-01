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
#include <stdint.h>
#include <netinet/in.h>

#define PORT_STRLEN 5
#define IFNAM_STRLEN 16
#define INET_STRLEN INET6_ADDRSTRLEN 

#define NODE_STRLEN 1 + INET_STRLEN + 1 + 1 + IFNAM_STRLEN + 1  + 1 + PORT_STRLEN

struct node_info
{
	struct sockaddr_storage addr;
	int domain; // socket domain
	char ip_string[INET_STRLEN+1];
	char port_string[PORT_STRLEN+1];
	uint16_t port;
	char node_string[NODE_STRLEN+1];

	char iface_scope[IFNAM_STRLEN+1]; // required for ipv6 scope id
	char *hostname;


	struct
	{
		char **resolved_addresses;
		uint8_t resolved_address_count;
		uint8_t current_address;

		struct dns_query *a;
		struct dns_query *aaaa;
	} dns;
};

bool node_info_set(struct node_info *node, struct sockaddr_storage *sa);
void node_info_add_addr(struct node_info *pi, const char *addr);
char *node_info_get_ip_string(struct node_info *node);
char *node_info_get_port_string(struct node_info *node);
void node_info_set_port(struct node_info *node, uint16_t port);
void node_info_addr_clear(struct node_info *node);
const char *node_info_get_next_addr(struct node_info *node);
