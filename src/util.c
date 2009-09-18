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


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <stdio.h>

#include <unistd.h>

#include <glib.h>

#include <lcfg/lcfg.h>
#include <lcfgx/lcfgx_tree.h>



#include "dionaea.h"
#include "util.h"
#include "log.h"

#define D_LOG_DOMAIN "util"


int ipv6_addr_any(struct in6_addr const * const a)
{
	return((a->s6_addr32[0] | a->s6_addr32[1] | 
			a->s6_addr32[2] | a->s6_addr32[3] ) == 0); 
}

int ipv6_addr_loopback(struct in6_addr const * const a)
{
	return((a->s6_addr32[0] | a->s6_addr32[1] |
			a->s6_addr32[2] | (a->s6_addr32[3] ^ htonl(1))) == 0);
}

int ipv6_addr_linklocal(struct in6_addr const * const a)
{
	return ((a->s6_addr32[0] & htonl(0xFFC00000)) == htonl(0xFE800000));
}

int ipv6_addr_v4mapped(struct in6_addr const * const a)
{
	return ((a->s6_addr32[0] | a->s6_addr32[1]) == 0 &&
		 a->s6_addr32[2] == htonl(0x0000ffff));
}

bool parse_addr(char const * const addr, char const * const iface, uint16_t const port, struct sockaddr_storage * const sa, int * const socket_domain, socklen_t * const sizeof_sa)
{
	struct sockaddr_in6 *si6;
	struct sockaddr_in *si;
	struct sockaddr_un *su;

	si6 = (struct sockaddr_in6 *)sa;
	si  = (struct sockaddr_in  *)sa;
	su  = (struct sockaddr_un  *)sa;


	int validaddr = inet_pton(PF_INET6, addr, &si6->sin6_addr);

	if ( validaddr > 0 )
	{
		si6->sin6_family = PF_INET6;
		si6->sin6_port = htons(port);
		*sizeof_sa = sizeof(struct sockaddr_in6);
		*socket_domain = PF_INET6;
		if( ipv6_addr_linklocal(&si6->sin6_addr) )
		{
			if ( iface == NULL || strlen(iface) == 0 || if_nametoindex(iface) == 0)
			{
				g_warning("Link Local address %s without valid scope id?", addr);
				return false;
			}
			si6->sin6_scope_id = if_nametoindex(iface);
		}
		return true;
	}

#ifdef HAVE_V4_MAPPED_ADDRESS
	validaddr = inet_pton(PF_INET, addr, &si6->sin6_addr.__in6_u.__u6_addr32[3]);
	if ( validaddr > 0 )
	{
		si6->sin6_family = PF_INET6;
		si6->sin6_port = htons(port);
		*sizeof_sa = sizeof(struct sockaddr_in6);
		*socket_domain = PF_INET6;
		static const unsigned char V4mappedprefix[12]={0,0,0,0,0,0,0,0,0,0,0xff,0xff};
		for (int i=0;i<12;i++ )
			si6->sin6_addr.s6_addr[i] = V4mappedprefix[i];
		return true;
	}
#else 
	validaddr = inet_pton(PF_INET, addr, &si->sin_addr);
	if ( validaddr > 0 )
	{
		si->sin_family = PF_INET;
		si->sin_port = htons(port);
		*sizeof_sa = sizeof(struct sockaddr_in);
		*socket_domain = PF_INET;
		return true;
	}
#endif

	static const char *un_prefix = "un://";
	if ( strncmp(addr, un_prefix,  strlen(un_prefix)) == 0 )
	{
		const char *p = addr + strlen(un_prefix);
		if( strlen(p) > sizeof(struct sockaddr_storage) - sizeof(unsigned short))
		{
			g_warning("unix path would not fit into buffer\n");
			return false;
		}
		su->sun_family = PF_UNIX;
		strncpy(su->sun_path, p, 107);
		*sizeof_sa = sizeof(su->sun_family) + strlen(su->sun_path);
		*socket_domain = PF_UNIX;
		return true;
	}

	return false;
}

struct tempfile *tempfile_new(char *path, char *prefix)
{
	struct tempfile *tf = g_malloc0(sizeof(struct tempfile));

	if( prefix )
		tf->path = g_strdup_printf("%s/%sXXXXXX", path, prefix);
	else
		tf->path = g_strdup_printf("%s/XXXXXX", path);
	tf->fd = mkstemp(tf->path);
	tf->fh = fdopen(tf->fd, "w+");
	return tf;
}

struct tempfile *tempdownload_new(char *prefix)
{
	struct lcfgx_tree_node *node;
	if( lcfgx_get_string(g_dionaea->config.root, &node, "downloads.dir") != LCFGX_PATH_FOUND_TYPE_OK )
	{
		g_warning("missing downloads.dir in dionaea.conf");
		return NULL;
	}
	return tempfile_new((char *)node->value.string.data, prefix);
}

void tempfile_close(struct tempfile *tf)
{
	if( tf->fh != NULL )
		fclose(tf->fh);

	if( tf->fd != -1 )
		close(tf->fd);

	tf->fd = -1;
	tf->fh = NULL;
}

void tempfile_free(struct tempfile *tf)
{
	g_free(tf);
}
