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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <errno.h>

#include <glib.h>


#include "config.h"
#include "dionaea.h"
#include "util.h"
#include "log.h"

#define D_LOG_DOMAIN "util"

void *ADDROFFSET(const void *x)
{
	if( x == NULL )
		return NULL;

	if( ((struct sockaddr *)(x))->sa_family == AF_INET )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in, sin_addr));
	}else
	if( ((struct sockaddr *)(x))->sa_family == AF_INET6 )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in6, sin6_addr));
	}

	return NULL;
}

unsigned int ADDRSIZE(const void *x)
{
	if( x == NULL )
		return 0;
	if( ((struct sockaddr *)(x))->sa_family == AF_INET )
	{
		return sizeof(struct sockaddr_in);
	}else
	if( ((struct sockaddr *)(x))->sa_family == AF_INET6 )
	{
		return sizeof(struct sockaddr_in6);
	}
	return 0;
}

void *PORTOFFSET(const void *x)
{
	if( x == NULL )
		return NULL;

	if( ((struct sockaddr *)(x))->sa_family == AF_INET )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in, sin_port));
	}else
	if( ((struct sockaddr *)(x))->sa_family == AF_INET6 )
	{
		return ((void *)(x) + offsetof(struct sockaddr_in6, sin6_port));
	}

	return NULL;
}

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
	return((a->s6_addr32[0] & htonl(0xFFC00000)) == htonl(0xFE800000));
}

int ipv6_addr_v4mapped(struct in6_addr const * const a)
{
	return((a->s6_addr32[0] | a->s6_addr32[1]) == 0 &&
		   a->s6_addr32[2] == htonl(0x0000ffff));
}

void ipv6_v6_map_v4(struct sockaddr_in6 *from, struct sockaddr_in *to)
{
	to->sin_family = PF_INET;
	to->sin_port = from->sin6_port;
	to->sin_addr.s_addr = from->sin6_addr.s6_addr32[3];
}

void ipv6_v4_map_v6(struct sockaddr_in *from, struct sockaddr_in6 *to)
{
	to->sin6_family = PF_INET6;
	to->sin6_port = from->sin_port;
	to->sin6_addr.s6_addr32[3] = from->sin_addr.s_addr;
	to->sin6_addr.s6_addr32[2] = htonl(0x0000ffff);
	to->sin6_addr.s6_addr32[1] = 0;
	to->sin6_addr.s6_addr32[0] = 0;
}

bool sockaddr_storage_from(struct sockaddr_storage *ss, int family, void *host, uint16_t port)
{
	ss->ss_family = family;
	if( family == PF_INET )
	{
		struct sockaddr_in *in4 = (void *)ss;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, host, sizeof(struct in_addr));
		return true;
	}else
	if( family == PF_INET6 )
	{
		struct sockaddr_in6 *in6 = (void *)ss;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, host, sizeof(struct in6_addr));
		return true;
	}
	return false;
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

	if( validaddr > 0 )
	{
		si6->sin6_family = PF_INET6;
		si6->sin6_port = htons(port);
		*sizeof_sa = sizeof(struct sockaddr_in6);
		*socket_domain = PF_INET6;
		if( ipv6_addr_linklocal(&si6->sin6_addr) )
		{
			if( iface == NULL || strlen(iface) == 0 || if_nametoindex(iface) == 0 )
			{
				g_warning("Link Local address %s without valid scope id?", addr);
				return false;
			}
			si6->sin6_scope_id = if_nametoindex(iface);
		}
		return true;
	}

	validaddr = inet_pton(PF_INET, addr, &si->sin_addr);
	if( validaddr > 0 )
	{
		si->sin_family = PF_INET;
		si->sin_port = htons(port);

#ifdef CAN_BIND_IPV4_MAPPED_IPV6
		ipv6_v4_map_v6(si, si6);
		*sizeof_sa = sizeof(struct sockaddr_in6);
		*socket_domain = PF_INET6;
#else
		*sizeof_sa = sizeof(struct sockaddr_in);
		*socket_domain = PF_INET;
#endif
		return true;
	}

	static const char *un_prefix = "un://";
	if( strncmp(addr, un_prefix,  strlen(un_prefix)) == 0 )
	{
		const char *p = addr + strlen(un_prefix);
		if( strlen(p) > sizeof(struct sockaddr_storage) - sizeof(unsigned short) )
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
	if( tf->fd == -1 )
	{
		g_warning("could not open path %s (%s)", path, strerror(errno));
		g_free(tf);
		return NULL;
	}

	tf->fh = fdopen(tf->fd, "w+");
	return tf;
}

struct tempfile *tempdownload_new(char *prefix)
{
	/* ToDo: replace 
  struct lcfgx_tree_node *node;
	if( lcfgx_get_string(g_dionaea->config.root, &node, "downloads.dir") != LCFGX_PATH_FOUND_TYPE_OK )
	{
		g_warning("missing downloads.dir in dionaea.conf");
		return NULL;
	}
	return tempfile_new((char *)node->value.string.data, prefix);
  */
	return tempfile_new((char *)"/tmp", prefix);
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

void tempfile_unlink(struct tempfile *tf)
{
	unlink(tf->path);
}


void tempfile_free(struct tempfile *tf)
{
	if( tf->path )
		g_free(tf->path);
	g_free(tf);
}
