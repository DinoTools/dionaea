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

#include <glib.h>

#include "util.h"
#include "log.h"

#define D_LOG_DOMAIN "util"


bool parse_addr(const char *addr, const char *iface, uint16_t port, struct sockaddr_storage *sa, int *socket_domain, socklen_t *sizeof_sa)
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
		if ( iface != NULL && strlen(iface) != 0 )
		{
			si6->sin6_scope_id = if_nametoindex(iface);
			if ( si6->sin6_scope_id == 0 )
			{
				g_warning("invalid iface '%s' %x\n", iface, *iface);
				return false;
			}
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

	if ( strstr(addr, "/") != NULL )
	{
		if(strlen(addr) > sizeof(struct sockaddr_storage) - sizeof(unsigned short))
		{
			g_warning("unix path would not fit into buffer\n");
			return false;
		}
		su->sun_family = PF_UNIX;
		strncpy(su->sun_path, addr, 107);
		*sizeof_sa = sizeof(su->sun_family) + strlen(su->sun_path);
		*socket_domain = PF_UNIX;
		return true;
	}

	return false;
}

