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

#ifndef HAVE_UTIL_H
#define HAVE_UTIL_H

#include <stdbool.h>
#include <stdint.h>


#define ADDROFFSET(x) \
	((((struct sockaddr *)(x))->sa_family == AF_INET) ?  \
		((void *)(x) + offsetof(struct sockaddr_in, sin_addr)) :  \
		(((struct sockaddr *)(x))->sa_family == AF_INET6) ? \
			((void *)(x) + offsetof(struct sockaddr_in6, sin6_addr)) : \
			NULL)


bool sockaddr_storage_from(struct sockaddr_storage *ss, int family, void *host, uint16_t port);
bool parse_addr(char const * const addr, char const * const iface, uint16_t const port, struct sockaddr_storage * const sa, int * const socket_domain, socklen_t * const sizeof_sa);

int ipv6_addr_linklocal(struct in6_addr const * const a);
int ipv6_addr_v4mapped(struct in6_addr const * const a);

struct tempfile
{
	int fd;
	FILE *fh;
	char *path;
};

struct tempfile *tempfile_new(char *path, char *prefix);
struct tempfile *tempdownload_new(char *prefix);
void tempfile_close(struct tempfile *tf);
void tempfile_unlink(struct tempfile *tf);
void tempfile_free(struct tempfile *tf);

#endif
