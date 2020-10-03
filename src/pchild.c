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
#include <unistd.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/uio.h>


#include <glib.h>

#include "config.h"
#include "dionaea.h"
#include "pchild.h"
#include "log.h"

#define D_LOG_DOMAIN "pchild"

struct pchild *pchild_new()
{
	struct pchild *p = g_malloc0(sizeof(struct pchild));
	g_mutex_init(&p->mutex);
	return p;
}

void pchild_run(int fd)
{
	pchild_cmd cmd;
	uintptr_t x;
	while( recv(fd, &x, sizeof(uintptr_t), 0) ==  sizeof(uintptr_t) )
	{
		cmd = (pchild_cmd)x;
		cmd(fd);
	}
	close(fd);
	exit(0);
}

bool pchild_init(void)
{
	int     pair[2], fd;
	pid_t   pid;


	if( socketpair(PF_UNIX, SOCK_STREAM, 0, pair) < 0 )
	{
		return false;
	}


	if( (pid = fork()) < 0 )
	{
		return false;
	}

	if( pid != 0 )
	{
		g_dionaea->pchild->fd = pair[0];
		close(pair[1]);
		return true;
	}

	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	setsid();

	/* We're the backend */
	close(pair[0]);
	fd = pair[1];

	pchild_run(fd);
	return 0;
}

int pchild_recv_bind(int fd)
{
#ifdef HAVE_LINUX_SOCKIOS_H
	struct sockaddr_storage sa;
	socklen_t   sizeof_sa;
	char data[1024];
	struct msghdr   msg;
	struct cmsghdr  *cmsg;
	struct iovec    iov[2];

	memset(&msg, 0, sizeof(msg));
	iov[0].iov_base   = &sa;
	iov[0].iov_len    = sizeof(struct sockaddr_storage);
	iov[1].iov_base   = &sizeof_sa;
	iov[1].iov_len    = sizeof(socklen_t);

	msg.msg_iov    = iov;
	msg.msg_iovlen = 2;
	msg.msg_control = data;
	msg.msg_controllen = 1024;

	if( recvmsg(fd, &msg, 0) > 0 )
	{
		cmsg = CMSG_FIRSTHDR(&msg);
		while( cmsg != NULL )
		{
			if( cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type  == SCM_RIGHTS )
			{
				int bind_fd = *(int *) CMSG_DATA(cmsg);
				int ret = bind(bind_fd, (struct sockaddr *)&sa, sizeof_sa);
				int err = errno;
				close(bind_fd);
				if( write(fd, &ret, sizeof(int)) < 0 )
				{
					perror("write");
				}
				if( ret != 0 )
				{
					if( write(fd, &err, sizeof(int)) < 0 )
					{
						perror("write");
					}
				}
			}
			cmsg = CMSG_NXTHDR(&msg, cmsg);
		}
	}
#endif
	return 0;
}

int pchild_sent_bind(int sx, struct sockaddr *s, socklen_t size)
{
#ifdef HAVE_LINUX_SOCKIOS_H
	g_mutex_lock(&g_dionaea->pchild->mutex);
	uintptr_t cmd = (uintptr_t)pchild_recv_bind;
	if( send(g_dionaea->pchild->fd, &cmd, sizeof(uintptr_t), 0) != sizeof(uintptr_t) )
	{
		g_error("pchild seems to be dead!");
	}


	char data[1024];
	struct msghdr   msg;
	struct cmsghdr  *cmsg;
	struct iovec    iov[2];

	struct sockaddr_storage sa;
	memset(&sa, 0, sizeof(struct sockaddr_storage));
	memcpy(&sa, s, size);

	socklen_t sizeof_sa = sizeof(struct sockaddr_storage);


	memset(&msg, 0, sizeof(msg));
	iov[0].iov_base   = &sa;
	iov[0].iov_len    = sizeof(struct sockaddr_storage);
	iov[1].iov_base   = &sizeof_sa;
	iov[1].iov_len    = sizeof(socklen_t);

	msg.msg_iov    = iov;
	msg.msg_iovlen = 2;
	msg.msg_control = data;
	msg.msg_controllen = 1024;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(cmsg) = sx;

	msg.msg_controllen = cmsg->cmsg_len;

	g_debug("sending msg to child to bind port ...");
	if( sendmsg(g_dionaea->pchild->fd, &msg, 0) < 0 )
	{
		g_critical("sendmsg failed (%s)", strerror(errno));
		g_mutex_unlock(&g_dionaea->pchild->mutex);
		return -1;
	}

	int ret=0;
	recv(g_dionaea->pchild->fd, &ret, sizeof(int), 0);
	g_mutex_unlock(&g_dionaea->pchild->mutex);
	if( ret != 0 )
	{
		recv(g_dionaea->pchild->fd, &ret, sizeof(int), 0);
		g_critical("bind failed (%s)", strerror(ret));
		errno = ret;
		return -1;
	} else
	{
		g_debug("child could bind the socket!");
		errno = 0;
		return ret;
	}
#else
	return bind(sx,s,size);
#endif
	return 0;
}
