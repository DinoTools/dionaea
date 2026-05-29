/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>


#include <sys/time.h>
#include <time.h>

#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#include <glib.h>

#define D_LOG_DOMAIN "connection"

#define CL g_dionaea->loop

#include "dionaea.h"
#include "connection.h"
#include "util.h"
#include "log.h"
#include "incident.h"
#include "processor.h"


/*
 *
 * connection udp
 *
 */


ssize_t recvfromto(int sockfd, void *buf, size_t len, int flags,
				 const struct sockaddr *fromaddr, socklen_t *fromlen,
				 const struct sockaddr *toaddr, socklen_t *tolen)
{
	struct iovec iov[1];
#if defined(IPV6_PKTINFO)
	char cmsg[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#else
	char cmsg[CMSG_SPACE(64)];
#endif
	struct cmsghdr *cmsgptr;
	struct msghdr msg;
	ssize_t rlen;

	iov[0].iov_base = buf;
	iov[0].iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)fromaddr;
	msg.msg_namelen = *fromlen;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsg;
	msg.msg_controllen = sizeof(cmsg);

	if( (rlen = recvmsg(sockfd, &msg, 0)) == -1 )
		return -1;


	for( cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr) )
	{
#ifdef SOL_IP
		if( fromaddr->sa_family == PF_INET && cmsgptr->cmsg_level == SOL_IP && cmsgptr->cmsg_type == IP_PKTINFO )
		{ /* IPv4 */
			if( *fromlen < sizeof(struct sockaddr_in) )
			{
				errno = EINVAL;
				return -1;
			}
			void *addr = ADDROFFSET(toaddr);
			void *t = &((struct in_pktinfo *)(CMSG_DATA(cmsgptr)))->ipi_addr;
			memcpy(addr, t, sizeof(struct in_addr));
			break;
		}else
#endif
#if defined(SOL_IPV6) && defined(IPV6_PKTINFO)
		if( fromaddr->sa_family == PF_INET6 && cmsgptr->cmsg_level == SOL_IPV6 && cmsgptr->cmsg_type == IPV6_PKTINFO )
		{ /* IPv6 */
			if( *fromlen < sizeof(struct sockaddr_in6) )
			{
				errno = EINVAL;
				return -1;
			}
			void *addr = ADDROFFSET(toaddr);
			void *t = &((struct in6_pktinfo *)(CMSG_DATA(cmsgptr)))->ipi6_addr;
			memcpy(addr, t, sizeof(struct in6_addr));
			break;
		}
#endif
	}
	return rlen;
}

ssize_t sendtofrom(int fd, void *buf, size_t len, int flags, struct sockaddr *to, socklen_t tolen, struct sockaddr *from, socklen_t fromlen)
{
	struct iovec iov[1];
	struct msghdr msg;

	struct cmsghdr* cmsgptr;
	cmsgptr = NULL;

	iov[0].iov_base = buf;
	iov[0].iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *) to;
	msg.msg_namelen = tolen;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = flags;



	if( from->sa_family == PF_INET )
	{ /* IPv4 */
#if defined(SOL_IP) && defined(IP_PKTINFO)
		char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
		memset(cbuf, 0, sizeof(cbuf));
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);

		cmsgptr = CMSG_FIRSTHDR(&msg);
		cmsgptr->cmsg_level = SOL_IP;
		cmsgptr->cmsg_type = IP_PKTINFO;
		cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		memcpy(&((struct in_pktinfo *)(CMSG_DATA(cmsgptr)))->ipi_spec_dst.s_addr, ADDROFFSET(from),  sizeof(struct in_addr) );
		return sendmsg(fd, &msg, 0);
#endif
	}else
	if( from->sa_family == PF_INET6 )
	{ /* IPv6 */
#if defined(SOL_IPV6) && defined(IPV6_PKTINFO)
		char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
		memset(cbuf, 0, sizeof(cbuf));
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);

		cmsgptr = CMSG_FIRSTHDR(&msg);
		cmsgptr->cmsg_level = SOL_IPV6;
		cmsgptr->cmsg_type = IPV6_PKTINFO;
		cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		memcpy(&((struct in6_pktinfo *)(CMSG_DATA(cmsgptr)))->ipi6_addr, ADDROFFSET(from),  sizeof(struct in6_addr) );
		return sendmsg(fd, &msg, 0);
#endif
	}else
	{
		errno = EINVAL;
		return -1;
	}
	/* if your operating system lacks everything ... */
	g_warning("Your operating system lacks SOL_IP(V6) / IP(V6)_PKTINFO");
	return sendto(fd, buf, len, flags, to, tolen);
}

void connection_udp_io_in_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_IN(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	socklen_t sizeof_sa = sizeof(struct sockaddr_storage);
	socklen_t sizeof_sb = sizeof(struct sockaddr_storage);
	unsigned char buf[64*1024];
	memset(buf, 0, 64*1024);
	int ret;
	while( (ret = recvfromto(con->socket, buf, 64*1024, 0,  (struct sockaddr *)&con->remote.addr, &sizeof_sa, (struct sockaddr *)&con->local.addr, &sizeof_sb)) > 0 )
	{
		node_info_set(&con->remote, &con->remote.addr);
		node_info_set(&con->local, &con->local.addr);


		struct connection *peer;
		switch( con->type )
		{
		case connection_type_listen:
			/* we are a server -> find the peer */
			if( (peer = g_hash_table_lookup(con->transport.udp.type.server.peers, con)) == NULL )
			{ /* no peer? create a new one */
				peer = connection_new(connection_transport_udp);
				peer->transport.udp.type.client.parent = con;
				peer->type = connection_type_accept;
				peer->state = connection_state_established;
				memcpy(&peer->local.addr, &con->local.addr, sizeof(struct sockaddr_storage));
				memcpy(&peer->remote.addr, &con->remote.addr, sizeof(struct sockaddr_storage));
				node_info_set(&peer->remote, &peer->remote.addr);
				node_info_set(&peer->local, &peer->local.addr);
				g_debug("new udp peer %s %s", peer->local.node_string, peer->remote.node_string);
				peer->transport.udp.type.client.parent = con;
				connection_protocol_set(peer, &peer->transport.udp.type.client.parent->protocol);

				ev_timer_init(&peer->events.idle_timeout, connection_idle_timeout_cb, 0. ,con->events.idle_timeout.repeat);
				ev_timer_init(&peer->events.sustain_timeout, connection_sustain_timeout_cb, 0. ,con->events.sustain_timeout.repeat);
				peer->protocol.ctx = peer->transport.udp.type.client.parent->protocol.ctx_new(peer);

				// teach new connection about parent
				if( peer->transport.udp.type.client.parent->protocol.origin != NULL )
					peer->transport.udp.type.client.parent->protocol.origin(peer, peer->transport.udp.type.client.parent);

				connection_established(peer);

				g_hash_table_insert(con->transport.udp.type.server.peers, peer, peer);
			}
			g_debug("%s -> %s %i bytes", peer->remote.node_string, peer->local.node_string, ret);
			break;
		case connection_type_bind:
		case connection_type_connect:
			peer = con;
			break;
		default:
			return;
		}

		if( peer->type == connection_type_accept && peer->processor_data != NULL )
			processors_io_in(peer, buf, ret);

		peer->protocol.io_in(peer, peer->protocol.ctx, buf, ret);
	}

	if( ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK )
	{
		g_warning("connection error %i %s", ret, strerror(errno));
	}
}

void _connection_send_packets(struct connection *con, int fd, GList **packets)
{
	GList *elem;

	while( (elem = g_list_first(*packets)) != NULL )
	{
		struct udp_packet *packet = elem->data;
		socklen_t size = ((struct sockaddr *)&packet->to)->sa_family == PF_INET ? sizeof(struct sockaddr_in) :
						 ((struct sockaddr *)&packet->to)->sa_family == PF_INET6 ? sizeof(struct sockaddr_in6) :
						 ((struct sockaddr *)&packet->to)->sa_family == AF_UNIX ? sizeof(struct sockaddr_un) : -1;

		int ret;
		/*
		 * for whatever reason
		 * * send
		 *   - works on udp sockets which were connect()'ed before (linux)
		 *   - works not on udp sockets which were bind()'ed before (linux)
		 * * sendto
		 *   - does not work on connect()'ed sockets on (openbsd)
		 *
		 * and as we can't distinguish from bound/unbound connected/unconnected sockets at this point
		 * udp does not work for openbsd
		 */
		if( con->type == connection_type_accept && con->processor_data != NULL )
			processors_io_out(con, packet->data->str, packet->data->len);

		ret = sendtofrom(fd, packet->data->str, packet->data->len, 0, (struct sockaddr *)&packet->to, size, (struct sockaddr *)&packet->from, size);

		if( ret == -1 )
		{
			if( errno == EAGAIN )
			{
				break;
			} else
			{
				g_debug("domain %i size %i", ((struct sockaddr *)&packet->to)->sa_family, size);
				g_warning("sendtofrom failed %s",  strerror(errno));
				g_string_free(packet->data, TRUE);
				g_free(packet);
				*packets = g_list_delete_link(*packets, elem);
			}
			break;
		} else
		if( ret == packet->data->len )
		{
			g_string_free(packet->data, TRUE);
			g_free(packet);
			*packets = g_list_delete_link(*packets, elem);
		} else
		{
			g_warning("sendtofrom failed %s",  strerror(errno));
			g_string_free(packet->data, TRUE);
			g_free(packet);
			*packets = g_list_delete_link(*packets, elem);
			break;
		}
	}
}

void connection_udp_io_out_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_OUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	int fd = 0;
	switch( con->type )
	{
	case connection_type_connect:
	case connection_type_bind:
		fd = con->socket;
		break;
	case connection_type_accept:
		fd = con->transport.udp.type.client.parent->socket;
		break;
	default:
		g_warning("Invalid connection type!");
	}

	_connection_send_packets(con, fd, &con->transport.udp.io_out);

	if( g_list_length(con->transport.udp.io_out) > 0 )
	{
		if( !ev_is_active(&con->events.io_out) )
		{
			ev_io_init(&con->events.io_out, connection_udp_io_out_cb, con->socket, EV_WRITE);
			ev_io_start(EV_A_ &con->events.io_out);
		}
	} else
	{
		ev_io_stop(EV_A_ &con->events.io_out);
	}
	if( ev_is_active(&con->events.idle_timeout) )
		ev_timer_again(CL, &con->events.idle_timeout);
}

void connection_udp_disconnect(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	connection_set_state(con, connection_state_close);
	switch( con->type )
	{
	case connection_type_accept:
		g_hash_table_remove(con->transport.udp.type.client.parent->transport.udp.type.server.peers, con);
	case connection_type_connect:
	case connection_type_bind:
		con->protocol.disconnect(con, con->protocol.ctx);
		break;
	case connection_type_listen:
		{
			GHashTableIter iter;
			gpointer key, value;
			g_hash_table_iter_init (&iter, con->transport.udp.type.server.peers);
			while( g_hash_table_iter_next (&iter, &key, &value) )
			{
				struct connection *peer = value;
				connection_udp_disconnect(peer);
				g_hash_table_iter_init (&iter, con->transport.udp.type.server.peers);
			}
		}
		break;
	default:
		break;
	}

	connection_disconnect(con);
	connection_free(con);
}
