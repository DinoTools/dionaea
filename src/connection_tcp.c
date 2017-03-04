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
 * connection tcp
 *
 */


void connection_tcp_accept_cb (EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_IN(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	while( 1 )
	{

		struct sockaddr_storage sa;
		socklen_t sizeof_sa = sizeof(struct sockaddr_storage);

		int accepted_socket = accept(con->socket, (struct sockaddr *)&sa, &sizeof_sa);

		if( accepted_socket == -1 )
		{
			if( errno != EAGAIN && errno != EWOULDBLOCK )
			{
				g_warning("accept() failed errno=%i (%s)",  errno, strerror(errno));
			}
			break;
		}

		if( accepted_socket > g_dionaea->limits.fds * 70/100 )
		{
			g_warning("Running out of fds, closing connection (fd %i limit %i applied limit %i)",
					  accepted_socket,
					  g_dionaea->limits.fds,
					  g_dionaea->limits.fds * 70/100);
			close(accepted_socket);
			continue;
		}

		struct connection *accepted = connection_new(connection_transport_tcp);
		connection_set_type(accepted, connection_type_accept);
		accepted->socket = accepted_socket;

		if( connection_node_set_local(accepted) == false || connection_node_set_remote(accepted) == false )
		{
			g_warning("accepting connection failed, closing connection");
			close(accepted->socket);
			accepted->socket = -1;
			// Free connection information but don't report
			// incident.
			connection_free_cb(loop, &accepted->events.free, 0, false);
			continue;
		}

		g_debug("accept() %i local:'%s' remote:'%s'", accepted->socket, accepted->local.node_string,  accepted->remote.node_string);

		connection_set_nonblocking(accepted);

		accepted->data = con->data;

		// set protocol for accepted connection
		connection_protocol_set(accepted, &con->protocol);

		// copy connect timeout to new connection
		ev_timer_init(&accepted->events.idle_timeout, connection_idle_timeout_cb, 0. ,con->events.idle_timeout.repeat);


		// create protocol specific data
		accepted->protocol.ctx = con->protocol.ctx_new(accepted);

		// teach new connection about parent
		if( con->protocol.origin != NULL )
			con->protocol.origin(accepted, con);

//		stream_processors_init(accepted);
		accepted->stats.io_in.throttle.max_bytes_per_second = con->stats.io_in.throttle.max_bytes_per_second;
		accepted->stats.io_out.throttle.max_bytes_per_second = con->stats.io_out.throttle.max_bytes_per_second;
		connection_established(accepted);

		struct incident *i;
		i = incident_new("dionaea.connection.tcp.accept");
		incident_value_con_set(i, "con", accepted);
		incident_report(i);
		incident_free(i);

		i = incident_new("dionaea.connection.link");
		incident_value_con_set(i, "parent", con);
		incident_value_con_set(i, "child", accepted);
		incident_report(i);
		incident_free(i);
	}

	if( ev_is_active(&con->events.listen_timeout) )
	{
		ev_clear_pending(EV_A_ &con->events.listen_timeout);
		ev_timer_again(EV_A_  &con->events.listen_timeout);
	}
}

void connection_tcp_connecting_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_OUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	ev_timer_stop(EV_A_ &con->events.connecting_timeout);

	int socket_error = 0;
	int error_size = sizeof(socket_error);


	int ret = getsockopt(con->socket, SOL_SOCKET, SO_ERROR, &socket_error,(socklen_t *)&error_size);

	if( ret != 0 || socket_error != 0 )
	{
		errno = socket_error;
//		perror("getsockopt");
//		con->protocol.connect_error(con);
//    	connection_tcp_disconnect(EV_A_ con);

		ev_io_stop(EV_A_ &con->events.io_out);
		close(con->socket);
		con->socket = -1;
		connection_connect_next_addr(con);
		return;
	}

	connection_set_state(con, connection_state_established);

	connection_node_set_local(con);
	connection_node_set_remote(con);

	g_debug("connection %s -> %s", con->local.node_string, con->remote.node_string);

	connection_established(con);
}

void connection_tcp_io_in_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_IN(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	int size, buf_size;

	/* determine how many bytes we can recv */
#ifdef SIOCINQ
	if( ioctl(con->socket, SIOCINQ, &buf_size) != 0 )
		buf_size=1024;
#else
	buf_size = 16*1024;
#endif

	/* always increase by one so we get EOF and data in one callback */
	buf_size++;

	g_debug("can recv %i bytes", buf_size);

	int recv_throttle = connection_throttle(con, &con->stats.io_in.throttle);
	int recv_size = MIN(buf_size, recv_throttle);

	g_debug("io_in: throttle can %i want %i", buf_size, recv_size);

	if( recv_size == 0 )
		return;

	unsigned char buf[buf_size];

	GString *new_in = g_string_sized_new(buf_size);

	while( (size = recv(con->socket, buf, recv_size, 0)) > 0 )
	{
		g_string_append_len(new_in, (gchar *)buf, size);
		recv_size -= size;
		if( recv_size <= 0 )
			break;
	}
	int lerrno = errno;

	if( con->processor_data != NULL && new_in->len > 0 )
	{
		processors_io_in(con, new_in->str, new_in->len);
	}

	connection_throttle_update(con, &con->stats.io_in.throttle, new_in->len);
	// append
	g_string_append_len(con->transport.tcp.io_in, new_in->str, new_in->len);

	if( size==0 )//&& size != MIN(buf_size, recv_throttle) )
	{
		g_debug("remote closed connection");
		if( new_in->len > 0 )
			con->protocol.io_in(con, con->protocol.ctx, (unsigned char *)con->transport.tcp.io_in->str, con->transport.tcp.io_in->len);

		/*
		 * the protocol may have disabled the watcher for io_in already
		 * if so, do not deliver the disconnect
		 */
		if( ev_is_active(w) )
			connection_tcp_disconnect(con);
	} else
		if( (size == -1 && lerrno == EAGAIN) ||
			size == MIN(buf_size, recv_throttle) ||
			recv_size <= 0 )
	{
		g_debug("EAGAIN");
		if( ev_is_active(&con->events.idle_timeout) )
			ev_timer_again(EV_A_  &con->events.idle_timeout);

		int consumed = 0;

		if( new_in->len > 0 )
			consumed = con->protocol.io_in(con, con->protocol.ctx, (unsigned char *)con->transport.tcp.io_in->str, con->transport.tcp.io_in->len);

		g_string_erase(con->transport.tcp.io_in, 0, consumed);

		if( con->transport.tcp.io_out->len > 0 && !ev_is_active(&con->events.io_out) )
			ev_io_start(EV_A_ &con->events.io_out);

	} else
	{
		g_warning("recv failed size %i recv_size %i (%s)", size, recv_size, strerror(lerrno));
		connection_tcp_disconnect(con);
	}
	g_string_free(new_in, TRUE);

	if( connection_stats_accounting_limit_exceeded(&con->stats.io_in) )
	{
		g_debug("con %p io_in limit exceeded", con);
		connection_tcp_disconnect(con);
	}
}

void connection_tcp_io_out_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_OUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	int send_throttle = connection_throttle(con, &con->stats.io_out.throttle);
	int send_size = MIN(con->transport.tcp.io_out->len, send_throttle);


	if( send_size == 0 )
		return;


	int size = send(con->socket, con->transport.tcp.io_out->str, send_size, 0);

	if( ev_is_active(&con->events.idle_timeout) )
		ev_timer_again(EV_A_  &con->events.idle_timeout);

	if( size > 0 )
	{
		connection_throttle_update(con, &con->stats.io_out.throttle, size);

		if( con->processor_data != NULL && size > 0 )
		{
			processors_io_out(con, con->transport.tcp.io_out->str, size);
		}

//		bistream_data_add(&con->bistream, bistream_out, con->transport.tcp.io_out->str, size);
		g_string_erase(con->transport.tcp.io_out, 0 , size);
		if( con->transport.tcp.io_out->len == 0 )
		{
			if( ev_is_active(&con->events.io_out) )
				ev_io_stop(EV_A_ w);
			if( con->state == connection_state_close )
				connection_tcp_disconnect(con);
			else
				if( con->protocol.io_out != NULL )
			{ /* avoid recursion at any costs */
				connection_flag_set(con, connection_busy_sending);
				con->protocol.io_out(con, con->protocol.ctx);
				connection_flag_unset(con, connection_busy_sending);
				if( con->transport.tcp.io_out->len > 0 )
					ev_io_start(CL, &con->events.io_out);
			}
		} else
		{
			if( !ev_is_active(&con->events.io_out) )
				ev_io_start(EV_A_ w);
		}
	} else
		if( size == -1 )
	{
		if( errno == EAGAIN || errno == EWOULDBLOCK )
		{
			if( !ev_is_active(&con->events.io_out) )
				ev_io_start(CL, &con->events.io_out);
		} else
			if( revents != 0 )
			connection_tcp_disconnect(con);
	}

	if( connection_stats_accounting_limit_exceeded(&con->stats.io_out) )
	{
		g_debug("con %p io_out limit exceeded", con);
		connection_tcp_disconnect(con);
	}

}

void connection_tcp_disconnect(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	enum connection_state state = con->state;
	connection_set_state(con, connection_state_close);
	connection_disconnect(con);

	g_string_erase(con->transport.tcp.io_in, 0, -1);
	g_string_erase(con->transport.tcp.io_out, 0, -1);

	if( con->protocol.disconnect != NULL &&
		(state != connection_state_none &&
		 state != connection_state_connecting ) )
	{
		bool reconnect = con->protocol.disconnect(con, con->protocol.ctx);
		g_debug("reconnect is %i", reconnect);
		if( reconnect == true && con->type == connection_type_connect )
		{
			connection_reconnect(con);
			return;
		}
	}
	connection_free(con);
}
