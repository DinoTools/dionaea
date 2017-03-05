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

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#include <udns.h>
#include <glib.h>

#define D_LOG_DOMAIN "connection"

#define CL g_dionaea->loop

#include "dionaea.h"
#include "connection.h"
#include "dns.h"
#include "util.h"
#include "log.h"
#include "pchild.h"
#include "incident.h"
#include "processor.h"


int ssl_tmp_keys_init(struct connection *con);


/**
 * create a new connection of a given type
 *
 * @param type   udp,tcp,tls
 *
 * @return ptr to the new connection
 */
struct connection *connection_new(enum connection_transport type)
{
	struct connection *con = g_malloc0(sizeof(struct connection));

	con->trans = type;

	con->socket = -1;
	gettimeofday(&con->stats.start, NULL);
	switch( type )
	{
	case connection_transport_tcp:
		con->transport.tcp.io_in = g_string_new("");
		con->transport.tcp.io_out = g_string_new("");
		break;

	case connection_transport_tls:
		con->transport.tls.meth = SSLv23_method();
		con->transport.tls.ctx = SSL_CTX_new((SSL_METHOD *)con->transport.tls.meth);
		SSL_CTX_set_session_cache_mode(con->transport.tls.ctx, SSL_SESS_CACHE_OFF);
		con->transport.tls.io_in = g_string_new("");
		con->transport.tls.io_out = g_string_new("");
		con->transport.tls.io_out_again = g_string_new("");
//		SSL_CTX_set_timeout(con->transport.ssl.ctx, 60);
		break;
	case connection_transport_dtls:
		con->transport.tls.meth = DTLSv1_method();
		con->transport.tls.ctx = SSL_CTX_new((SSL_METHOD *)con->transport.tls.meth);
		break;
	case connection_transport_udp:
		break;

	case connection_transport_io:
		break;
	}

	con->stats.io_out.throttle.last_throttle = ev_now(CL);
	con->stats.io_out.throttle.interval_start = ev_now(CL);
	con->stats.io_in.throttle.last_throttle = ev_now(CL);
	con->stats.io_in.throttle.interval_start = ev_now(CL);

	refcount_init(&con->refcount);
	con->events.close_timeout.repeat = 10.0;
	con->events.connecting_timeout.repeat = 5.0;
	con->events.handshake_timeout.repeat = 10.0;
	con->events.free.repeat = 0.5;
	return con;
}

bool connection_node_set_local(struct connection *con)
{
	socklen_t sizeof_sa = sizeof(struct sockaddr_storage);
	if( getsockname(con->socket, (struct sockaddr *)&con->local.addr, &sizeof_sa) != 0 )
	{
		g_warning("getsockname failed (%s)", strerror(errno));
		return false;
	}
	return node_info_set(&con->local, &con->local.addr);
}

bool connection_node_set_remote(struct connection *con)
{
	socklen_t sizeof_sa = sizeof(struct sockaddr_storage);
	if( getpeername(con->socket, (struct sockaddr *)&con->remote.addr, &sizeof_sa) != 0 )
	{
		g_warning("getpeername failed (%s)", strerror(errno));
		return false;
	}
	return node_info_set(&con->remote, &con->remote.addr);
}

bool connection_socket(struct connection *con, int family, int type, int protocol)
{
	if( con->socket != -1 )
		close(con->socket);

	if ((con->socket = socket(family, type, protocol)) == -1 )
	{
		g_warning("socket() failed for con %p %i (%s)", con, errno, strerror(errno));
		con->protocol.error(con, ECONMANY);
		connection_free(con);
		return false;
	}

	return true;
}


/**
 * used to bind the connection to an address/port
 *
 * @param con the connection
 *
 * @return true on success
 */
bool bind_local(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	struct sockaddr_storage sa;
	memset(&sa, 0,  sizeof(struct sockaddr_storage));

	socklen_t sizeof_sa = 0;
	int socket_domain = 0;

	if( con->local.hostname == NULL && ntohs(con->local.port) == 0 )
		return true;

	if( con->local.hostname == NULL )
		return false;

	if( !parse_addr(con->local.hostname, con->local.iface_scope, ntohs(con->local.port), &sa, &socket_domain, &sizeof_sa) )
		return false;

	g_debug("%s socket %i %s:%i", __PRETTY_FUNCTION__, con->socket, con->local.hostname, ntohs(con->local.port));

//	memcpy(&con->src.addr,  &sa, sizeof(struct sockaddr_storage));

	int val=1;

	switch( con->trans )
	{
	case connection_transport_tls:
	case connection_transport_tcp:
		setsockopt(con->socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
//		setsockopt(con->socket, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
		if( pchild_sent_bind(con->socket, (struct sockaddr *)&sa, sizeof_sa) != 0 )
		{
			g_warning("Could not bind %s:%i (%s)", con->local.hostname, ntohs(con->local.port), strerror(errno));
			close(con->socket);
			con->socket = -1;
			return false;
		}

		// fill src node
		connection_node_set_local(con);

		g_debug("ip '%s' node '%s'", con->local.ip_string, con->local.node_string);

//		connection_set_nonblocking(con);
		return true;

		break;

	case connection_transport_dtls:
	case connection_transport_udp:
		if( pchild_sent_bind(con->socket, (struct sockaddr *)&sa, sizeof_sa) != 0 )
		{
			g_warning("Could not bind %s:%i (%s)", con->local.hostname, ntohs(con->local.port), strerror(errno));
			close(con->socket);
			con->socket = -1;
			return false;
		}
		return true;
		break;
	case connection_transport_io:
		break;

	}
	return false;
}

/**
 * bind the connection to a given address/port - not yet!
 * If the connection is meant to be used
 * to connect to a domain with multiple A/AAAA records,
 * we have to bind for each connect try.
 * Therefore we delay the bind, the real binding is in
 * @see connection_listen and @see connection_connect_next_addr
 * @param con
 * @param addr
 * @param port
 * @param iface_scope
 *
 * @return
 */
bool connection_bind(struct connection *con, const char *addr, uint16_t port, const char *iface_scope)
{
	g_debug("%s con %p addr %s port %i iface %s", __PRETTY_FUNCTION__, con, addr, port, iface_scope);
	struct sockaddr_storage sa;
	memset(&sa, 0,  sizeof(struct sockaddr_storage));

	socklen_t sizeof_sa = 0;
	int socket_domain = 0;

	char *laddr = (char *)addr;
	if( laddr == NULL )
		laddr = "0.0.0.0";

	con->local.port = htons(port);
	if( con->local.hostname != NULL )
		g_free(con->local.hostname);
	con->local.hostname = g_strdup(laddr);
	if( iface_scope )
		snprintf(con->local.iface_scope, sizeof(con->local.iface_scope), "%s", iface_scope);


	if( !parse_addr(con->local.hostname, con->local.iface_scope, ntohs(con->local.port), &con->local.addr, &socket_domain, &sizeof_sa) )
		return false;

	con->local.domain = socket_domain;

	switch( con->trans )
	{
	case connection_transport_udp:
	case connection_transport_dtls:
		con->type = connection_type_bind;
		if( con->socket == -1 )
			if( connection_socket(con,  socket_domain, SOCK_DGRAM, IPPROTO_UDP) == false )
				return false;
//		setsockopt(con->socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
//		setsockopt(con->socket, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
		if( bind_local(con) != true )
		{
			g_warning("Could not bind %s:%i (%s)", con->local.hostname, ntohs(con->local.port), strerror(errno));
			if( port != 0 && errno == EADDRINUSE )
			{
				g_warning("Could not bind %s:%i (%s)", con->local.hostname, ntohs(con->local.port), strerror(errno));
				return false;
			}
			return false;
		}

		// fill src node
		connection_node_set_local(con);

		g_debug("ip '%s' node '%s'", con->local.ip_string, con->local.node_string);


		{
			int sockopt;
			sockopt = 1;
#ifdef SOL_IP
			if( socket_domain == PF_INET )
			{
#ifdef IP_PKTINFO
				if( setsockopt(con->socket, SOL_IP, IP_PKTINFO, &sockopt, sizeof(sockopt)) != 0 )
					g_warning("con %p setsockopt fail domain %i level %i optname %i %s", con, socket_domain, SOL_IP, IP_PKTINFO, strerror(errno));
#else
					g_warning("your operating system lacks IP_PKTINFO - if you got multiple ip addresses better turn off udp services");
#endif
			}else
#endif
#ifdef SOL_IPV6
			if( socket_domain == PF_INET6 )
			{ /* sometimes it is better if you have a choice ...
			   * I just hope the cmsg type stays IPV6_PKTINFO
			   */

				int r = -1; errno = ENOPROTOOPT;
#ifdef IPV6_RECVPKTINFO
				r = setsockopt(con->socket, SOL_IPV6, IPV6_RECVPKTINFO, &sockopt, sizeof(sockopt));
#endif
#ifdef IPV6_2292PKTINFO
				if( r < 0 && errno == ENOPROTOOPT )
					r = setsockopt(con->socket, SOL_IPV6, IPV6_2292PKTINFO, &sockopt, sizeof(sockopt));
#endif
				if( r < 0 && errno == ENOPROTOOPT )
					r = setsockopt(con->socket, SOL_IPV6, IPV6_PKTINFO, &sockopt, sizeof(sockopt));

				if( r < 0 )
					g_warning("con %p setsockopt fail %s", con, strerror(errno));
			}
#endif
		}

		connection_set_nonblocking(con);
		if( con->trans == connection_transport_udp )
			ev_io_init(&con->events.io_in, connection_udp_io_in_cb, con->socket, EV_READ);
		else
			ev_io_init(&con->events.io_in, connection_dtls_io_in_cb, con->socket, EV_READ);

		if( port != 0 )
			ev_io_start(CL, &con->events.io_in);
		return true;
		break;

	case connection_transport_io:
		break;
	case connection_transport_tcp:
	case connection_transport_tls:
		return true;
		break;
	}

	return false;
}

bool connection_listen(struct connection *con, int len)
{
	GError *error = NULL;
	const char *cert_filename = NULL;
	const char *key_filename = NULL;

	g_debug("%s con %p len %i", __PRETTY_FUNCTION__, con, len);

	switch( con->trans )
	{
	case connection_transport_tcp:
		con->type = connection_type_listen;
		if( con->socket == -1 )
			if( connection_socket(con, con->local.domain, SOCK_STREAM, 0) == false )
				return false;

		if( bind_local(con) != true )
			return false;

		if( listen(con->socket, len) != 0 )
		{
			close(con->socket);
			g_warning("Could not listen %s:%i (%s)", con->local.hostname, ntohs(con->local.port), strerror(errno));
			return false;
		}
		connection_set_nonblocking(con);
		ev_io_init(&con->events.io_in, connection_tcp_accept_cb, con->socket, EV_READ);
		ev_set_priority(&con->events.io_in, EV_MAXPRI);
		ev_io_start(CL, &con->events.io_in);

		struct incident *i = incident_new("dionaea.connection.tcp.listen");
		incident_value_con_set(i, "con", con);
		incident_report(i);
		incident_free(i);
		break;

	case connection_transport_tls:
		con->type = connection_type_listen;
		if( con->socket == -1 )
			if( connection_socket(con, con->local.domain, SOCK_STREAM, 0) == false )
				return false;

		if( bind_local(con) != true )
			return false;

		if( listen(con->socket, len) != 0 )
		{
			close(con->socket);
			g_warning("Could not listen %s:%i (%s)", con->local.hostname, ntohs(con->local.port), strerror(errno));
			return false;
		}
		connection_set_nonblocking(con);

		cert_filename = g_key_file_get_string(g_dionaea->config, "dionaea", "ssl.default.cert", &error);
		g_clear_error(&error);
		if (cert_filename != NULL) {
			key_filename = g_key_file_get_string(g_dionaea->config, "dionaea", "ssl.default.key", &error);
			g_clear_error(&error);
		}
		if(cert_filename != NULL && key_filename != NULL) {
			g_info("Use '%s' as key and '%s' as cert file", key_filename, cert_filename);
			connection_tls_set_certificate(con, cert_filename, SSL_FILETYPE_PEM);
			connection_tls_set_key(con, key_filename, SSL_FILETYPE_PEM);
		} else {
			connection_tls_mkcert(con);
		}
//		SSL_CTX_set_timeout(con->transport.ssl.ctx, 15);
		//ssl_tmp_keys_init(con);
		ev_set_priority(&con->events.io_in, EV_MAXPRI);
		ev_io_init(&con->events.io_in, connection_tls_accept_cb, con->socket, EV_READ);
		ev_io_start(CL, &con->events.io_in);
		break;

	case connection_transport_udp:
		con->type = connection_type_listen;
		con->transport.udp.type.server.peers = g_hash_table_new_full(connection_addrs_hash, connection_addrs_cmp, NULL, NULL);
		break;

	case connection_transport_dtls:
		con->type = connection_type_listen;
		con->transport.dtls.type.server.peers = g_hash_table_new_full(connection_addrs_hash, connection_addrs_cmp, NULL, NULL);
		connection_dtls_mkcert(con);
		RAND_bytes(con->transport.dtls.type.server.cookie_secret, DTLS_COOKIE_SECRET_LENGTH);
		SSL_CTX_set_cookie_generate_cb(con->transport.dtls.ctx, dtls_generate_cookie_cb);
		SSL_CTX_set_cookie_verify_cb(con->transport.dtls.ctx, dtls_verify_cookie_cb);
		break;

	case connection_transport_io:
		return false;
		break;
	}


	if( con->events.listen_timeout.repeat > 0. )
		ev_timer_again(CL, &con->events.listen_timeout);
	return true;
}

void connection_close(struct connection *con)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);

	if( connection_flag_isset(con, connection_busy_close) )
	{
		g_warning("con %p called close recursive!", con);
		return;
	}

	connection_flag_set(con, connection_busy_close);
	switch( con->trans )
	{
	case connection_transport_tcp:
		if( con->type == connection_type_listen )
		{
			connection_tcp_disconnect(con);
		} else
			if( con->type == connection_type_connect &&
				(con->state == connection_state_none || con->state == connection_state_connecting) )
		{
			connection_tcp_disconnect(con);
		} else
			if( (con->type == connection_type_connect || con->type == connection_type_accept) &&
				con->state == connection_state_established )
		{
			if( !ev_is_active(&con->events.close_timeout) )
			{
				ev_timer_init(&con->events.close_timeout, connection_close_timeout_cb, 0., con->events.close_timeout.repeat);
				ev_timer_again(CL, &con->events.close_timeout);
			}

			if( con->transport.tcp.io_out->len == 0 )
			{
				shutdown(con->socket, SHUT_RD);
				connection_set_state(con, connection_state_shutdown);
			} else
				if( con->transport.tcp.io_out->len != 0 )
			{
				connection_set_state(con, connection_state_close);
			}

		} else
			if( con->type == connection_type_connect && con->state == connection_state_resolve )
		{
			connection_dns_resolve_cancel(con);
			connection_tcp_disconnect(con);
		} else
			if( con->type == connection_type_accept && con->state == connection_state_none )
		{
			connection_tcp_disconnect(con);
		} else
		{
			g_critical("Invalid close on connection %p type %s state %s",
					   con,
					   connection_type_to_string(con->type),
					   connection_state_to_string(con->state));
//			connection_tcp_disconnect(con);
		}
		break;

	case connection_transport_tls:
		if( con->type == connection_type_listen )
		{
			connection_set_state(con, connection_state_close);
			connection_tls_disconnect(con);
		} else
			if( con->type == connection_type_connect  &&
				(con->state == connection_state_none || con->state == connection_state_connecting) )
		{
			connection_tls_disconnect(con);
		} else
			if( con->type == connection_type_connect && con->transport.tls.ssl == NULL )
		{
			if( con->state == connection_state_resolve )
				connection_dns_resolve_cancel(con);

			connection_set_state(con, connection_state_close);
			connection_tls_disconnect(con);
		} else
			if( ( con->type == connection_type_connect || con->type == connection_type_accept) )
		{
			if( con->state == connection_state_resolve )
			{
				connection_dns_resolve_cancel(con);
				connection_tls_disconnect(con);
			} else
				if( con->state == connection_state_established )
			{
				if( !ev_is_active(&con->events.close_timeout) )
				{
					ev_timer_init(&con->events.close_timeout, connection_close_timeout_cb, 0., con->events.close_timeout.repeat);
					ev_timer_again(CL, &con->events.close_timeout);
				}

				if( con->transport.tls.io_out->len == 0 && con->transport.tls.io_out_again->len == 0 )
				{
					connection_set_state(con, connection_state_shutdown);
					connection_tls_shutdown_cb(CL, &con->events.io_in, 0);
				} else
					if( con->transport.tls.io_out->len != 0 || con->transport.tls.io_out_again->len != 0 )
				{
					connection_set_state(con, connection_state_close);
				}
			} else
			{
				connection_tls_disconnect(con);
			}
		} else
		{
			g_critical("Invalid close on connection %p type %s state %s",
					   con,
					   connection_type_to_string(con->type),
					   connection_state_to_string(con->state));
			connection_tls_disconnect(con);
		}
		break;

	case connection_transport_udp:
		connection_set_state(con, connection_state_close);
		connection_udp_disconnect(con);
		break;
	case connection_transport_dtls:
		g_warning("FIXME");
		break;
	case connection_transport_io:
		break;
	}
	connection_flag_unset(con, connection_busy_close);
}


void connection_close_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_CLOSE_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	switch( con->trans )
	{
	case connection_transport_tcp:
		connection_tcp_disconnect(con);
		break;

	case connection_transport_tls:
		connection_tls_disconnect(con);
		break;

	default:
		break;
	}
}

/**
 * free the connection - not yet!
 * problem is simple, assume:
 *
 * class ABC(connection):
 * ....
 *     def io_in(self, data):
 * 	....
 * 	self.close()
 * 	return len(data)
 *
 * if closing a connection has the possibility
 * to free the connection directly, the python object 'looses' ground,
 * it got destroyed while in use.
 *
 * additionally, you may not want to delete the connection, even
 * if it was closed
 * if refcounts do not work, as you can't control the
 * (shell)code, set the free.repeat interval to 0.
 *
 * @see connection_free_cb
 *
 * @param con
 */
void connection_free(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	ev_timer_stop(CL, &con->events.free);
	if( con->events.free.repeat > 0. )
	{
		ev_timer_init(&con->events.free, connection_free_report_cb, 0., con->events.free.repeat);
		ev_timer_again(CL, &con->events.free);
	}
}

/**
 * we poll the connection to see if the refcount hit 0
 * so we can free it
 *
 * @param w
 * @param revents
 * @param report_incident Report an incident
 */
void connection_free_cb(EV_P_ struct ev_timer *w, int revents, bool report_incident)
{
	struct connection *con = CONOFF_FREE(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( ! refcount_is_zero(&con->refcount) )
		return;

	ev_timer_stop(EV_A_ w);

	if( report_incident == true && con->local.domain != AF_UNIX && con->remote.domain != AF_UNIX)
	{
		g_debug("AF %i %i con->local.domain", con->local.domain, con->remote.domain);
		struct incident *i = incident_new("dionaea.connection.free");
		incident_value_con_set(i, "con", con);
		incident_report(i);
		incident_free(i);
	}

	switch( con->trans )
	{
	case connection_transport_tcp:
		g_string_free(con->transport.tcp.io_in, TRUE);
		g_string_free(con->transport.tcp.io_out, TRUE);
		break;

	case connection_transport_tls:
		g_string_free(con->transport.tls.io_in, TRUE);
		g_string_free(con->transport.tls.io_out, TRUE);
		g_string_free(con->transport.tls.io_out_again, TRUE);

		if( con->transport.tls.ssl != NULL )
			SSL_free(con->transport.tls.ssl);
		con->transport.tls.ssl = NULL;

		if( con->type == connection_type_listen &&  con->transport.tls.ctx != NULL )
			SSL_CTX_free(con->transport.tls.ctx);
		con->transport.tls.ctx = NULL;
		break;

	default:
		break;
	}
	node_info_addr_clear(&con->local);
	node_info_addr_clear(&con->remote);

	if( con->protocol.name != NULL )
	{
		g_free(con->protocol.name);
	}

	if( con->protocol.ctx_free != NULL )
	{
		con->protocol.ctx_free(con->protocol.ctx);
	}

	if( con->processor_data != NULL )
	{
		processors_clear(con);
	}

	refcount_exit(&con->refcount);

	memset(con, 0, sizeof(struct connection));
	g_free(con);
}

/**
 * we poll the connection to see if the refcount hit 0
 * so we can free it
 *
 * @see connection_free_cb
 *
 * @param w
 * @param revents
 */
void connection_free_report_cb(EV_P_ struct ev_timer *w, int revents)
{
	connection_free_cb(loop, w, revents, true);
}

/**
 * Set the connection nonblocking
 * this code is not really portable
 * libcurl shows how to do better
 *
 * @param con    the connection
 *
 * @see connection_set_blocking
 */
void connection_set_nonblocking(struct connection *con)
{
	g_debug(__PRETTY_FUNCTION__);
	int flags = fcntl(con->socket, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(con->socket, F_SETFL, flags);
}

/**
 * Set the connection blocking again
 *
 * @param con    The connection
 */
void connection_set_blocking(struct connection *con)
{
	g_debug(__PRETTY_FUNCTION__);
	int flags = fcntl(con->socket, F_GETFL, 0);
	flags |= ~O_NONBLOCK;
	fcntl(con->socket, F_SETFL, flags);
}


/**
 * connect somewhere
 *
 * we can connect to hostnames and ips
 * As domains can have more than one A/AAAA record,
 * and we try to be fault tolerant, we do only complain
 * if we can not connect any of the resolved addresses
 *
 * @param con    The connection
 */
void connection_connect_next_addr(struct connection *con)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);

	const char *addr;
	while( (addr = node_info_get_next_addr(&con->remote)) != NULL )
	{
		g_debug("connecting %s", addr);
		struct sockaddr_storage sa;
		memset(&sa, 0,  sizeof(struct sockaddr_storage));
		socklen_t sizeof_sa = 0;
		int socket_domain = 0;

		if( !parse_addr(addr, con->remote.iface_scope, ntohs(con->remote.port), &sa, &socket_domain, &sizeof_sa) )
		{
			g_debug("could not parse addr");
			continue;
		}
		con->remote.domain = socket_domain;
		strncpy(con->remote.ip_string, addr, INET_STRLEN);

		if( con->local.hostname != NULL )
		{
			if( con->local.domain != socket_domain )
			{
				if( (con->local.domain == PF_INET6 && socket_domain == PF_INET && !ipv6_addr_v4mapped(&((struct sockaddr_in6 *)&con->local.addr)->sin6_addr)) ||
					(con->local.domain == PF_INET && socket_domain == PF_INET6 && !ipv6_addr_v4mapped(&((struct sockaddr_in6 *)&sa)->sin6_addr)) )
				{
					g_debug("remote will be unreachable due to different protocol versions (%i <-> %i) (%s <-> %s)",
							socket_domain, con->local.domain,
							addr, con->local.hostname);
					continue;
				}
			}
		}

		g_debug("connecting %s:%i", addr, ntohs(con->remote.port));
		int ret;
		switch( con->trans )
		{
		case connection_transport_tcp:
			// create protocol specific data
			if( con->protocol.ctx == NULL )
				con->protocol.ctx = con->protocol.ctx_new(con);

			g_debug("tcp");

			if( con->socket == -1 )
				if( connection_socket(con, socket_domain, SOCK_STREAM, 0) == false )
					return;

			if( bind_local(con) != true )
				continue;

			connection_set_nonblocking(con);
			ret = connect(con->socket, (struct sockaddr *)&sa, sizeof_sa);


			if( ret == -1 )
			{
				if( errno == EINPROGRESS )
				{
					// set connecting timer
					if( ev_is_active(&con->events.connecting_timeout) )
						ev_timer_stop(CL, &con->events.connecting_timeout);
					ev_timer_init(&con->events.connecting_timeout, connection_connecting_timeout_cb, 0., con->events.connecting_timeout.repeat);
					ev_timer_again(CL, &con->events.connecting_timeout);

					ev_io_init(&con->events.io_out, connection_tcp_connecting_cb, con->socket, EV_WRITE);
					ev_io_start(CL, &con->events.io_out);
					connection_set_state(con, connection_state_connecting);
					return;
				} else
					if( errno == EISCONN )
				{
					connection_established(con);
					return;
				} else
				{
					g_warning("Could not connect %s:%i (%s)", con->remote.hostname, ntohs(con->remote.port), strerror(errno));
					close(con->socket);
					con->socket = -1;
					continue;
				}
			} else
				if( ret == 0 )
			{
				connection_established(con);
				return;
			}

			break;


		case connection_transport_tls:
			// create protocol specific data
			if( con->protocol.ctx == NULL )
				con->protocol.ctx = con->protocol.ctx_new(con);

			g_debug("ssl");
			if( con->socket == -1 )
				if( connection_socket(con, socket_domain, SOCK_STREAM, 0) == false )
					return;

			connection_set_nonblocking(con);

			if( bind_local(con) != true )
				continue;

			ret = connect(con->socket, (struct sockaddr *)&sa, sizeof_sa);


			if( ret == -1 )
			{
				if( errno == EINPROGRESS )
				{
					// set connecting timer
					if( ev_is_active(&con->events.connecting_timeout) )
						ev_timer_stop(CL, &con->events.connecting_timeout);
					ev_timer_init(&con->events.connecting_timeout, connection_connecting_timeout_cb, 0., con->events.connecting_timeout.repeat);
					ev_timer_again(CL, &con->events.connecting_timeout);

					ev_io_init(&con->events.io_out, connection_tls_connecting_cb, con->socket, EV_WRITE);
					ev_io_start(CL, &con->events.io_out);
					connection_set_state(con, connection_state_connecting);
					return;
				} else
				{
					g_warning("Could not connect %s:%i (%s)", con->remote.hostname, ntohs(con->remote.port), strerror(errno));
					close(con->socket);
					con->socket = -1;
					continue;
				}
			} else
				if( ret == 0 )
			{
				connection_set_state(con, connection_state_handshake);
				SSL_set_connect_state(con->transport.tls.ssl);
				con->events.io_in.events = EV_READ;
				connection_tls_handshake_again_cb(CL, &con->events.io_in, 0);
				return;
			}

			break;


		case connection_transport_udp:
			// create protocol specific data
//			con->protocol.ctx = con->protocol.ctx_new(con);

			g_debug("udp");
			if( con->socket == -1 )
				if( connection_socket(con, socket_domain, SOCK_DGRAM, 0) == false )
					return;

//			if ( bind_local(con) != true )
//				continue;

			connection_set_nonblocking(con);
			if( con->remote.port != 0 )
			{
				ret = connect(con->socket, (struct sockaddr *)&sa, sizeof_sa);
				if( ret != 0 )
					g_warning("Could not connect %s:%i (%s)", con->remote.hostname, ntohs(con->remote.port), strerror(errno));
			}
			connection_node_set_local(con);
//			connection_node_set_remote(con);
			memcpy(&con->remote.addr, &sa, sizeof_sa);
			node_info_set(&con->remote, &con->remote.addr);
			g_debug("connected %s -> %s", con->local.node_string,  con->remote.node_string);

			if( con->state == connection_state_established )
				return;

			connection_established(con);
			return;
			break;

		case connection_transport_dtls:
			if( con->socket == -1 )
				if( connection_socket(con, socket_domain, SOCK_DGRAM, 0) == false )
					return;
			connection_set_nonblocking(con);
			ret = connect(con->socket, (struct sockaddr *)&sa, sizeof_sa);
			connection_node_set_local(con);
			memcpy(&con->remote.addr, &sa, sizeof_sa);

			con->type = connection_type_connect;
			con->state = connection_state_handshake;
			g_debug("new dtls con %s %s", con->local.node_string, con->remote.node_string);
			con->transport.dtls.ssl = SSL_new(con->transport.dtls.ctx);
			con->transport.dtls.reading = BIO_new(BIO_s_mem());
			con->transport.dtls.writing = BIO_new(BIO_s_mem());
			BIO_set_mem_eof_return(con->transport.dtls.reading, -1);
			BIO_set_mem_eof_return(con->transport.dtls.writing, -1);
			SSL_set_bio(con->transport.dtls.ssl, con->transport.dtls.reading, con->transport.dtls.writing);
			SSL_set_connect_state(con->transport.dtls.ssl);
			ev_io_init(&con->events.io_in, connection_dtls_io_in_cb, con->socket, EV_READ);
			ev_io_start(CL, &con->events.io_in);
			connection_dtls_connect_again(CL, &con->events.io_in, 0);
			return;
			break;

		case connection_transport_io:
			break;


		}
	}

	if( addr == NULL )
	{
		if( con->protocol.error(con, ECONUNREACH) == false )
			connection_close(con);
		else
			connection_reconnect(con);
	}
}

/**
 * connect somewhere
 *
 * @param con    The connection
 * @param addr   the address - ipv4/6 or domain
 * @param port   the port, hostbyteorder
 * @param iface_scope
 *               iface scope, required for ipv6 link local scope
 */
void connection_connect(struct connection* con, const char* addr, uint16_t port, const char *iface_scope)
{
	g_debug("%s con %p addr %s port %i iface %s",__PRETTY_FUNCTION__, con, addr, port, iface_scope);
	struct sockaddr_storage sa;
	memset(&sa, 0,  sizeof(struct sockaddr_storage));

	socklen_t sizeof_sa = 0;
	int socket_domain = 0;


	if( iface_scope )
		snprintf(con->remote.iface_scope, sizeof(con->remote.iface_scope), "%s", iface_scope);
	else
		con->remote.iface_scope[0] = '\0';

	con->remote.port = htons(port);

	connection_set_type(con, connection_type_connect);


	if( !parse_addr(addr, NULL, port, &sa, &socket_domain, &sizeof_sa) )
	{
		con->remote.hostname = g_strdup(addr);
		connection_connect_resolve(con);
	} else
	{
		node_info_add_addr(&con->remote, addr);
		connection_connect_next_addr(con);
	}
	if( socket_domain != PF_UNIX )
	{
		struct incident *i;
		if( con->trans == connection_transport_udp )
			i = incident_new("dionaea.connection.udp.connect");
		else if( con->trans == connection_transport_tcp )
			i = incident_new("dionaea.connection.tcp.connect");
		else if( con->trans == connection_transport_tls )
			i = incident_new("dionaea.connection.tls.connect");
		else if( con->trans == connection_transport_dtls )
			i = incident_new("dionaea.connection.dtls.connect");
		else
		{
			g_warning("unexpected ... ");
			return;
		}
		incident_value_con_set(i, "con", con);
		incident_report(i);
		incident_free(i);
	}
}

/**
 * Set the reconnect timeout
 *
 * Sometimes your connection may get disconnected,
 * the reconnect timeout allows specifying a delay
 * before trying to reconnect
 *
 * @param con    The connection
 * @param timeout_interval_ms
 *               the delay in seconds
 */
void connection_reconnect_timeout_set(struct connection *con, double timeout_interval_ms)
{
	ev_timer_init(&con->events.reconnect_timeout, connection_reconnect_timeout_cb, 0., timeout_interval_ms);
}

/**
 * Get the reconnect delay
 *
 * @param con    The connection
 *
 * @return the delay in seconds
 */
double connection_reconnect_timeout_get(struct connection *con)
{
	return con->events.reconnect_timeout.repeat;
}


/**
 * Reconnect a connection - with delay
 *
 * @param con The connection
 */
void connection_reconnect(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( con->socket > 0 )
	{
		close(con->socket);
		con->socket = -1;
	}

	connection_set_state(con, connection_state_reconnect);

	// reset local port
	if( con->local.hostname == NULL )
		con->local.port = 0;

	if( con->events.reconnect_timeout.repeat > 0. )
	{
		ev_timer_again(CL, &con->events.reconnect_timeout);
	} else
	{
		connection_reconnect_timeout_cb(CL, &con->events.reconnect_timeout, 0);
	}
}

void connection_reconnect_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_RECONNECT_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	struct sockaddr_storage sa;
	memset(&sa, 0,  sizeof(struct sockaddr_storage));

	socklen_t sizeof_sa = 0;
	int socket_domain = 0;


	ev_timer_stop(EV_A_ w);
	connection_set_state(con, connection_state_none);

	if( !parse_addr(con->remote.hostname, NULL, ntohs(con->remote.port), &sa, &socket_domain, &sizeof_sa) )
	{ /* domain */
		if( con->remote.dns.resolved_address_count == con->remote.dns.current_address )
		{ /* tried all resolved ips already */
			char *host = con->remote.hostname;
			con->remote.hostname = NULL;
			node_info_addr_clear(&con->remote);
			con->remote.hostname = host;
			connection_connect_resolve(con);
		} else
		{ /* try next */
			connection_connect_next_addr(con);
		}
	} else
	{ /* single ip(s) */
		if( con->remote.dns.resolved_address_count == con->remote.dns.current_address )
			/* reset and reconnect */
			con->remote.dns.current_address = 0;
		connection_connect_next_addr(con);
	}
}

/**
 * Stop all events for a connection
 *
 * @param con    The connection
 */
void connection_stop(struct connection *con)
{
	if( ev_is_active(&con->events.io_in) )
		ev_io_stop(CL, &con->events.io_in);

	if( ev_is_active(&con->events.io_out) )
		ev_io_stop(CL,  &con->events.io_out);

	if( ev_is_active(&con->events.listen_timeout) )
		ev_timer_stop(CL,  &con->events.listen_timeout);

	if( ev_is_active(&con->events.sustain_timeout) )
		ev_timer_stop(CL,  &con->events.sustain_timeout);

	if( ev_is_active(&con->events.idle_timeout) )
		ev_timer_stop(CL,  &con->events.idle_timeout);

	if( ev_is_active(&con->events.connecting_timeout) )
		ev_timer_stop(CL,  &con->events.connecting_timeout);

	if( ev_is_active(&con->events.throttle_io_out_timeout) )
		ev_timer_stop(CL,  &con->events.throttle_io_out_timeout);

	if( ev_is_active(&con->events.throttle_io_in_timeout) )
		ev_timer_stop(CL,  &con->events.throttle_io_in_timeout);

	if( ev_is_active(&con->events.close_timeout) )
		ev_timer_stop(CL,  &con->events.close_timeout);

	if( ev_is_active(&con->events.handshake_timeout) )
		ev_timer_stop(CL,  &con->events.handshake_timeout);

	if( ev_is_active(&con->events.reconnect_timeout) )
		ev_timer_stop(CL,  &con->events.reconnect_timeout);
}

/**
 * disconnects a connection
 * closes the socket and stops all events
 *
 * @param con    The connection
 * @see connection_stop
 */
void connection_disconnect(struct connection *con)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
//	bistream_debug(&con->bistream);

	connection_stop(con);

	if( con->socket != -1 )
		close(con->socket);
	con->socket = -1;
}

/**
 * Send something
 * does not block,	buffers the data to send, and sends it when possible
 *
 * @param con    The connection
 * @param data   The data to send
 * @param size   length of the data
 *
 * @see connection_send_string
 */
void connection_send(struct connection *con, const void *data, uint32_t size)
{
	g_debug("%s con %p data %p size %i",__PRETTY_FUNCTION__, con, data, size);

	switch( con->trans )
	{
	case connection_transport_tcp:
		g_string_append_len(con->transport.tcp.io_out, (gchar *)data, size);
		// flush as much as possible
		// revents=0 indicates send() might return 0
		// in this case we do not close & free the connection
		if( con->state == connection_state_established && !connection_flag_isset(con, connection_busy_sending) )
			connection_tcp_io_out_cb(g_dionaea->loop, &con->events.io_out, 0);
		break;

	case connection_transport_tls:
		g_string_append_len(con->transport.tls.io_out, (gchar *)data, size);
		// flush as much as possible
		if( con->state == connection_state_established && !connection_flag_isset(con, connection_busy_sending) )
			connection_tls_io_out_cb(g_dionaea->loop, &con->events.io_out, 0);
		break;


	case connection_transport_dtls:
		{
			int err = SSL_write(con->transport.dtls.ssl, data, size);
			g_debug("SSL_write %i", err);
			connection_dtls_error(con);
			connection_dtls_drain_bio(con);
		}
		break;
	case connection_transport_udp:
		{
			struct udp_packet *packet = g_malloc0(sizeof(struct udp_packet));
			packet->data = g_string_new_len(data, size);
			memcpy(&packet->to, &con->remote.addr, sizeof(struct sockaddr_storage));
			memcpy(&packet->from, &con->local.addr, sizeof(struct sockaddr_storage));
			con->transport.udp.io_out = g_list_append(con->transport.udp.io_out, packet);
			connection_udp_io_out_cb(g_dionaea->loop, &con->events.io_out, 0);
		}
		break;
	case connection_transport_io:
		break;
	}
}

/**
 * Send a zero terminated string
 *
 * @param con    The connection
 * @param str    The zero terminated string
 *
 * @see connection_send
 */
void connection_send_string(struct connection *con, const char *str)
{
	connection_send(con, str, strlen(str));
}

/**
 * set the connection idle timeout
 *
 * the connection idle time is reset if io occurs
 * if no io occurs for the specified timeout,
 * the protocols idle timeout callback is called
 *
 * @param con    The connection
 * @param timeout_interval_ms
 *               idle timeout in seconds
 */
void connection_idle_timeout_set(struct connection *con, double timeout_interval_ms)
{
	g_debug("%s %p %f", __PRETTY_FUNCTION__, con, timeout_interval_ms);

	if( ev_is_active(&con->events.idle_timeout) )
		ev_timer_stop(CL, &con->events.idle_timeout);

	switch( con->trans )
	{
	case connection_transport_tcp:
	case connection_transport_tls:
	case connection_transport_udp:
		ev_timer_init(&con->events.idle_timeout, connection_idle_timeout_cb, 0., timeout_interval_ms);
		break;

	default:
		break;
	}

	if( con->state == connection_state_established && timeout_interval_ms >= 0. )
		ev_timer_again(CL, &con->events.idle_timeout);
}

/**
 * Get the connections idle timeout
 *
 * @param con    The connection
 *
 * @return the connections idle timeout in seconds
 */
double connection_idle_timeout_get(struct connection *con)
{
	return con->events.idle_timeout.repeat;
}

void connection_idle_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_IDLE_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( con->protocol.idle_timeout == NULL || con->protocol.idle_timeout(con, con->protocol.ctx) == false )
	{
		switch( con->trans )
		{
		case connection_transport_tcp:
			connection_tcp_disconnect(con);
			break;

		case connection_transport_tls:
			connection_close(con);
			break;

		case connection_transport_udp:
			connection_udp_disconnect(con);
			break;

		case connection_transport_dtls:
		case connection_transport_io:
			break;
		}
	}
	else
	{
		if( con->state == connection_state_established )
			ev_timer_again(EV_A_ &con->events.idle_timeout);
	}
}

/**
 * Set the connections sustain timeout
 * The sustain timeout is the maximum
 * allowed session time for the connection
 *
 * If the connections duration is larger than the sustain timeout,
 * the protocols sustain timeout callback is called
 *
 * @param con    The connection
 * @param timeout_interval_ms
 */
void connection_sustain_timeout_set(struct connection *con, double timeout_interval_ms)
{
	g_debug("%s %p %f", __PRETTY_FUNCTION__, con, timeout_interval_ms);

	if( ev_is_active(&con->events.sustain_timeout) )
		ev_timer_stop(CL, &con->events.sustain_timeout);

	switch( con->trans )
	{
	case connection_transport_tcp:
	case connection_transport_tls:
	case connection_transport_udp:
		ev_timer_init(&con->events.sustain_timeout, connection_sustain_timeout_cb, 0., timeout_interval_ms);
		break;

	default:
		break;
	}

	if( con->state == connection_state_established && timeout_interval_ms >= 0. )
		ev_timer_again(CL, &con->events.sustain_timeout);
}

/**
 * Get the connections sustain timeout
 *
 * @param con    The connection
 *
 * @return the sustain timeout in seconds
 */
double connection_sustain_timeout_get(struct connection *con)
{
	return con->events.sustain_timeout.repeat;
}

void connection_sustain_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_SUSTAIN_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( con->protocol.sustain_timeout == NULL || con->protocol.sustain_timeout(con, con->protocol.ctx) == false )
	{
		switch( con->trans )
		{
		case connection_transport_tcp:
			connection_tcp_disconnect(con);
			break;
		case connection_transport_tls:
			connection_close(con);
			break;
		case connection_transport_udp:
			connection_udp_disconnect(con);
			break;
		case connection_transport_dtls:
		case connection_transport_io:
			break;
		}
	}
	else
	{
		if( con->state == connection_state_established )
		{
			ev_timer_again(EV_A_ &con->events.sustain_timeout);
		}
	}
}


/**
 * Set the connections listen timeout
 *
 * if a connection is listening,
 * you may want to close it automatically after a specified timeout
 * If the connections is listening for a longer period than specified here,
 * the protocols listen timeout callback is called
 *
 * @param con    The connection
 * @param timeout_interval_ms
 *               The timeout in seconds
 */
void connection_listen_timeout_set(struct connection *con, double timeout_interval_ms)
{
	g_debug("%s con %p timeout_interval_ms %f", __PRETTY_FUNCTION__, con, timeout_interval_ms);

	if( ev_is_active(&con->events.listen_timeout) )
		ev_timer_stop(CL, &con->events.listen_timeout);

	switch( con->trans )
	{
	case connection_transport_tcp:
	case connection_transport_tls:
		ev_timer_init(&con->events.listen_timeout, connection_listen_timeout_cb, 0., timeout_interval_ms);
		break;

	default:
		break;
	}

	if( con->type == connection_type_listen && timeout_interval_ms >= 0. )
		ev_timer_again(CL, &con->events.sustain_timeout);
}

void connection_listen_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_LISTEN_TIMEOUT(w);
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);

	switch( con->trans )
	{
	case connection_transport_tcp:
	case connection_transport_tls:
		if( con->protocol.listen_timeout  != NULL && con->protocol.listen_timeout(con, con->protocol.ctx) == true )
		{
			ev_timer_again(loop, &con->events.listen_timeout);
			return;
		}

		connection_set_state(con, connection_state_close);
		connection_disconnect(con);
		connection_free(con);
		break;
	case connection_transport_dtls:
	case connection_transport_udp:
	case connection_transport_io:
		break;
	}
}


/**
 * Get the connections listen timeout
 *
 * @param con    The connection
 *
 * @return the listen timeout in seconds
 */
double connection_listen_timeout_get(struct connection *con)
{
	return con->events.listen_timeout.repeat;
}


/**
 * Set the connections handshake timeout
 * TLS/SSL handshakes are special, they get a special timeout
 * If the handshake takes longer than specified here, the connection gets closed
 *
 * @param con    The connection
 * @param timeout_interval_ms
 */
void connection_handshake_timeout_set(struct connection *con, double timeout_interval_ms)
{
	g_debug(__PRETTY_FUNCTION__);
	if( ev_is_active(&con->events.handshake_timeout) )
		ev_timer_stop(CL, &con->events.handshake_timeout);

	switch( con->trans )
	{
	case connection_transport_tls:
		ev_timer_init(&con->events.handshake_timeout, NULL, 0., timeout_interval_ms);
		break;

	default:
		break;
	}

	if( con->state == connection_state_handshake && timeout_interval_ms > 0. )
		ev_timer_again(CL, &con->events.handshake_timeout);
}



/**
 * Get the connections handshake timeout
 *
 * @param con    The connection
 *
 * @return the handshake timeout in seconds
 */
double connection_handshake_timeout_get(struct connection *con)
{
	return con->events.handshake_timeout.repeat;
}


/**
 * Set the connections connecting timeout
 * Connecting some host may take some time, if you want to limit the time, set this timeout.
 *
 * @param con    The connection
 * @param timeout_interval_ms
 *               connecting timeout in seconds
 */
void connection_connecting_timeout_set(struct connection *con, double timeout_interval_ms)
{
	g_debug(__PRETTY_FUNCTION__);

	if( ev_is_active(&con->events.connecting_timeout) )
		ev_timer_stop(CL, &con->events.connecting_timeout);

	switch( con->trans )
	{
	case connection_transport_tcp:
	case connection_transport_tls:
		ev_timer_init(&con->events.connecting_timeout, connection_connecting_timeout_cb, 0., timeout_interval_ms);
		break;

	case connection_transport_dtls:
		g_warning("FIXME");
		break;
	case connection_transport_udp:
	case connection_transport_io:
		break;
	}

	if( con->state == connection_state_connecting && timeout_interval_ms > 0. )
		ev_timer_again(CL, &con->events.connecting_timeout);
}

void connection_connecting_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_CONNECTING_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	switch( con->trans )
	{
	case connection_transport_tcp:
	case connection_transport_tls:
		ev_io_stop(EV_A_ &con->events.io_out);
		ev_timer_stop(EV_A_ &con->events.connecting_timeout);
		close(con->socket);
		con->socket = -1;
		connection_connect_next_addr(con);
		break;
	case connection_transport_udp:
	case connection_transport_dtls:
	case connection_transport_io:
		break;
	}
}

/**
 * Get the connections connecting timeout
 *
 * @param con    The connection
 *
 * @return the connecting timeout in seconds
 */
double connection_connecting_timeout_get(struct connection *con)
{
	return con->events.connecting_timeout.repeat;
}



/**
 * The connection was established!
 * Great, inform the protcol about it and set the required event callbacks
 *
 * @param con    The connection
 */
void connection_established(struct connection *con)
{
	g_debug("%s %p", __PRETTY_FUNCTION__, con);
	ev_io_stop(CL, &con->events.io_in);
	ev_io_stop(CL, &con->events.io_out);

	if( con->socket != -1 )
	{
		connection_node_set_local(con);
		connection_node_set_remote(con);
	}

	connection_set_state(con, connection_state_established);

	switch( con->trans )
	{
	case connection_transport_tcp:
		ev_io_init(&con->events.io_in, connection_tcp_io_in_cb, con->socket, EV_READ);
		ev_io_init(&con->events.io_out, connection_tcp_io_out_cb, con->socket, EV_WRITE);

		// start only io_in
		ev_io_start(CL, &con->events.io_in);

		// inform protocol about new connection
		con->protocol.established(con);

		// timers
		if( con->events.idle_timeout.repeat >= 0. )
			ev_timer_again(CL,  &con->events.idle_timeout);

		if( con->events.sustain_timeout.repeat >= 0. )
			ev_timer_again(CL,  &con->events.sustain_timeout);

		// if there is something to send, send
		if( con->transport.tcp.io_out->len > 0 )
			ev_io_start(CL, &con->events.io_out);

		break;

	case connection_transport_tls:
		ev_io_init(&con->events.io_in, connection_tls_io_in_cb, con->socket, EV_READ);
		ev_io_init(&con->events.io_out, connection_tls_io_out_cb, con->socket, EV_WRITE);

		// start only io_in
		ev_io_start(CL, &con->events.io_in);

		// inform protocol about new connection
		con->protocol.established(con);

		// timers
		if( con->events.idle_timeout.repeat >= 0. )
			ev_timer_again(CL,  &con->events.idle_timeout);

		if( con->events.sustain_timeout.repeat >= 0. )
			ev_timer_again(CL,  &con->events.sustain_timeout);

		if( con->transport.tls.io_out_again->len > 0 || con->transport.tls.io_out->len > 0 )
			ev_io_start(CL, &con->events.io_out);

		break;

	case connection_transport_udp:
		// inform protocol about new connection
		con->protocol.established(con);
		if( con->type == connection_type_connect || con->type == connection_type_bind )
		{
			ev_io_init(&con->events.io_in, connection_udp_io_in_cb, con->socket, EV_READ);
			ev_io_start(CL, &con->events.io_in);
		}
		// timers
		if( con->events.idle_timeout.repeat >= 0. )
			ev_timer_again(CL,  &con->events.idle_timeout);

		if( con->events.sustain_timeout.repeat >= 0. )
			ev_timer_again(CL,  &con->events.sustain_timeout);

		break;
	case connection_transport_dtls:
		con->protocol.established(con);
		break;
	case connection_transport_io:
		break;
	}
}


double connection_stats_speed_get(struct connection_stats *throttle_info)
{
	double delta = ev_now(g_dionaea->loop) - throttle_info->throttle.interval_start;
	return throttle_info->throttle.interval_bytes / delta;
}

double connection_stats_speed_limit_get(struct connection_stats *throttle_info)
{
	return throttle_info->throttle.max_bytes_per_second;
}

void connection_stats_speed_limit_set(struct connection_stats *throttle_info, double limit)
{
	throttle_info->throttle.max_bytes_per_second = limit;
}

double connection_stats_accounting_get(struct connection_stats *throttle_info)
{
	return throttle_info->accounting.bytes;
}

double connection_stats_accounting_limit_get(struct connection_stats *throttle_info)
{
	return throttle_info->accounting.limit;
}

void connection_stats_accounting_limit_set(struct connection_stats *throttle_info, double limit)
{
	throttle_info->accounting.limit = limit;
}

bool connection_stats_accounting_limit_exceeded(struct connection_stats *stats)
{
	g_debug("%s stats %p", __PRETTY_FUNCTION__, stats);
//	g_debug("bytes %f limit %f", stats->accounting.bytes,  stats->accounting.limit);
	if( stats->accounting.limit <= 1.0 )
		return false;
	if( stats->accounting.bytes > stats->accounting.limit )
		return true;
	return false;
}


void connection_throttle_io_in_set(struct connection *con, uint32_t max_bytes_per_second)
{
	g_debug(__PRETTY_FUNCTION__);
	connection_stats_speed_limit_set(&con->stats.io_in, max_bytes_per_second);
}


void connection_throttle_io_out_set(struct connection *con, uint32_t max_bytes_per_second)
{
	g_debug(__PRETTY_FUNCTION__);
	connection_stats_speed_limit_set(&con->stats.io_out, max_bytes_per_second);
}

int connection_throttle(struct connection *con, struct connection_throttle *thr)
{

	if( thr->max_bytes_per_second == 0 )
		return 64*1024;

	g_debug("%s con %p thr %p", __PRETTY_FUNCTION__, con, thr);

	double delta = 0.; // time in ms for this session
	double expect = 0.;	// expected time frame for the sended bytes

	double last_throttle;
	last_throttle = ev_now(CL) - thr->last_throttle;

	g_debug("last_throttle %f", last_throttle);
	if( last_throttle > 1.0 )
	{
		g_debug("resetting connection");
		connection_throttle_reset(thr);
	}
	thr->last_throttle = ev_now(CL);

	delta = ev_now(CL) - thr->interval_start;
	expect = (double)thr->interval_bytes / (double)thr->max_bytes_per_second;

	g_debug("throttle: delta  %f expect %f", delta, expect);

	int bytes = 1;
	bytes = (delta+0.125)* thr->max_bytes_per_second;
	bytes -= thr->interval_bytes;

	if( expect > delta )
	{ // we sent to much
		double slp = expect - delta;

		if( slp + thr->sleep_adjust < 0.200 && bytes > 0 )
		{
			thr->sleep_adjust = slp;
			g_debug("throttle: discarding sleep %f do %i bytes", slp, bytes);
			return bytes;
		}

		if( &con->stats.io_in.throttle == thr )
		{
			g_debug("throttle: io_in");
			ev_io_stop(CL, &con->events.io_in);
			if( !ev_is_active(&con->events.throttle_io_in_timeout) )
			{
				if( slp < 0.200 )
					slp = 0.200;
				ev_timer_init(&con->events.throttle_io_in_timeout, connection_throttle_io_in_timeout_cb, slp+thr->sleep_adjust, 0.);
				ev_timer_start(CL, &con->events.throttle_io_in_timeout);
			}
			return 0;
		} else
			if( &con->stats.io_out.throttle == thr )
		{
			g_debug("throttle: io_out");
			ev_io_stop(CL, &con->events.io_out);
			if( !ev_is_active(&con->events.throttle_io_out_timeout) )
			{
				if( slp < 0.200 )
					slp = 0.200;
				ev_timer_init(&con->events.throttle_io_out_timeout, connection_throttle_io_out_timeout_cb, slp+thr->sleep_adjust, 0.);
				ev_timer_start(CL, &con->events.throttle_io_out_timeout);
			}
			return 0;
		}
	} else
	{
		bytes = (delta+0.250)* thr->max_bytes_per_second;
		bytes -= thr->interval_bytes;
		g_debug("throttle: can do %i bytes", bytes);
	}

	return bytes;
}

void connection_throttle_update(struct connection *con, struct connection_throttle *thr, int bytes)
{
	g_debug("%s con %p thr %p bytes %i",__PRETTY_FUNCTION__, con, thr, bytes);
	if( bytes > 0 )
		thr->interval_bytes += bytes;

	if( &con->stats.io_in.throttle == thr )
	{
		con->stats.io_in.accounting.bytes += bytes;
	} else
		if( &con->stats.io_out.throttle == thr )
	{
		con->stats.io_out.accounting.bytes += bytes;
	}
}

void connection_throttle_io_in_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_THROTTLE_IO_IN_TIMEOUT(w);
	g_debug("%s %p", __PRETTY_FUNCTION__, con);
	ev_io_start(EV_A_ &con->events.io_in);
}

void connection_throttle_io_out_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_THROTTLE_IO_OUT_TIMEOUT(w);
	g_debug("%s %p", __PRETTY_FUNCTION__, con);
	ev_io_start(EV_A_ &con->events.io_out);
}

void connection_throttle_reset(struct connection_throttle *thr)
{
	thr->interval_bytes = 0;
	thr->sleep_adjust = 0;
}


/*
 *
 * connection resolve
 *
 */


void connection_dns_resolve_cancel(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	if( con->remote.dns.a != NULL )
	{
		dns_cancel(g_dionaea->dns->dns, con->remote.dns.a);
		con->remote.dns.a = NULL;
	}
	if( con->remote.dns.aaaa != NULL )
	{
		dns_cancel(g_dionaea->dns->dns, con->remote.dns.aaaa);
		con->remote.dns.aaaa = NULL;
	}

	if( ev_is_active(&con->events.dns_timeout) )
		ev_timer_stop(g_dionaea->loop, &con->events.dns_timeout);
	connection_set_state(con, connection_state_none);
}

void connection_dns_resolve_timeout_cb(EV_P_ struct ev_timer *w, int revent)
{
	struct connection *con = CONOFF_DNS_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	connection_dns_resolve_cancel(con);

	if( con->protocol.error(con, ECONDNSTIMEOUT) == false )
		connection_close(con);
	else
		connection_reconnect(con);

}

void connection_connect_resolve(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	g_debug("submitting dns %s", con->remote.hostname);

	con->remote.dns.a = dns_submit_p(g_dionaea->dns->dns,
									 con->remote.hostname,
									 DNS_C_IN,
									 DNS_T_A,
									 0,
									 dns_parse_a4,
									 connection_connect_resolve_a_cb,
									 con);
	con->remote.dns.aaaa = dns_submit_p(g_dionaea->dns->dns,
										con->remote.hostname,
										DNS_C_IN,
										DNS_T_AAAA,
										0,
										dns_parse_a6,
										connection_connect_resolve_aaaa_cb,
										con);

	connection_set_state(con, connection_state_resolve);
	con->events.dns_timeout.data = con;
	ev_timer_init(&con->events.dns_timeout, connection_dns_resolve_timeout_cb, 0., 10.);
	ev_timer_again(g_dionaea->loop, &con->events.dns_timeout);
	return;
}

static int cmp_ip_address_stringp(const void *p1, const void *p2)
{
//	g_debug("%s",__PRETTY_FUNCTION__);
	struct sockaddr_storage sa1, sa2;
	int domain1,domain2;
	socklen_t sizeof_sa1, sizeof_sa2;

	parse_addr(*(const char **)p1, NULL, 0, &sa1, &domain1, &sizeof_sa1);
	parse_addr(*(const char **)p2, NULL, 0, &sa2, &domain2, &sizeof_sa2);

	if( domain1 == domain2 )
	{
		void *a = ADDROFFSET(&sa1);
		void *b = ADDROFFSET(&sa2);

		if( domain1 == PF_INET6 )
		{
			if( ipv6_addr_v4mapped(a) &&
				ipv6_addr_v4mapped(b) )
				return -memcmp(a, b, sizeof_sa1);

			if( ipv6_addr_v4mapped(a) )
				return 1;

			if( ipv6_addr_v4mapped(b) )
				return -1;
		}

		return -memcmp(a, b, sizeof_sa1);

	} else
		if( domain1 > domain2 )	// domain1 is ipv6
	{
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&sa1;
		struct sockaddr_in *b  = (struct sockaddr_in *)&sa2;
		if( ipv6_addr_v4mapped(&a->sin6_addr) )
			return -memcmp(&a->sin6_addr.s6_addr32[3], &b->sin_addr.s_addr, sizeof_sa2);

		return -1;
	} else				 // domain2 is ipv6
	{
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&sa2;
		struct sockaddr_in *b  = (struct sockaddr_in *)&sa1;
		if( ipv6_addr_v4mapped(&a->sin6_addr) )
			return memcmp(&a->sin6_addr.s6_addr32[3], &b->sin_addr.s_addr, sizeof_sa2);

		return 1;
	}
}

void connection_connect_resolve_action(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	if( con->remote.dns.a == NULL && con->remote.dns.aaaa == NULL )
	{
		ev_timer_stop(g_dionaea->loop, &con->events.dns_timeout);

		if( con->remote.dns.resolved_address_count == 0 )
		{
			if( con->protocol.error(con, ECONNOSUCHDOMAIN) == false )
				connection_close(con);
			else
				connection_reconnect(con);
			return;
		}

		qsort(con->remote.dns.resolved_addresses, con->remote.dns.resolved_address_count, sizeof(char *), cmp_ip_address_stringp);
/*		int i;
		for(i=0;i<con->remote.dns.resolved_address_count;i++)
		{
			g_debug("node address %s", con->remote.dns.resolved_addresses[i]);
		}
*/
//		return;
		connection_connect_next_addr(con);
	}
}

void connection_connect_resolve_a_cb(struct dns_ctx *ctx, void *result, void *data)
{
	g_debug("%s ctx %p result %p con %p",__PRETTY_FUNCTION__, ctx, result, data);
	struct connection *con = data;

	struct dns_rr_a4 *a4 = result;

	if( result )
	{
		int i=0;
		for( i=0;i<a4->dnsa4_nrr; i++ )
		{
			char addr[INET6_ADDRSTRLEN];

			inet_ntop(PF_INET, &a4->dnsa4_addr[i], addr, INET6_ADDRSTRLEN);
			g_debug("\t%s",addr);
			node_info_add_addr(&con->remote, addr);
		}
	}
	con->remote.dns.a = NULL;

	connection_connect_resolve_action(con);
}

void connection_connect_resolve_aaaa_cb(struct dns_ctx *ctx, void *result, void *data)
{
	g_debug("%s ctx %p result %p con %p",__PRETTY_FUNCTION__, ctx, result, data);
	struct connection *con = data;

	struct dns_rr_a6 *a6 = result;

	if( result )
	{
		int i=0;
		for( i=0;i<a6->dnsa6_nrr; i++ )
		{
			char addr[INET6_ADDRSTRLEN];

			inet_ntop(PF_INET6, &a6->dnsa6_addr[i], addr, INET6_ADDRSTRLEN);
			g_debug("\t%s",addr);
			node_info_add_addr(&con->remote, addr);
		}
	}
	con->remote.dns.aaaa = NULL;

	connection_connect_resolve_action(con);
}

bool connection_transport_from_string(const char *type_str, enum connection_transport *type)
{
	if( strcmp(type_str, "tcp") == 0 )
		*type = connection_transport_tcp;
	else if( strcmp(type_str, "udp") == 0 )
		*type = connection_transport_udp;
	else if( strcmp(type_str, "tls") == 0 )
		*type = connection_transport_tls;
	else if( strcmp(type_str, "dtls") == 0 )
		*type = connection_transport_dtls;
	else
		return false;

	return true;
}

const char *connection_transport_to_string(enum connection_transport trans)
{
	static const char *connection_transport_str[] =
	{
		"udp",
		"tcp",
		"tls",
		"dtls",
		"io"
	};
	return connection_transport_str[trans];
}

void connection_protocol_set(struct connection *con, struct protocol *proto)
{
	memcpy(&con->protocol, proto, sizeof(struct protocol));
	if( con->protocol.name )
		con->protocol.name = g_strdup(con->protocol.name);
	else
		con->protocol.name = g_strdup("unknown");
}

void connection_protocol_ctx_set(struct connection *con, void *data)
{
	g_debug("%s con %p data %p", __PRETTY_FUNCTION__, con, data);
	con->protocol.ctx = data;
}

void *connection_protocol_ctx_get(struct connection *con)
{
	g_debug("%s con %p data %p", __PRETTY_FUNCTION__, con, con->protocol.ctx);
	return con->protocol.ctx;
}


const char *connection_type_to_string(enum connection_type type)
{
	static const char *connection_type_str[] =
	{
		"none",
		"accept",
		"bind",
		"connect",
		"listen",
	};
	return connection_type_str[type];
}




void connection_set_type(struct connection *con, enum connection_type type)
{
	enum connection_type old_type;
	old_type = con->type;
	con->type = type;
	g_message("connection %p %s/%s type: %s->%s",
			  con,
			  connection_type_to_string(old_type),
			  connection_transport_to_string(con->trans),
			  connection_type_to_string(old_type),
			  connection_type_to_string(type));
}


const char *connection_state_to_string(enum connection_state state)
{
	static const char *connection_state_str[] =
	{
		"none",
		"resolve",
		"connecting",
		"handshake",
		"established",
		"shutdown",
		"close",
		"reconnect"
	};
	return connection_state_str[state];
}

void connection_set_state(struct connection *con, enum connection_state state)
{
	enum connection_state old_state;
	old_state = con->state;
	con->state = state;
	g_message("connection %p %s/%s/%s [%s->%s] state: %s->%s",
			  con,
			  connection_type_to_string(con->type),
			  connection_transport_to_string(con->trans),
			  connection_state_to_string(old_state),
			  con->local.node_string,
			  con->remote.node_string,
			  connection_state_to_string(old_state),
			  connection_state_to_string(state));
}

int connection_ref(struct connection *con)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
	refcount_inc(&con->refcount);
	return con->refcount.refs;
}

int connection_unref(struct connection *con)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
	refcount_dec(&con->refcount);
	return con->refcount.refs;
}

void connection_process(struct connection *con)
{
	processors_init(con);
}

const char *connection_strerror(enum connection_error error)
{
	static const char *myerrormsgs[] =
	{
		"timeout resolving the domain" , /* ECONDNSTIMEOUT   */
		"could not connect host(s)" ,/* ECONUNREACH       */
		"could not resolve domain" , /* ECONNOSUCHDOMAIN */
		"too many connections" , /* ECONMANY */
	};
	if( error >= ECONMANY )
		return NULL;

	return myerrormsgs[error];
}
