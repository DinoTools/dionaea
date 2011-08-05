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

#define CONOFF(x)							((void *)x - sizeof(struct connection))
#define CONOFF_IO_IN(x)  					((struct connection *)(((void *)x) - offsetof (struct connection, events.io_in)))
#define CONOFF_IO_OUT(x) 					((struct connection *)(((void *)x) - offsetof (struct connection, events.io_out)))
#define CONOFF_LISTEN_TIMEOUT(x) 			((struct connection *)(((void *)x) - offsetof (struct connection, events.listen_timeout)))
#define CONOFF_CONNECTING_TIMEOUT(x) 		((struct connection *)(((void *)x) - offsetof (struct connection, events.connecting_timeout)))
#define CONOFF_SUSTAIN_TIMEOUT(x)			((struct connection *)(((void *)x) - offsetof (struct connection, events.sustain_timeout)))
#define CONOFF_IDLE_TIMEOUT(x) 				((struct connection *)(((void *)x) - offsetof (struct connection, events.idle_timeout)))
#define CONOFF_DNS_TIMEOUT(x) 				((struct connection *)(((void *)x) - offsetof (struct connection, events.dns_timeout)))
#define CONOFF_HANDSHAKE_TIMEOUT(x) 		((struct connection *)(((void *)x) - offsetof (struct connection, events.handshake_timeout)))
#define CONOFF_CLOSE_TIMEOUT(x) 			((struct connection *)(((void *)x) - offsetof (struct connection, events.close_timeout)))
#define CONOFF_RECONNECT_TIMEOUT(x) 		((struct connection *)(((void *)x) - offsetof (struct connection, events.reconnect_timeout)))
#define CONOFF_THROTTLE_IO_IN_TIMEOUT(x) 	((struct connection *)(((void *)x) - offsetof (struct connection, events.throttle_io_in_timeout)))
#define CONOFF_THROTTLE_IO_OUT_TIMEOUT(x) 	((struct connection *)(((void *)x) - offsetof (struct connection, events.throttle_io_out_timeout)))
#define CONOFF_FREE(x)						((struct connection *)(((void *)x) - offsetof (struct connection, events.free)))



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
		strcpy(con->local.iface_scope, iface_scope);


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
		connection_tls_mkcert(con);
//		connection_tls_set_certificate(con,"/tmp/server.crt",SSL_FILETYPE_PEM);
//		connection_tls_set_key(con,"/tmp/server.pem",SSL_FILETYPE_PEM);
//		SSL_CTX_set_timeout(con->transport.ssl.ctx, 15);
		ssl_tmp_keys_init(con);
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
		ev_timer_init(&con->events.free, connection_free_cb, 0., con->events.free.repeat);
		ev_timer_again(CL, &con->events.free);
	}
}

/**
 * we poll the connection to see if the refcount hit 0
 * so we can free it
 * 
 * @param w
 * @param revents
 */
void connection_free_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_FREE(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);   

	if( ! refcount_is_zero(&con->refcount) )
		return;

	ev_timer_stop(EV_A_ w);

	if( con->local.domain != AF_UNIX && con->remote.domain != AF_UNIX)
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
					ev_timer_init(&con->events.connecting_timeout, connection_tcp_connecting_timeout_cb, 0., con->events.connecting_timeout.repeat);
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
					ev_timer_init(&con->events.connecting_timeout, connection_tls_connecting_timeout_cb, 0., con->events.connecting_timeout.repeat);
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
				connection_tls_connect_again_cb(CL, &con->events.io_in, EV_READ);
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
		strcpy(con->remote.iface_scope, iface_scope);
	else
		con->remote.iface_scope[0] = '\0';

	con->remote.port = htons(port);

	con->remote.hostname = g_strdup(addr);

	connection_set_type(con, connection_type_connect);


	if( !parse_addr(addr, NULL, port, &sa, &socket_domain, &sizeof_sa) )
	{
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
		ev_timer_init(&con->events.idle_timeout, connection_tcp_idle_timeout_cb, 0., timeout_interval_ms);
		break;

	case connection_transport_tls:
		ev_timer_init(&con->events.idle_timeout, connection_tls_idle_timeout_cb, 0., timeout_interval_ms);
		break;

	case connection_transport_udp:
		ev_timer_init(&con->events.idle_timeout, connection_udp_idle_timeout_cb, 0., timeout_interval_ms);
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
		ev_timer_init(&con->events.sustain_timeout, connection_tcp_sustain_timeout_cb, 0., timeout_interval_ms);
		break;

	case connection_transport_tls:
		ev_timer_init(&con->events.sustain_timeout, connection_tls_sustain_timeout_cb, 0., timeout_interval_ms);
		break;

	case connection_transport_udp:
		ev_timer_init(&con->events.sustain_timeout, connection_udp_sustain_timeout_cb, 0., timeout_interval_ms);
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
		ev_timer_init(&con->events.listen_timeout, connection_tcp_listen_timeout_cb, 0., timeout_interval_ms);
//		ev_timer_again(CL, &con->events.listen_timeout);
		break;

	case connection_transport_tls:
		ev_timer_init(&con->events.listen_timeout, connection_tls_listen_timeout_cb, 0., timeout_interval_ms);
//		ev_timer_again(CL, &con->events.listen_timeout);
		break;

	default:
		break;
	}

	if( con->type == connection_type_listen && timeout_interval_ms >= 0. )
		ev_timer_again(CL, &con->events.sustain_timeout);
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
		ev_timer_init(&con->events.connecting_timeout, NULL, 0., timeout_interval_ms);
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

	connection_node_set_local(con);
	connection_node_set_remote(con);


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
			connection_free_cb(loop, &accepted->events.free, 0);
			continue;
		}

		g_debug("accept() %i local:'%s' remote:'%s'", accepted->socket, accepted->local.node_string,  accepted->remote.node_string);

		connection_set_nonblocking(accepted);

		accepted->data = con->data;

		// set protocol for accepted connection
		connection_protocol_set(accepted, &con->protocol);

		// copy connect timeout to new connection
		ev_timer_init(&accepted->events.idle_timeout, connection_tcp_idle_timeout_cb, 0. ,con->events.idle_timeout.repeat);


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



void connection_tcp_listen_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_LISTEN_TIMEOUT(w);
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);


	if( con->protocol.listen_timeout  != NULL && 
		con->protocol.listen_timeout(con, con->protocol.ctx) == true )
	{
		ev_timer_again(loop, &con->events.listen_timeout);
		return;
	}

	connection_set_state(con, connection_state_close);
	connection_disconnect(con);

	connection_free(con);
}


void connection_tcp_connecting_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_CONNECTING_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	ev_timer_stop(EV_A_ &con->events.connecting_timeout);
	ev_io_stop(EV_A_ &con->events.io_out);
	close(con->socket);
	con->socket = -1;
	connection_connect_next_addr(con);
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

void connection_tcp_sustain_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_SUSTAIN_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( con->protocol.sustain_timeout == NULL || con->protocol.sustain_timeout(con, con->protocol.ctx) == false )
		connection_tcp_disconnect(con);
	else
		ev_timer_again(EV_A_ &con->events.sustain_timeout);
}


void connection_tcp_idle_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_IDLE_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( con->protocol.idle_timeout == NULL || con->protocol.idle_timeout(con, con->protocol.ctx) == false )
		connection_tcp_disconnect(con);
	else
		ev_timer_again(EV_A_ &con->events.idle_timeout);
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


/*
 *
 * connection ssl
 *
 */

/*
 * the ssl dh key setup is taken from the mod_ssl package from apache
 */

#ifndef SSLC_VERSION_NUMBER
#define SSLC_VERSION_NUMBER 0x0000
#endif

DH *myssl_dh_configure(unsigned char *p, int plen,
					   unsigned char *g, int glen)
{
	DH *dh;

	if( !(dh = DH_new()) )
	{
		return NULL;
	}

#if defined(OPENSSL_VERSION_NUMBER) || (SSLC_VERSION_NUMBER < 0x2000)
	dh->p = BN_bin2bn(p, plen, NULL);
	dh->g = BN_bin2bn(g, glen, NULL);
	if( !(dh->p && dh->g) )
	{
		DH_free(dh);
		return NULL;
	}
#else
	R_EITEMS_add(dh->data, PK_TYPE_DH, PK_DH_P, 0, p, plen, R_EITEMS_PF_COPY);
	R_EITEMS_add(dh->data, PK_TYPE_DH, PK_DH_G, 0, g, glen, R_EITEMS_PF_COPY);
#endif

	return dh;
}





/*
 * Handle the Temporary RSA Keys and DH Params
 */


/*
** Diffie-Hellman-Parameters: (512 bit)
**     prime:
**         00:9f:db:8b:8a:00:45:44:f0:04:5f:17:37:d0:ba:
**         2e:0b:27:4c:df:1a:9f:58:82:18:fb:43:53:16:a1:
**         6e:37:41:71:fd:19:d8:d8:f3:7c:39:bf:86:3f:d6:
**         0e:3e:30:06:80:a3:03:0c:6e:4c:37:57:d0:8f:70:
**         e6:aa:87:10:33
**     generator: 2 (0x2)
** Diffie-Hellman-Parameters: (1024 bit)
**     prime:
**         00:d6:7d:e4:40:cb:bb:dc:19:36:d6:93:d3:4a:fd:
**         0a:d5:0c:84:d2:39:a4:5f:52:0b:b8:81:74:cb:98:
**         bc:e9:51:84:9f:91:2e:63:9c:72:fb:13:b4:b4:d7:
**         17:7e:16:d5:5a:c1:79:ba:42:0b:2a:29:fe:32:4a:
**         46:7a:63:5e:81:ff:59:01:37:7b:ed:dc:fd:33:16:
**         8a:46:1a:ad:3b:72:da:e8:86:00:78:04:5b:07:a7:
**         db:ca:78:74:08:7d:15:10:ea:9f:cc:9d:dd:33:05:
**         07:dd:62:db:88:ae:aa:74:7d:e0:f4:d6:e2:bd:68:
**         b0:e7:39:3e:0f:24:21:8e:b3
**     generator: 2 (0x2)
*/

static unsigned char dh512_p[] = {
	0x9F, 0xDB, 0x8B, 0x8A, 0x00, 0x45, 0x44, 0xF0, 0x04, 0x5F, 0x17, 0x37,
	0xD0, 0xBA, 0x2E, 0x0B, 0x27, 0x4C, 0xDF, 0x1A, 0x9F, 0x58, 0x82, 0x18,
	0xFB, 0x43, 0x53, 0x16, 0xA1, 0x6E, 0x37, 0x41, 0x71, 0xFD, 0x19, 0xD8,
	0xD8, 0xF3, 0x7C, 0x39, 0xBF, 0x86, 0x3F, 0xD6, 0x0E, 0x3E, 0x30, 0x06,
	0x80, 0xA3, 0x03, 0x0C, 0x6E, 0x4C, 0x37, 0x57, 0xD0, 0x8F, 0x70, 0xE6,
	0xAA, 0x87, 0x10, 0x33,
};
static unsigned char dh512_g[] = {
	0x02,
};

static DH *get_dh512(void)
{
	return myssl_dh_configure(dh512_p, sizeof(dh512_p),
							  dh512_g, sizeof(dh512_g));
}

static unsigned char dh1024_p[] = {
	0xD6, 0x7D, 0xE4, 0x40, 0xCB, 0xBB, 0xDC, 0x19, 0x36, 0xD6, 0x93, 0xD3,
	0x4A, 0xFD, 0x0A, 0xD5, 0x0C, 0x84, 0xD2, 0x39, 0xA4, 0x5F, 0x52, 0x0B,
	0xB8, 0x81, 0x74, 0xCB, 0x98, 0xBC, 0xE9, 0x51, 0x84, 0x9F, 0x91, 0x2E,
	0x63, 0x9C, 0x72, 0xFB, 0x13, 0xB4, 0xB4, 0xD7, 0x17, 0x7E, 0x16, 0xD5,
	0x5A, 0xC1, 0x79, 0xBA, 0x42, 0x0B, 0x2A, 0x29, 0xFE, 0x32, 0x4A, 0x46,
	0x7A, 0x63, 0x5E, 0x81, 0xFF, 0x59, 0x01, 0x37, 0x7B, 0xED, 0xDC, 0xFD,
	0x33, 0x16, 0x8A, 0x46, 0x1A, 0xAD, 0x3B, 0x72, 0xDA, 0xE8, 0x86, 0x00,
	0x78, 0x04, 0x5B, 0x07, 0xA7, 0xDB, 0xCA, 0x78, 0x74, 0x08, 0x7D, 0x15,
	0x10, 0xEA, 0x9F, 0xCC, 0x9D, 0xDD, 0x33, 0x05, 0x07, 0xDD, 0x62, 0xDB,
	0x88, 0xAE, 0xAA, 0x74, 0x7D, 0xE0, 0xF4, 0xD6, 0xE2, 0xBD, 0x68, 0xB0,
	0xE7, 0x39, 0x3E, 0x0F, 0x24, 0x21, 0x8E, 0xB3,
};
static unsigned char dh1024_g[] = {
	0x02,
};

static DH *get_dh1024(void)
{
	return myssl_dh_configure(dh1024_p, sizeof(dh1024_p),
							  dh1024_g, sizeof(dh1024_g));
}

/* ----END GENERATED SECTION---------- */

DH *ssl_dh_GetTmpParam(int nKeyLen)
{
	DH *dh;

	if( nKeyLen == 512 )
		dh = get_dh512();
	else if( nKeyLen == 1024 )
		dh = get_dh1024();
	else
		dh = get_dh1024();
	return dh;
}

DH *ssl_dh_GetParamFromFile(char *file)
{
	DH *dh = NULL;
	BIO *bio;

	if( (bio = BIO_new_file(file, "r")) == NULL )
		return NULL;
#if 0 //SSL_LIBRARY_VERSION < 0x00904000
	dh = PEM_read_bio_DHparams(bio, NULL, NULL);
#else
	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
#endif
	BIO_free(bio);
	return(dh);
}


#define MYSSL_TMP_KEY_FREE(con, type, idx) \
    if (con->transport.tls.pTmpKeys[idx]) { \
        type##_free((type *)con->transport.tls.pTmpKeys[idx]); \
        con->transport.tls.pTmpKeys[idx] = NULL; \
    }

#define MYSSL_TMP_KEYS_FREE(con, type) \
    MYSSL_TMP_KEY_FREE(con, type, SSL_TMP_KEY_##type##_512); \
    MYSSL_TMP_KEY_FREE(con, type, SSL_TMP_KEY_##type##_1024)

void ssl_tmp_keys_free(struct connection *con)
{
	MYSSL_TMP_KEYS_FREE(con, RSA);
	MYSSL_TMP_KEYS_FREE(con, DH);
}

int ssl_tmp_key_init_rsa(struct connection *con, int bits, int idx)
{
	if( !(con->transport.tls.pTmpKeys[idx] = RSA_generate_key(bits, RSA_F4, NULL, NULL)) )
	{
		g_error("Init: Failed to generate temporary %d bit RSA private key", bits);
		return -1;
	}

	return 0;
}

static int ssl_tmp_key_init_dh(struct connection *con, int bits, int idx)
{
	if( !(con->transport.tls.pTmpKeys[idx] = ssl_dh_GetTmpParam(bits)) )
	{
		g_error("Init: Failed to generate temporary %d bit DH parameters", bits);
		return -1;
	}

	return 0;
}

#define MYSSL_TMP_KEY_INIT_RSA(s, bits) \
    ssl_tmp_key_init_rsa(s, bits, SSL_TMP_KEY_RSA_##bits)

#define MYSSL_TMP_KEY_INIT_DH(s, bits) \
    ssl_tmp_key_init_dh(s, bits, SSL_TMP_KEY_DH_##bits)

int ssl_tmp_keys_init(struct connection *con)
{

	g_message("Init: Generating temporary RSA private keys (512/1024 bits)");

	if( MYSSL_TMP_KEY_INIT_RSA(con, 512) ||
		MYSSL_TMP_KEY_INIT_RSA(con, 1024) )
	{
		return -1;
	}

	g_message("Init: Generating temporary DH parameters (512/1024 bits)");

	if( MYSSL_TMP_KEY_INIT_DH(con, 512) ||
		MYSSL_TMP_KEY_INIT_DH(con, 1024) )
	{
		return -1;
	}

	return 0;
}

RSA *ssl_callback_TmpRSA(SSL *ssl, int export, int keylen)
{
	struct connection *c = (struct connection *)SSL_get_app_data(ssl);
	int idx;

	g_debug("handing out temporary %d bit RSA key", keylen);

	/* doesn't matter if export flag is on,
	 * we won't be asked for keylen > 512 in that case.
	 * if we are asked for a keylen > 1024, it is too expensive
	 * to generate on the fly.
	 * XXX: any reason not to generate 2048 bit keys at startup?
	 */

	switch( keylen )
	{
	case 512:
		idx = SSL_TMP_KEY_RSA_512;
		break;

	case 1024:
	default:
		idx = SSL_TMP_KEY_RSA_1024;
	}

	return(RSA *)c->transport.tls.pTmpKeys[idx];
}

/*
 * Hand out the already generated DH parameters...
 */
DH *ssl_callback_TmpDH(SSL *ssl, int export, int keylen)
{
	struct connection *c = (struct connection *)SSL_get_app_data(ssl);
	int idx;

	g_debug("handing out temporary %d bit DH key", keylen);

	switch( keylen )
	{
	case 512:
		idx = SSL_TMP_KEY_DH_512;
		break;

	case 1024:
	default:
		idx = SSL_TMP_KEY_DH_1024;
	}

	return(DH *)c->transport.tls.pTmpKeys[idx];
}



bool connection_tls_set_certificate(struct connection *con, const char *path, int type)
{
	g_debug("%s con %p path %s type %i",__PRETTY_FUNCTION__, con, path, type);
	int ret = SSL_CTX_use_certificate_file(con->transport.tls.ctx, path, type);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_certificate_file");
		return false;
	}
	return true;
}

bool connection_tls_set_key(struct connection *con, const char *path, int type)
{
	g_debug("%s con %p path %s type %i",__PRETTY_FUNCTION__, con, path, type);
	int ret = SSL_CTX_use_PrivateKey_file(con->transport.tls.ctx, path, type);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_PrivateKey_file");
		return false;
	}
	return true;
}


int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if( !ex )
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}

static void callback(int p, int n, void *arg)
{
	char c='B';

	if( p == 0 ) c='.';
	if( p == 1 ) c='+';
	if( p == 2 ) c='*';
	if( p == 3 ) c='\n';
	fputc(c,stderr);
}


bool mkcert(SSL_CTX *ctx)
{
	int bits = 512*4;
	int serial = time(NULL);
	int days = 365;

	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name=NULL;

	if( (pk=EVP_PKEY_new()) == NULL )
		goto err;

	if( (x=X509_new()) == NULL )
		goto err;

	rsa=RSA_generate_key(bits,RSA_F4,callback,NULL);
	if( !EVP_PKEY_assign_RSA(pk,rsa) )
	{
		perror("EVP_PKEY_assign_RSA");
		goto err;
	}
	rsa=NULL;

	X509_set_version(x,2);
	ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
	X509_set_pubkey(x,pk);

	name=X509_get_subject_name(x);

	X509_NAME_add_entry_by_txt(name,"C",
							   MBSTRING_ASC, (const unsigned char *)"DE", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"CN",
							   MBSTRING_ASC, (const unsigned char *)"Nepenthes Development Team", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"O",
							   MBSTRING_ASC, (const unsigned char *)"dionaea.carnivore.it", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"OU",
							   MBSTRING_ASC, (const unsigned char *)"anv", -1, -1, 0);


	/* Its self signed so set the issuer name to be the same as the
	 * subject.
	 */
	X509_set_issuer_name(x,name);

	add_ext(x, NID_netscape_cert_type, "server");
	add_ext(x, NID_netscape_ssl_server_name, "localhost");

	if( !X509_sign(x,pk,EVP_md5()) )
		goto err;


	int ret = SSL_CTX_use_PrivateKey(ctx, pk);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_PrivateKey");
		return false;
	}

	ret = SSL_CTX_use_certificate(ctx, x);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_certificate");
		return false;
	}

	return true;
	err:
	return false;
}

bool connection_tls_mkcert(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	return mkcert(con->transport.tls.ctx);
}

void connection_tls_io_out_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = NULL;
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( w->events == EV_READ )
		con = CONOFF_IO_IN(w);
	else
		con	= CONOFF_IO_OUT(w);


	if( con->transport.tls.io_out_again->len == 0 )
	{
		GString *io_out_again = con->transport.tls.io_out_again;
		con->transport.tls.io_out_again = con->transport.tls.io_out;
		con->transport.tls.io_out = io_out_again;
		con->transport.tls.io_out_again_size = 0;
	}


	int send_throttle = connection_throttle(con, &con->stats.io_out.throttle);
	if( con->transport.tls.io_out_again_size == 0 )
		con->transport.tls.io_out_again_size = MIN((int)con->transport.tls.io_out_again->len, send_throttle);

	if( con->transport.tls.io_out_again_size <= 0 )
		return;

	g_debug("send_throttle %i con->transport.tcp.io_out_again->len %i con->transport.ssl.io_out_again_size %i todo %i",
			send_throttle, (int)con->transport.tls.io_out_again->len, con->transport.tls.io_out_again_size,
			(int)con->transport.tls.io_out_again->len + (int)con->transport.tls.io_out->len);


	int err = SSL_write(con->transport.tls.ssl, con->transport.tls.io_out_again->str, con->transport.tls.io_out_again_size);
	connection_tls_error(con);

	if( err <= 0 )
	{
		int action = SSL_get_error(con->transport.tls.ssl, err);
		connection_tls_error(con);
		switch( action )
		{
		case SSL_ERROR_ZERO_RETURN:
			g_debug("%s:%i", __FILE__,  __LINE__);
			if( revents != 0 )
				connection_tls_disconnect(con);
			else
				connection_set_state(con, connection_state_close);
			break;

		case SSL_ERROR_WANT_READ:
			g_debug("SSL_WANT_READ %s:%i", __FILE__,  __LINE__);

			if( ev_is_active(&con->events.io_in) && revents != EV_READ )
			{
				ev_io_stop(CL, &con->events.io_in);
				ev_io_init(&con->events.io_in, connection_tls_io_out_cb, con->socket, EV_READ);
				ev_io_start(CL, &con->events.io_in);
			}

			if( ev_is_active(&con->events.io_out) )
				ev_io_stop(CL, &con->events.io_out);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_WANT_WRITE %s:%i", __FILE__,  __LINE__);
			if( !ev_is_active(&con->events.io_out) )
				ev_io_start(CL, &con->events.io_out);

			if( ev_is_active(&con->events.io_in) )
				ev_io_stop(CL, &con->events.io_in);
			break;

		case SSL_ERROR_WANT_ACCEPT:
			g_debug("SSL_ERROR_WANT_ACCEPT%s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_X509_LOOKUP %s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_SYSCALL:
			g_debug("SSL_ERROR_SYSCALL %s:%i", __FILE__,  __LINE__);
			connection_tls_disconnect(con);
			break;

		case SSL_ERROR_SSL:
			g_debug("SSL_ERROR_SSL %s:%i", __FILE__,  __LINE__);
			connection_tls_disconnect(con);
			break;

		case SSL_ERROR_NONE:
			g_debug("%s:%i", __FILE__,  __LINE__);
			break;

		}
	} else
	{
		int size = err;

		if( size == con->transport.tls.io_out_again_size )
		{
			/* restore io handlers to fit default */
			if( ev_is_active(&con->events.io_in) && ev_cb(&con->events.io_in) != connection_tls_io_in_cb )
				ev_io_stop(CL, &con->events.io_in);

			if( !ev_is_active(&con->events.io_in) )
			{
				ev_io_init(&con->events.io_in, connection_tls_io_in_cb, con->socket, EV_READ);
				ev_io_start(CL, &con->events.io_in);
			}

			if( ev_is_active(&con->events.io_out) && ev_cb(&con->events.io_out) != connection_tls_io_out_cb )
				ev_io_stop(CL, &con->events.io_out);

			if( !ev_is_active(&con->events.io_out) )
			{
				ev_io_init(&con->events.io_out, connection_tls_io_out_cb, con->socket, EV_WRITE);
				ev_io_start(CL, &con->events.io_out);
			}

			connection_throttle_update(con, &con->stats.io_out.throttle, size);

			g_string_erase(con->transport.tls.io_out_again, 0 , con->transport.tls.io_out_again_size);
			con->transport.tls.io_out_again_size = 0;

			if( con->transport.tls.io_out_again->len == 0 && con->transport.tls.io_out->len == 0 )
			{
				g_debug("connection is flushed");
				if( ev_is_active(&con->events.io_out) )
					ev_io_stop(EV_A_ &con->events.io_out);

				if( con->state == connection_state_close )
					connection_tls_shutdown_cb(EV_A_ w, revents);
				else
					if( con->protocol.io_out != NULL )
				{
					/* avoid recursion */
					connection_flag_set(con, connection_busy_sending);
					con->protocol.io_out(con, con->protocol.ctx);
					connection_flag_unset(con, connection_busy_sending);
					if( con->transport.tls.io_out->len > 0 )
						ev_io_start(CL, &con->events.io_out);
				}
			}



		} else
		{
			g_debug("unexpected %s:%i...", __FILE__,  __LINE__);
		}

	}
}


void connection_tls_shutdown_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = NULL;
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( w->events == EV_READ )
		con = CONOFF_IO_IN(w);
	else
		con	= CONOFF_IO_OUT(w);

	if( con->type == connection_type_listen )
	{
		g_debug("connection was listening, closing!");
		connection_tls_disconnect(con);
		return;
	}

	if( SSL_get_shutdown(con->transport.tls.ssl) & (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN) )
	{
		g_debug("connection has sent&received shutdown");
		connection_tls_disconnect(con);
		return;
	}

	ev_io_stop(EV_A_ &con->events.io_in);
	ev_io_stop(EV_A_ &con->events.io_out);

	connection_tls_error(con);

	int err = SSL_shutdown(con->transport.tls.ssl);
	connection_tls_error(con);

	int action;

	switch( err )
	{
	case 1:
		connection_tls_disconnect(con);
		break;

	case 0:
		err = SSL_shutdown(con->transport.tls.ssl);
		action = SSL_get_error(con->transport.tls.ssl, err);
		connection_tls_error(con);

		switch( action )
		{
		case SSL_ERROR_WANT_READ:
			g_debug("SSL_WANT_READ %s:%i", __FILE__,  __LINE__);
			ev_io_init(&con->events.io_in, connection_tls_shutdown_cb, con->socket, EV_READ);
			ev_io_start(EV_A_ &con->events.io_in);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_WANT_WRITE %s:%i", __FILE__,  __LINE__);
			ev_io_init(&con->events.io_out, connection_tls_shutdown_cb, con->socket, EV_WRITE);
			ev_io_start(EV_A_ &con->events.io_out);
			break;

		case SSL_ERROR_WANT_ACCEPT:
			g_debug("SSL_ERROR_WANT_ACCEPT%s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_X509_LOOKUP %s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_SYSCALL:
			g_debug("SSL_ERROR_SYSCALL %i %s %s:%i", errno, strerror(errno), __FILE__,  __LINE__);
			if( errno == 0 )
			{
				/* 
				 * HACK actually a bug in openssl - a patch sent on
				 * 2006-06-29 0:12:51
				 * with subject
				 * [PATCH2] Fix for SSL_shutdown() with non-blocking not returning -1
				 * by Darryl L. Miles
				 * actually fixes the issue 
				 *  
				 * patch was merged into openssl
				 * 2009-Apr-07 18:28 http://cvs.openssl.org/chngview?cn=17995
				 * and will (hopefully) ship with openssl 0.9.8l 
				 *  
				 * given the 3 years it took openssl to accept a patch, 
				 * it did not take me that long to figure out 
				 * why SSL_shutdown failed on nonblocking sockets 
				 *  
				 * at the time of this writing, 0.9.8k is current 
				 * 0.9.8g is shipped by all major vendors as stable 
				 *  
				 * so it may take some time to get this fix to the masses 
				 *  
				 * due to unclear&complex openssl version situation 
				 * I decided not to provide an workaround, just close the connection instead
				 * and rant about openssl 
				 *  
				 */
				connection_tls_disconnect(con);
			}else
				connection_tls_disconnect(con);

			break;

		case SSL_ERROR_SSL:
			g_debug("SSL_ERROR_SSL %s:%i", __FILE__,  __LINE__);
			connection_tls_disconnect(con);
			break;
		}

		break;

	case -1:
		g_debug("SSL_shutdown -1 %s:%i", __FILE__,  __LINE__);
		action = SSL_get_error(con->transport.tls.ssl, err);
		connection_tls_error(con);

		switch( action )
		{
		case SSL_ERROR_WANT_READ:
			g_debug("SSL_WANT_READ %s:%i", __FILE__,  __LINE__);
			ev_io_init(&con->events.io_in, connection_tls_shutdown_cb, con->socket, EV_READ);
			ev_io_start(EV_A_ &con->events.io_in);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_WANT_WRITE %s:%i", __FILE__,  __LINE__);
			ev_io_init(&con->events.io_out, connection_tls_shutdown_cb, con->socket, EV_WRITE);
			ev_io_start(EV_A_ &con->events.io_out);
			break;

		default:
			g_debug("SSL_ERROR_ %i %s:%i", action, __FILE__,  __LINE__);
			connection_tls_disconnect(con);
			break;
		}
		break;

	default:
		g_debug("SSL_shutdown %i %s:%i", err, __FILE__,  __LINE__);
		break;
	}
}

void connection_tls_io_in_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = NULL;

	if( w->events == EV_READ )
		con = CONOFF_IO_IN(w);
	else
		con	= CONOFF_IO_OUT(w);

	g_debug("%s con %p",__PRETTY_FUNCTION__, con);


	int recv_throttle = connection_throttle(con, &con->stats.io_in.throttle);
	if( recv_throttle == 0 )
	{
		g_debug("recv throttle %i", recv_throttle);
		return;
	}
	
	unsigned char buf[recv_throttle];

	int err=0;
	if( (err = SSL_read(con->transport.tls.ssl, buf, recv_throttle)) > 0 )
	{
//		g_debug("SSL_read %i %.*s", err, err, buf);
		g_string_append_len(con->transport.tls.io_in, (gchar *)buf, err);
	}
	connection_tls_error(con);

	int action = SSL_get_error(con->transport.tls.ssl, err);
	connection_tls_error(con);

	if( err<=0 )
	{
		switch( action )
		{
		case SSL_ERROR_NONE:
			g_debug("%s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_ZERO_RETURN:
			g_debug("%s:%i", __FILE__,  __LINE__);
			connection_tls_shutdown_cb(EV_A_ w, revents);
			break;

		case SSL_ERROR_WANT_READ:
			g_debug("SSL_WANT_READ %s:%i", __FILE__,  __LINE__);
			if( ev_is_active(&con->events.io_out) )
				ev_io_stop(CL, &con->events.io_out);

			if( !ev_is_active(&con->events.io_in) )
				ev_io_start(CL, &con->events.io_in);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_WANT_WRITE %s:%i", __FILE__,  __LINE__);
			if( ev_is_active(&con->events.io_in) )
				ev_io_stop(CL, &con->events.io_in);

			if( ev_is_active( &con->events.io_out ) && revents != EV_WRITE )
			{
				ev_io_stop(EV_A_ &con->events.io_out);
				ev_io_init(&con->events.io_out, connection_tls_io_in_cb, con->socket, EV_WRITE);
				ev_io_start(EV_A_ &con->events.io_out);
			}
			break;

		case SSL_ERROR_WANT_ACCEPT:
			g_debug("SSL_ERROR_WANT_ACCEPT%s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_X509_LOOKUP %s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_SYSCALL:
			g_debug("SSL_ERROR_SYSCALL %s:%i", __FILE__,  __LINE__);
			if( err == 0 )
				g_debug("remote closed protocol, violating the specs!");
			else
				if( err == -1 )
				perror("read");

			connection_tls_disconnect(con);
			break;

		case SSL_ERROR_SSL:
			g_debug("SSL_ERROR_SSL %s:%i", __FILE__,  __LINE__);
			connection_tls_disconnect(con);
			break;
		}
	} else
		if( err > 0 )
	{

		/* restore io handlers to fit default */
		if( ev_is_active(&con->events.io_in) && ev_cb(&con->events.io_in) != connection_tls_io_in_cb )
			ev_io_stop(CL, &con->events.io_in);

		if( !ev_is_active(&con->events.io_in) )
		{
			ev_io_init(&con->events.io_in, connection_tls_io_in_cb, con->socket, EV_READ);
			ev_io_start(CL, &con->events.io_in);
		}

		if( ev_is_active(&con->events.io_out) && ev_cb(&con->events.io_out) != connection_tls_io_out_cb )
			ev_io_stop(CL, &con->events.io_out);

		if( !ev_is_active(&con->events.io_out) )
		{
			ev_io_init(&con->events.io_out, connection_tls_io_out_cb, con->socket, EV_WRITE);
		}


		connection_throttle_update(con, &con->stats.io_in.throttle, err);
		if( ev_is_active(&con->events.idle_timeout) )
			ev_timer_again(EV_A_  &con->events.idle_timeout);


		con->protocol.io_in(con, con->protocol.ctx, (unsigned char *)con->transport.tls.io_in->str, con->transport.tls.io_in->len);
		con->transport.tls.io_in->len = 0;

		if( (con->transport.tls.io_out->len > 0 || con->transport.tls.io_out_again->len > 0 ) && 
			!ev_is_active(&con->events.io_out) )
			ev_io_start(EV_A_ &con->events.io_out);
	}
}

void connection_tls_accept_cb (EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_IN(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	while( 1 )
	{
		struct sockaddr_storage sa;
		socklen_t sizeof_sa = sizeof(struct sockaddr_storage);

		// clear accept timeout, reset


		int accepted_socket = accept(con->socket, (struct sockaddr *)&sa, &sizeof_sa);

		if( accepted_socket == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) )
			break;


		if( accepted_socket > g_dionaea->limits.fds * 70/100 )
		{
			g_warning("Running out of fds, closing connection (fd %i limit %i applied limit %i)", 
					  accepted_socket,
					  g_dionaea->limits.fds,
					  g_dionaea->limits.fds * 70/100);
			close(accepted_socket);
			continue;
		}


		struct connection *accepted = connection_new(connection_transport_tls);
		SSL_CTX_free(accepted->transport.tls.ctx);
		connection_set_type(accepted, connection_type_accept);
		accepted->socket = accepted_socket;
		accepted->data = con->data;

		connection_node_set_local(accepted);
		connection_node_set_remote(accepted);

		g_debug("accept() %i local:'%s' remote:'%s'", accepted->socket, accepted->local.node_string,  accepted->remote.node_string);
		connection_set_nonblocking(accepted);

		// set protocol for accepted connection
		connection_protocol_set(accepted, &con->protocol);

		accepted->stats.io_out.throttle.max_bytes_per_second = con->stats.io_out.throttle.max_bytes_per_second;

		accepted->transport.tls.ctx = con->transport.tls.ctx;
		accepted->transport.tls.ssl = SSL_new(accepted->transport.tls.ctx);
		SSL_set_fd(accepted->transport.tls.ssl, accepted->socket);

		SSL_set_app_data(accepted->transport.tls.ssl, con);
//		SSL_set_app_data2(ssl, NULL); /* will be request_rec */

//		sslconn->ssl = ssl;

		/*
		 *  Configure callbacks for SSL connection
		 */
//		memcpy(accepted->transport.ssl.pTmpKeys, con->transport.ssl.pTmpKeys, sizeof(void *)*SSL_TMP_KEY_MAX);
//		accepted->transport.ssl.parent = con;
		SSL_set_tmp_rsa_callback(accepted->transport.tls.ssl, ssl_callback_TmpRSA);
		SSL_set_tmp_dh_callback(accepted->transport.tls.ssl,  ssl_callback_TmpDH);


		ev_timer_init(&accepted->events.handshake_timeout, connection_tls_accept_again_timeout_cb, 0., con->events.handshake_timeout.repeat);
		ev_timer_init(&accepted->events.idle_timeout, connection_tls_accept_again_timeout_cb, 0., con->events.idle_timeout.repeat);


		// create protocol specific data
		accepted->protocol.ctx = accepted->protocol.ctx_new(accepted);

		accepted->events.io_in.events = EV_READ;

		accepted->stats.io_in.throttle.max_bytes_per_second = con->stats.io_in.throttle.max_bytes_per_second;
		accepted->stats.io_out.throttle.max_bytes_per_second = con->stats.io_out.throttle.max_bytes_per_second;

		// teach new connection about parent
		if( con->protocol.origin != NULL )
			con->protocol.origin(accepted, con);

		connection_set_state(accepted, connection_state_handshake);
		connection_tls_accept_again_cb(EV_A_ &accepted->events.io_in, 0);
	}

	if( ev_is_active(&con->events.listen_timeout) )
	{
		ev_clear_pending(EV_A_ &con->events.listen_timeout);
		ev_timer_again(EV_A_  &con->events.listen_timeout);
	}
}

void connection_tls_accept_again_cb (EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = NULL;
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( w->events == EV_READ )
		con = CONOFF_IO_IN(w);
	else
		con	= CONOFF_IO_OUT(w);


	ev_io_stop(EV_A_ &con->events.io_in);
	ev_io_stop(EV_A_ &con->events.io_out);

	int err = SSL_accept(con->transport.tls.ssl);
	connection_tls_error(con);
	if( err != 1 )
	{
		g_debug("setting connection_tls_accept_again_timeout_cb to %f",con->events.handshake_timeout.repeat);
		ev_timer_again(EV_A_ &con->events.handshake_timeout);

		int action = SSL_get_error(con->transport.tls.ssl, err);
		g_debug("SSL_accept failed %i %i read:%i write:%i", err, action, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE);

		connection_tls_error(con);
		switch( action )
		{
//		default:
		

		case SSL_ERROR_NONE:
			g_debug("%s:%i", __FILE__,  __LINE__);
			break;
		case SSL_ERROR_ZERO_RETURN:
			g_debug("%s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_READ:
			g_debug("SSL_WANT_READ %s:%i", __FILE__,  __LINE__);
			ev_io_init(&con->events.io_in, connection_tls_accept_again_cb, con->socket, EV_READ);
			ev_io_start(EV_A_ &con->events.io_in);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_WANT_WRITE %s:%i", __FILE__,  __LINE__);
			ev_io_init(&con->events.io_out, connection_tls_accept_again_cb, con->socket, EV_WRITE);
			ev_io_start(EV_A_ &con->events.io_out);
			break;

		case SSL_ERROR_WANT_ACCEPT:
			g_debug("SSL_ERROR_WANT_ACCEPT%s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_X509_LOOKUP %s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_SYSCALL:
			g_debug("SSL_ERROR_SYSCALL %s:%i", __FILE__,  __LINE__);
			connection_tls_disconnect(con);
			break;

		case SSL_ERROR_SSL:
			g_debug("SSL_ERROR_SSL %s:%i", __FILE__,  __LINE__);
			connection_tls_disconnect(con);
			break;

		}
	} else
	{
		g_debug("SSL_accept success");

		ev_timer_stop(EV_A_ &con->events.handshake_timeout);

		ev_timer_init(&con->events.idle_timeout, connection_tls_idle_timeout_cb, 0. ,con->events.idle_timeout.repeat);

		connection_established(con);

	}
}

void connection_tls_accept_again_timeout_cb (EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_HANDSHAKE_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	connection_tls_disconnect(con);
}

void connection_tls_disconnect(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	enum connection_state state = con->state;
	connection_set_state(con, connection_state_close);

	connection_disconnect(con);

	g_string_erase(con->transport.tls.io_in, 0, -1);
	g_string_erase(con->transport.tls.io_out, 0, -1);
	g_string_erase(con->transport.tls.io_out_again, 0, -1);
	con->transport.tls.io_out_again_size = 0;


	if( con->protocol.disconnect != NULL && 
		(state != connection_state_none &&
		 state != connection_state_connecting && 
		 state != connection_state_handshake) )
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

void connection_tls_connecting_cb(EV_P_ struct ev_io *w, int revents)
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
		ev_io_stop(EV_A_ &con->events.io_out);
		close(con->socket);
		connection_connect_next_addr(con);
		return;
	}

	connection_node_set_local(con);
	connection_node_set_remote(con);

	g_debug("connection %s -> %s", con->local.node_string, con->remote.node_string);

	if( con->transport.tls.ssl != NULL )
		SSL_free(con->transport.tls.ssl);

	con->transport.tls.ssl = SSL_new(con->transport.tls.ctx);
	SSL_set_fd(con->transport.tls.ssl, con->socket);

	ev_timer_init(&con->events.handshake_timeout, connection_tls_connect_again_timeout_cb, 0., con->events.handshake_timeout.repeat);

	connection_set_state(con, connection_state_handshake);
	connection_tls_connect_again_cb(EV_A_ w, revents);
}

void connection_tls_connecting_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_CONNECTING_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	ev_io_stop(EV_A_ &con->events.io_out);
	ev_timer_stop(EV_A_ &con->events.connecting_timeout);
	close(con->socket);
	con->socket = -1;
	connection_connect_next_addr(con);
}

void connection_tls_connect_again_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = NULL;
	if( w->events == EV_READ )
		con = CONOFF_IO_IN(w);
	else
		con	= CONOFF_IO_OUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);


	ev_io_stop(EV_A_ &con->events.io_in);
	ev_io_stop(EV_A_ &con->events.io_out);


	int err = SSL_connect(con->transport.tls.ssl);
	connection_tls_error(con);
	if( err != 1 )
	{
		ev_timer_again(EV_A_ &con->events.handshake_timeout);
		int action = SSL_get_error(con->transport.tls.ssl, err);
		connection_tls_error(con);

		switch( action )
		{
		case SSL_ERROR_NONE:
		case SSL_ERROR_ZERO_RETURN:
			g_debug("%s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_READ:
			g_debug("SSL_WANT_READ %s:%i", __FILE__,  __LINE__);
			ev_io_init(&con->events.io_in, connection_tls_connect_again_cb, con->socket, EV_READ);
			ev_io_start(EV_A_ &con->events.io_in);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_WANT_WRITE %s:%i", __FILE__,  __LINE__);
			ev_io_init(&con->events.io_out, connection_tls_connect_again_cb, con->socket, EV_WRITE);
			ev_io_start(EV_A_ &con->events.io_out);
			break;

		case SSL_ERROR_WANT_ACCEPT:
		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_* %i %s:%i", action, __FILE__,  __LINE__);
			break;

		case SSL_ERROR_SYSCALL:
		case SSL_ERROR_SSL:
			g_debug("SSL_ERROR_* %i %s:%i", action, __FILE__,  __LINE__);
			connection_tls_disconnect(con);
			break;

		}   
	} else
	{
		g_debug("SSL_connect success");
		ev_timer_stop(EV_A_ &con->events.handshake_timeout);
		ev_timer_init(&con->events.idle_timeout, connection_tls_idle_timeout_cb, 0. ,con->events.idle_timeout.repeat);
		connection_established(con);
	}
}

void connection_tls_sustain_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_SUSTAIN_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( con->protocol.sustain_timeout == NULL || con->protocol.sustain_timeout(con, con->protocol.ctx) == false )
		connection_close(con);
	else
		ev_timer_again(CL, &con->events.sustain_timeout);
}


void connection_tls_idle_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_IDLE_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( con->protocol.idle_timeout == NULL || con->protocol.idle_timeout(con, con->protocol.ctx) == false )
		connection_close(con);
	else
		ev_timer_again(CL, &con->events.idle_timeout);
}

void connection_tls_connect_again_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_HANDSHAKE_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	ev_timer_stop(EV_A_ &con->events.handshake_timeout);
	ev_io_stop(EV_A_ &con->events.io_out);
	close(con->socket);
	con->socket = -1;
	connection_connect_next_addr(con);
}



void connection_tls_error(struct connection *con)
{
	con->transport.tls.ssl_error = ERR_get_error();
	ERR_error_string(con->transport.tls.ssl_error, con->transport.tls.ssl_error_string);
	if( con->transport.tls.ssl_error != 0 )
		g_debug("SSL ERROR %s\t%s", con->transport.tls.ssl_error_string, SSL_state_string_long(con->transport.tls.ssl));
}

void connection_tls_listen_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_LISTEN_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( con->protocol.listen_timeout  != NULL && 
		con->protocol.listen_timeout(con, con->protocol.ctx) == true )
	{
		ev_timer_again(loop, &con->events.listen_timeout);
		return;
	}

	connection_set_state(con, connection_state_close);
	connection_disconnect(con);
	connection_free(con);
}

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


	if( getsockname(fd, from, &fromlen) != 0)
	{
		g_warning("sendtofrom: getsockname failed %s", strerror(errno) );
		return -1;
	}

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
		memcpy(&((struct in_pktinfo *)(CMSG_DATA(cmsgptr)))->ipi_addr.s_addr, ADDROFFSET(from),  sizeof(struct in_addr) );
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

				ev_timer_init(&peer->events.idle_timeout, connection_udp_idle_timeout_cb, 0. ,con->events.idle_timeout.repeat);
				ev_timer_init(&peer->events.sustain_timeout, connection_udp_sustain_timeout_cb, 0. ,con->events.sustain_timeout.repeat);
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

void connection_udp_sustain_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_SUSTAIN_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( con->protocol.sustain_timeout == NULL || con->protocol.sustain_timeout(con, con->protocol.ctx) == false )
	{
		ev_timer_stop(EV_A_ w);
		connection_udp_disconnect(con);
	} else
		ev_timer_again(CL, &con->events.sustain_timeout);
}

void connection_udp_idle_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_IDLE_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( con->protocol.idle_timeout == NULL || con->protocol.idle_timeout(con, con->protocol.ctx) == false )
	{
		ev_timer_stop(EV_A_ w);
		connection_udp_disconnect(con);
	} else
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

/*
 * dtls
 */

int _SSL_connection_index;

bool connection_dtls_mkcert(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	return mkcert(con->transport.dtls.ctx);
}

guint connection_addrs_hash(gconstpointer key)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, key);
	const struct connection *con = key;
	int local = con->local.port;
	int remote = (con->remote.port << 16);
	return local | remote;
}

gboolean connection_addrs_cmp(gconstpointer a, gconstpointer b)
{
	const struct connection *ca = a;
	const struct connection *cb = b;
	g_debug("%s con %p %p %s %s | %s %s", __PRETTY_FUNCTION__, a, b, 
			ca->local.node_string, cb->local.node_string,
			ca->remote.node_string, cb->remote.node_string);
	if( memcmp(&ca->local.addr, &cb->local.addr, sizeof(struct sockaddr_storage)) == 0 &&
		memcmp(&ca->remote.addr, &cb->remote.addr, sizeof(struct sockaddr_storage)) == 0)
		return true;
	return false;
}

void dtls_create_cookie(struct connection *con, unsigned char *hash, unsigned int *len)
{
	/* Create buffer with peer's address and port */
	g_debug("%s con %p %s:%s", __PRETTY_FUNCTION__, con, con->remote.ip_string, con->remote.port_string);
	int length = sizeof(in_port_t) + ADDRSIZE(&con->remote.addr);
	unsigned char buffer[length];
	memcpy(buffer, PORTOFFSET(&con->remote.addr), sizeof(in_port_t));
	memcpy(buffer + sizeof(in_port_t), ADDROFFSET(&con->remote.addr), ADDRSIZE(&con->remote.addr));

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), 
		 (const void*) con->transport.dtls.type.client.parent->transport.dtls.type.server.cookie_secret, DTLS_COOKIE_SECRET_LENGTH, 
		 (const unsigned char*) buffer, length, 
		 hash, len);
}

/** 
 * 
 * 
 * @param ssl
 * @param cookie
 * @param cookie_len
 * 
 * @return int 0 on error
 */
int dtls_generate_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int *len)
{
	struct connection *con = SSL_get_ex_data(ssl, _SSL_connection_index);
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
	dtls_create_cookie(con, cookie, len);
	return 1;
}

/** 
 * 
 * 
 * @param ssl
 * @param cookie
 * @param cookie_len
 * 
 * @return int 0 on error
 */
int dtls_verify_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int len)
{
	struct connection *con = SSL_get_ex_data(ssl, _SSL_connection_index);
	g_debug("%s con %p cookie %p len %i", __PRETTY_FUNCTION__, con, cookie, len);

	unsigned char _cookie[SHA_DIGEST_LENGTH];
	unsigned int _len;
	con->transport.dtls.type.client.flags |= DTLS_HAS_SEEN_THE_COOKIE;
	dtls_create_cookie(con, _cookie, &_len);

	if( len == _len && memcmp(_cookie, cookie, len) == 0 )
		return 1;
	return 0;
}

void connection_dtls_error(struct connection *con)
{
	con->transport.dtls.ssl_error = ERR_get_error();
	ERR_error_string(con->transport.dtls.ssl_error, con->transport.dtls.ssl_error_string);
	if( con->transport.dtls.ssl_error != 0 )
		g_debug("SSL ERROR %s\t%s", con->transport.dtls.ssl_error_string, SSL_state_string_long(con->transport.dtls.ssl));
}

void connection_dtls_connect_again(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_IN(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	g_debug("CLIENT state %s", SSL_state_string_long(con->transport.dtls.ssl));
	int err = SSL_connect(con->transport.dtls.ssl);
	connection_dtls_drain_bio(con);

	if( err != 1 )
		return;
	g_warning("connected!");
	connection_established(con);
	ev_io_start(EV_A_  &con->events.io_in);
}

void connection_dtls_accept_again(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_IN(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	g_debug("CLIENT state %s", SSL_state_string_long(con->transport.dtls.ssl));
	int err = SSL_accept(con->transport.dtls.ssl);

	if( err != 1 )
	{
		int action = SSL_get_error(con->transport.dtls.ssl, err);
		g_debug("SSL_accept failed %i %i read:%i write:%i", err, action, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE);
		connection_dtls_error(con);
		if( !(con->transport.dtls.type.client.flags & DTLS_HAS_SEEN_THE_COOKIE) )
		{
			g_warning("CLIENT CONNECT WITHOUT COOKIE!");
			g_hash_table_remove(con->transport.dtls.type.client.parent->transport.dtls.type.server.peers, con);
			connection_dtls_drain_bio(con);
			connection_free_cb(EV_A_ &con->events.free, 0);
			return;
		}
		switch( action )
		{
		case SSL_ERROR_NONE:
			g_debug("%s:%i", __FILE__,  __LINE__);
			break;
		case SSL_ERROR_ZERO_RETURN:
			g_debug("%s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_READ:
			g_debug("SSL_WANT_READ %s:%i", __FILE__,  __LINE__);
			connection_dtls_drain_bio(con);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_WANT_WRITE %s:%i", __FILE__,  __LINE__);
			connection_dtls_drain_bio(con);
			break;

		case SSL_ERROR_WANT_ACCEPT:
			g_debug("SSL_ERROR_WANT_ACCEPT%s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_X509_LOOKUP %s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_SYSCALL:
			g_debug("SSL_ERROR_SYSCALL %s:%i", __FILE__,  __LINE__);
//			connection_dtls_disconnect(con);
			break;

		case SSL_ERROR_SSL:
			g_debug("SSL_ERROR_SSL %s:%i", __FILE__,  __LINE__);
//			connection_dtls_disconnect(con);
			break;

		}
	} else
	{
		g_debug("SSL_accept success");
		ev_timer_stop(EV_A_ &con->events.handshake_timeout);

		// set protocol for accepted connection
		connection_protocol_set(con, &con->transport.dtls.type.client.parent->protocol);

		// copy connect timeout to new connection
//		ev_timer_init(&con->events.idle_timeout, connection_dtls_idle_timeout_cb, 0. ,con->events.idle_timeout.repeat);

		// create protocol specific data
		con->protocol.ctx = con->transport.dtls.type.client.parent->protocol.ctx_new(con);

		// teach new connection about parent
		if( con->transport.dtls.type.client.parent->protocol.origin != NULL )
			con->transport.dtls.type.client.parent->protocol.origin(con, con->transport.dtls.type.client.parent);

		connection_established(con);
/*
		struct incident *i;
		i = incident_new("dionaea.connection.dtls.accept");
		incident_value_con_set(i, "con", con);
		incident_report(i);
		incident_free(i);

		i = incident_new("dionaea.connection.link");
		incident_value_con_set(i, "parent", con->transport.dtls.type.client.parent);
		incident_value_con_set(i, "child", con);
		incident_report(i);
		incident_free(i);
*/  
	}
}

void connection_dtls_io_in(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_IN(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	unsigned char buf[64*1024];
	int r = SSL_read(con->transport.dtls.ssl, buf, 1024*64);
	if( r > 0)
	{
		g_debug("recv %.*s", r, buf);
		con->protocol.io_in(con, con->protocol.ctx, buf, r);
	}else
	{
		int action = SSL_get_error(con->transport.dtls.ssl, r);
		connection_dtls_error(con);
		switch( action )
		{
		case SSL_ERROR_NONE:
			g_debug("SSL_ERROR_NONE %s:%i", __FILE__,  __LINE__);
			break;
		case SSL_ERROR_ZERO_RETURN:
			g_debug("SSL_ERROR_ZERO_RETURN %s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_READ:
			g_debug("SSL_WANT_READ %s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_WANT_WRITE %s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_ACCEPT:
			g_debug("SSL_ERROR_WANT_ACCEPT%s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_X509_LOOKUP %s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_SYSCALL:
			g_debug("SSL_ERROR_SYSCALL %s:%i", __FILE__,  __LINE__);
			break;

		case SSL_ERROR_SSL:
			g_debug("SSL_ERROR_SSL %s:%i", __FILE__,  __LINE__);
			break;
		default:
			g_debug("SSL_ERROR %i %i",r, action);
		}
	}
}

void connection_dtls_drain_bio(struct connection *con)
{
	if( BIO_ctrl_pending(con->transport.dtls.writing) > 0 )
	{
		g_warning("need to flush the bio");
		unsigned char buf[64*1024];
		uint32_t size = BIO_read(con->transport.dtls.writing, buf, sizeof(buf));
		{
			struct udp_packet *packet = g_malloc0(sizeof(struct udp_packet));
			packet->data = g_string_new_len((void *)buf, size);
			memcpy(&packet->to, &con->remote.addr, sizeof(struct sockaddr_storage));
			memcpy(&packet->from, &con->local.addr, sizeof(struct sockaddr_storage));
			con->transport.dtls.io_out = g_list_append(con->transport.dtls.io_out, packet);
			connection_dtls_io_out_cb(g_dionaea->loop, &con->events.io_out, 0);
		}
	}
}

void connection_dtls_io_in_cb(struct ev_loop *loop, struct ev_io *w, int revents)
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
		if( con->type == connection_type_listen )
		{ /* we are a server -> find the peer */
			if( (peer = g_hash_table_lookup(con->transport.dtls.type.server.peers, con)) == NULL )
			{ /* no peer? create a new one */
				peer = connection_new(connection_transport_dtls);
				peer->transport.dtls.type.client.parent = con;
				peer->type = connection_type_accept;
				peer->state = connection_state_handshake;
				memcpy(&peer->local.addr, &con->local.addr, sizeof(struct sockaddr_storage));
				memcpy(&peer->remote.addr, &con->remote.addr, sizeof(struct sockaddr_storage));
				node_info_set(&peer->remote, &peer->remote.addr);
				node_info_set(&peer->local, &peer->local.addr);
				g_debug("new dtls peer %s %s", peer->local.node_string, peer->remote.node_string);
				peer->transport.dtls.type.client.parent = con;
				peer->transport.dtls.ctx = con->transport.dtls.ctx;
				peer->transport.dtls.ssl = SSL_new(peer->transport.dtls.ctx);
#if OPENSSL_VERSION_NUMBER >= 0x009080ffL // OpenSSL 0.9.8o 01 Jun 2010
				peer->transport.dtls.ssl->d1->listen = 1;
#endif
				SSL_CTX_set_session_cache_mode(peer->transport.dtls.ctx, SSL_SESS_CACHE_OFF);
				peer->transport.dtls.reading = BIO_new(BIO_s_mem());
				peer->transport.dtls.writing = BIO_new(BIO_s_mem());
				BIO_set_mem_eof_return(peer->transport.dtls.reading, -1);
				BIO_set_mem_eof_return(peer->transport.dtls.writing, -1);
				SSL_set_bio(peer->transport.dtls.ssl, peer->transport.dtls.reading, peer->transport.dtls.writing);
				SSL_set_accept_state(peer->transport.dtls.ssl);
#if OPENSSL_VERSION_NUMBER > 0x1000004fL // OpenSSL 1.0.0d 8 Feb 2011
				SSL_set_options(peer->transport.dtls.ssl, SSL_OP_COOKIE_EXCHANGE);
#endif
				SSL_set_ex_data(peer->transport.dtls.ssl, _SSL_connection_index, peer);
				g_hash_table_insert(con->transport.dtls.type.server.peers, peer, peer);
			}
			g_debug("%s -> %s %i bytes", peer->remote.node_string, peer->local.node_string, ret);
		}else
		if( con->type == connection_type_connect )
		{
			peer = con;
		}else
		{
			g_critical("Invalid connection for DTLS");
		}
		BIO_write(peer->transport.dtls.reading, buf, ret);

		switch( peer->state )
		{
		case connection_state_handshake:
			if( peer->type == connection_type_accept )
				connection_dtls_accept_again(EV_A_ &peer->events.io_in, EV_READ);
			else
			if( peer->type == connection_type_connect )
				connection_dtls_connect_again(EV_A_ &peer->events.io_in, EV_READ);
			break;
		case connection_state_established:
			connection_dtls_io_in(EV_A_ &peer->events.io_in, EV_READ);
			break;
		default:
			g_warning("UNHANDLED STATE");
		}
	}
	if( ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK )
	{
		g_warning("connection error %i %s", ret, strerror(errno));
	}
}

void connection_dtls_io_out_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct connection *con = CONOFF_IO_OUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	int fd = 0;
	switch( con->type )
	{
	case connection_type_connect:
		fd = con->socket;
		break;
	case connection_type_accept:
		fd = con->transport.dtls.type.client.parent->socket;
		break;
	default:
		g_warning("Invalid connection type!");
	}
	_connection_send_packets(con, fd, &con->transport.dtls.io_out);

//	g_debug(" done");
	if( g_list_length(con->transport.dtls.io_out) > 0 )
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
	};
	if( error > ECONMAX )
		return NULL;

	return myerrormsgs[error];
}
