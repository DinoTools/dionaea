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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
int dtls_verify_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int len)
#else
int dtls_verify_cookie_cb(SSL *ssl, const unsigned char *cookie, unsigned int len)
#endif
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
			connection_free_cb(EV_A_ &con->events.free, 0, true);
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
#if OPENSSL_VERSION_NUMBER < 0x10100000L // OpenSSL 1.1.0
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
