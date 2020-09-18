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
 * connection ssl
 *
 */

/*
 * the ssl dh key setup is taken from the mod_ssl package from apache
 */


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

			if( con->processor_data != NULL && size > 0 )
			{
				processors_io_out(con, con->transport.tls.io_out_again->str, size);
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

		if( con->processor_data != NULL && con->transport.tls.io_in->len > 0 )
                {
                    processors_io_in(con, con->transport.tls.io_in->str, con->transport.tls.io_in->len);
                }
		
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
	struct incident *i;
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


		ev_timer_init(&accepted->events.handshake_timeout, connection_tls_handshake_again_timeout_cb, 0., con->events.handshake_timeout.repeat);
//		ev_timer_init(&accepted->events.idle_timeout, connection_tls_accept_again_timeout_cb, 0., con->events.idle_timeout.repeat);


		// create protocol specific data
		accepted->protocol.ctx = accepted->protocol.ctx_new(accepted);


		accepted->stats.io_in.throttle.max_bytes_per_second = con->stats.io_in.throttle.max_bytes_per_second;
		accepted->stats.io_out.throttle.max_bytes_per_second = con->stats.io_out.throttle.max_bytes_per_second;

		// teach new connection about parent
		if( con->protocol.origin != NULL )
			con->protocol.origin(accepted, con);

		connection_set_state(accepted, connection_state_handshake);
		SSL_set_accept_state(accepted->transport.tls.ssl);

		accepted->events.io_in.events = EV_READ;
		connection_tls_handshake_again_cb(EV_A_ &accepted->events.io_in, 0);

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


void connection_tls_handshake_again_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = NULL;
	struct incident *i;

	if( w->events == EV_READ )
		con = CONOFF_IO_IN(w);
	else
		con	= CONOFF_IO_OUT(w);
	g_debug("%s con %p %i %p %p",__PRETTY_FUNCTION__, con, revents, CONOFF_IO_IN(w), CONOFF_IO_OUT(w));

	ev_io_stop(EV_A_ &con->events.io_in);
	ev_io_stop(EV_A_ &con->events.io_out);

	int err = SSL_do_handshake(con->transport.tls.ssl);
	connection_tls_error(con);
	if( err != 1 )
	{
		g_debug("setting connection_tls_accept_again_timeout_cb to %f",con->events.handshake_timeout.repeat);
		ev_timer_again(EV_A_ &con->events.handshake_timeout);

		int action = SSL_get_error(con->transport.tls.ssl, err);
		g_debug("SSL_do_handshake failed %i %i read:%i write:%i", err, action, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE);

		connection_tls_error(con);
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
			ev_io_init(&con->events.io_in, connection_tls_handshake_again_cb, con->socket, EV_READ);
			ev_io_start(EV_A_ &con->events.io_in);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_WANT_WRITE %s:%i", __FILE__,  __LINE__);
			ev_io_init(&con->events.io_out, connection_tls_handshake_again_cb, con->socket, EV_WRITE);
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
		g_debug("SSL_do_handshake success");
		ev_timer_stop(EV_A_ &con->events.handshake_timeout);
		ev_timer_init(&con->events.idle_timeout, connection_idle_timeout_cb, 0. ,con->events.idle_timeout.repeat);
		connection_established(con);

		i = incident_new("dionaea.connection.tls.accept");
		incident_value_con_set(i, "con", con);
		incident_report(i);
		incident_free(i);
	}
}

void connection_tls_handshake_again_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	struct connection *con = CONOFF_HANDSHAKE_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	switch( con->type )
	{
	case connection_type_connect:
		ev_timer_stop(EV_A_ &con->events.handshake_timeout);
		ev_io_stop(EV_A_ &con->events.io_out);
		close(con->socket);
		con->socket = -1;
		connection_connect_next_addr(con);
		break;
	case connection_type_accept:
		connection_tls_disconnect(con);
		break;
	case connection_type_listen:
	case connection_type_bind:
	case connection_type_none:
		break;
	}
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

	ev_timer_init(&con->events.handshake_timeout, connection_tls_handshake_again_timeout_cb, 0., con->events.handshake_timeout.repeat);

	connection_set_state(con, connection_state_handshake);

	SSL_set_connect_state(con->transport.tls.ssl);

	con->events.io_in.events = EV_READ;
	connection_tls_handshake_again_cb(EV_A_ &con->events.io_in, 0);
}

void connection_tls_error(struct connection *con)
{
	con->transport.tls.ssl_error = ERR_get_error();
	ERR_error_string(con->transport.tls.ssl_error, con->transport.tls.ssl_error_string);
	if( con->transport.tls.ssl_error != 0 )
		g_debug("SSL ERROR %s\t%s", con->transport.tls.ssl_error_string, SSL_state_string_long(con->transport.tls.ssl));
}
