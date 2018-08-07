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

#include <stdint.h>

#include <glib.h>
#include <unistd.h> // close

#include <emu/emu.h>
#include <emu/emu_memory.h>
#include <emu/emu_cpu.h>
#include <emu/emu_log.h>
#include <emu/emu_cpu_data.h>
#include <emu/emu_cpu_stack.h>
#include <emu/environment/emu_profile.h>
#include <emu/environment/emu_env.h>
#include <emu/environment/win32/emu_env_w32.h>
#include <emu/environment/win32/emu_env_w32_dll.h>
#include <emu/environment/win32/emu_env_w32_dll_export.h>
#include <emu/environment/win32/env_w32_dll_export_kernel32_hooks.h>
#include <emu/environment/linux/emu_env_linux.h>
#include <emu/emu_getpc.h>
#include <emu/emu_string.h>
#include <emu/emu_shellcode.h>

#include "connection.h"
#include "module.h"
#include "dionaea.h"
#include "threads.h"
#include "log.h"
#include "incident.h"
#include "util.h"

#define D_LOG_DOMAIN "hooks"

#define CL g_dionaea->loop

#define BACKUP_ESP(env) ((struct emu_emulate_ctx *)env->userdata)->esp = emu_cpu_reg32_get(emu_cpu_get((env)->emu),esp)
#define RESTORE_ESP(env) emu_cpu_reg32_set(emu_cpu_get(env->emu),esp, ((struct emu_emulate_ctx *)(env)->userdata)->esp)


#define CONTINUE_EMULATION(ctx) \
do \
{ \
	GError *thread_error = NULL; \
	struct thread *t = thread_new(NULL, (ctx), emulate_thread); \
	g_thread_pool_push(g_dionaea->threads->pool, t, &thread_error); \
} while (0)

void dump_sockets(gpointer key, gpointer value, gpointer user_data)
{
	printf("key %p %i value %p \n", key, *(int *)key, value);
}

/**
 * callback function for connection_established
 * we do not call this function in the callback itself, 
 * as the POP_* macros return, and the callback returns nothing
 * 
 * @param con    The connection
 * 
 * @return 0 on success 
 * @see proto_emu_accept_established 
 */
int32_t hook_connection_accept_cb(struct connection *con)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
	struct emu_emulate_ctx *ctx = con->data;
	struct emu_cpu *c = emu_cpu_get(ctx->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*SOCKET accept(
  SOCKET s,
  struct sockaddr* addr,
  int* addrlen
);*/

	uint32_t s;
	POP_DWORD(c, &s);

	uint32_t addr;
	POP_DWORD(c, &addr);

	uint32_t addrlen;
	POP_DWORD(c, &addrlen);

	con->protocol.ctx = g_malloc0(sizeof(int));
	*(int *)con->protocol.ctx = ctx->serial++;
	g_hash_table_insert(ctx->sockets, con->protocol.ctx, con);

	emu_cpu_reg32_set(c, eax, *(int32_t *)con->protocol.ctx);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

/**
 * callback funtion for protocol.origin
 * we stop the listening callback on the parent connection 
 * after we accepted a new connection
 * 
 * @param parent The listening connection
 * @param con    The accepted connection 
 * @see async_connection_accept 
 * @see protocol.origin 
 */
void proto_emu_origin(struct connection *con, struct connection *parent)
{
	connection_stop(parent);
}


/**
 * Callback for accepting connections for protocol.established
 *  
 * If a connection is established, the blocking accept() call 
 * can continue, and we can continue running the emulation 
 *  
 * @param con    The connection 
 * @see ll_win_hook_accept  
 * @see hook_connection_accept_cb 
 * @see protocol.established 
 */
void proto_emu_accept_established(struct connection *con)
{
	g_debug("%s con %p ctx %p",__PRETTY_FUNCTION__, con, con->protocol.ctx);
	struct emu_emulate_ctx *ctx = con->data;

	connection_stop(con);
	hook_connection_accept_cb(con);
	con->events.free.repeat = 0.;
	CONTINUE_EMULATION(ctx);
}

/**
 * Callback for connecting connections for protocol.established
 *  
 * If a connection is established after a blocking call to 
 * connect(), we can remove all events for the connection and 
 * continue the emulation.
 *  
 * @param con    The connection 
 * @see async_connection_connect 
 * @see user_hook_connect 
 * @see protocol.established 
 */
void proto_emu_connect_established(struct connection *con)
{
	g_debug("%s con %p ctx %p",__PRETTY_FUNCTION__, con, con->protocol.ctx);
	struct emu_emulate_ctx *ctx = con->data;

	connection_stop(con);

	CONTINUE_EMULATION(ctx);
}


/**
 * Callback for connect errors for protocol.error
 *  
 * Only possible when we connect somewhere blocking 
 * we already halted emulation and wait for the connection to 
 * finish 
 * in this case establishing the connection failed 
 *  
 * @param con    The connection
 * @param error 
 * @see user_hook_connect 
 * @see async_connection_connect 
 */ 
bool proto_emu_error(struct connection *con, enum connection_error error)
{
	g_debug("%s con %p error %i",__PRETTY_FUNCTION__, con, error);
	struct emu_emulate_ctx *ctx = con->data;

	connection_stop(con);
	ctx->state = failed;

	CONTINUE_EMULATION(ctx);
	return false;
}

/**
 * Callback for protocol.io_in
 * Once we received something, 
 * we disable all events for the connection
 * and continue the emulation
 * 
 * @param con     The connection
 * @param context The protocol context
 * @param data    The data we received
 * @param size    Size of the data we received
 * 
 * @return 0, as the shellcode will consume the data by itself 
 * @see protocol.io_in 
 */
uint32_t proto_emu_io_in(struct connection *con, void *context, unsigned char *data, uint32_t size)
{
	g_debug("%s con %p ctx %p data %p size %i",__PRETTY_FUNCTION__, con, context, data, size);
	struct emu_emulate_ctx *ctx = con->data;

	connection_stop(con);

	CONTINUE_EMULATION(ctx);
	return 0;
}


/**
 * Callback for protocol.io_out 
 *  
 * This callback is called if we wanted to send something, and 
 * our send buffer got flushed. 
 *  
 * We stop all events on the connection, and continue emulation.
 *  
 * This callback is required, as it is possible other api calls 
 * to the same connection may be done, and suspend all events 
 * for the connection, so the io_out buffer is never flushed. 
 *  
 * Currently send() is only used for the 4byte cookie during 
 * session negotiation of the 'link' protocol.<p> 
 * These 4 bytes which fits into a tcp buffer without problems, 
 * and can not cause problems therefore, but ... things may 
 * change.
 *  
 * @param con     The connection
 * @param context The protocol context
 */
void proto_emu_io_out(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p",__PRETTY_FUNCTION__, con, context);
	struct emu_emulate_ctx *ctx = con->data;

	connection_stop(con);

	CONTINUE_EMULATION(ctx);
	return;
}

/**
 * Callback for protocol.disconnect
 * This callback can only occur if the connection is waiting for io, 
 * like recv.
 * Therefore we can continue the emulation
 * 
 * @param con     The connection
 * @param context The protocol context
 * 
 * @return 0 
 * @see protocol.disconnect 
 */
bool proto_emu_disconnect(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	struct emu_emulate_ctx *ctx = con->data;

	CONTINUE_EMULATION(ctx);
	return false;
}

/**
 * Callback for protocol.idle_timeout
 * Not used yet
 * 
 * @param con
 * @param context
 * 
 * @return 
 *  
 * @see protocol.idle_timeout 
 */
bool proto_emu_idle_timeout(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	struct emu_emulate_ctx *ctx = con->data;

	ctx->state = failed;

	return false;
}

/**
 * Callback for protocol.sustain_timeout
 * 
 * Sustain timeouts can only happen if the connection is waiting for io,
 * like recv.
 * But we do not continue the emulation, 
 * as the return value will trigger the disconnect callback,
 * which will continue the emulation.
 * 
 * @param con     The connection
 * @param context
 * 
 * @return false, we do not want to reset the sustain timeout, we want to see this connection dead 
 * @see protocol.sustain_timeout 
 */
bool proto_emu_sustain_timeout(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	struct emu_emulate_ctx *ctx = con->data;

	ctx->state = failed;

	return false;
}

/**
 * Callback for protocol.listen_timeout
 * 
 * This callback can only occur if the connection is waiting for action, 
 * like accept().
 * Therefore it is safe to continue the emulation.
 * 
 * @param con     The connection
 * @param context The procotol context
 * 
 * @return false, this connection will be closed 
 * @see async_connection_accept 
 * @see ll_win_hook_accept 
 * @see protocol.listen_timeout
 */
bool proto_emu_listen_timeout(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	struct emu_emulate_ctx *ctx = con->data;

	connection_stop(con);
	ctx->state = failed;

	CONTINUE_EMULATION(ctx);
	return false;
}

/**
 * Callback for protocol.ctx_new
 * 
 * Does not create a new ctx, 
 * but returns the already created ctx instead
 * 
 * @param con    The connection
 * 
 * @return con->protocol.ctx 
 * @see protocol.ctx_new 
 */
void *proto_emu_ctx_new(struct connection *con)
{
	g_debug("%s con %p ctx %p", __PRETTY_FUNCTION__, con, con->protocol.ctx);
	return con->protocol.ctx;
}

/**
 * Callback for protocol.ctx_free
 * 
 * Does nothing
 * 
 * @param context The context we shall free 
 * @see protocol.ctx_free 
 */
void proto_emu_ctx_free(void *context)
{
	g_debug("%s ctx %p ",__PRETTY_FUNCTION__, context);
}

struct protocol proto_emu = 
{
	.name = "emulation",
	.ctx_new = proto_emu_ctx_new,
	.ctx_free = proto_emu_ctx_free,
	.origin = proto_emu_origin,
	.established = proto_emu_accept_established,
	.error = proto_emu_error,
	.idle_timeout = proto_emu_idle_timeout,
	.listen_timeout = proto_emu_listen_timeout,
	.sustain_timeout = proto_emu_sustain_timeout,
	.disconnect = proto_emu_disconnect,
	.io_in = proto_emu_io_in,
	.io_out = proto_emu_io_out,
	.ctx = NULL,
};

/**
 * Helper function for async_cmd
 * sets a connection into the ev_loop
 * waiting to accept new connections or listening timeout<p>
 * connection gets accepted
 *  * proto_emu_origin removes this connection from ev_loop
 *  * the emulation is continued by
 *    proto_emu_accept_established<p>
 * 
 * on timeout 
 *  * proto_emu_listen_timeout gets called, and the emulation
 *    is discarded<p>
 * 
 * @param data   The connection we want to listen for incoming connection
 * 
 * @see ll_win_hook_accept
 * @see proto_emu_origin
 * @see proto_emu_listen_timeout
 * @see proto_emu_accept_established
 * @see async_cmd
 */
void async_connection_accept(void *data)
{
	g_debug("%s data %p", __PRETTY_FUNCTION__, data);
	struct connection *con = data;
	struct emu_emulate_ctx *ctx = con->data;
	struct emu_config *conf = ctx->config;

	switch( con->trans )
	{
	case connection_transport_tcp:
		ev_io_init(&con->events.io_in, connection_tcp_accept_cb, con->socket, EV_READ);
		ev_set_priority(&con->events.io_in, EV_MAXPRI);
		ev_io_start(CL, &con->events.io_in);
		break;

	case connection_transport_tls:
		ev_set_priority(&con->events.io_in, EV_MAXPRI);
		ev_io_init(&con->events.io_in, connection_tls_accept_cb, con->socket, EV_READ);
		ev_io_start(CL, &con->events.io_in);
		break;

	case connection_transport_dtls:
	case connection_transport_io:
	case connection_transport_udp:
		break;
	}

	con->events.listen_timeout.repeat = conf->limits.listen;

	if( con->events.listen_timeout.repeat > 0. )
	{
		ev_timer_init(&con->events.listen_timeout, connection_listen_timeout_cb, 0., con->events.listen_timeout.repeat);
		ev_timer_again(CL, &con->events.listen_timeout);
	}
}

/**
 * libemu low level hook for accept()<p>
 * halts the emulation
 * restores ESP
 * does not touch EIP
 * async_connection_accept puts the connection into the ev_loop
 *  * io_in to accept new connections
 *  * listen_timeout to die when idle for too long
 * 
 * once the a new connection gets accepted
 *  * proto_emu_origin	removes the connection from the ev_loop
 *  * proto_emu_accept_established continues the emulation
 * 
 * @param env
 * @param hook
 * 
 * @return 0
 * @see async_connection_accept
 * @see proto_emu_accept_established
 * @see proto_emu_origin
 */
int32_t ll_win_hook_accept(struct emu_env *env, struct emu_env_hook *hook)
{
	g_debug("%s env %p hook %p", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;

	BACKUP_ESP(env);
	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*SOCKET accept(
  SOCKET s,
  struct sockaddr* addr,
  int* addrlen
);*/

	uint32_t s;
	POP_DWORD(c, &s);

	uint32_t addr;
	POP_DWORD(c, &addr);

	uint32_t addrlen;
	POP_DWORD(c, &addrlen);

	struct connection *con;
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL )
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return 0;
	}

	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	g_async_queue_push(aq, async_cmd_new(async_connection_accept, con));
	g_async_queue_unref(aq);
	ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);


	RESTORE_ESP(env);
	ctx->state = waiting;
	return 0;
}

/**
 * libemu hook for bind()
 * binds the socket to a host:port<p>
 * be aware connection_bind does not bind directly, it waits for
 * the final call to connection_connect or connection_listen, it
 * just stores the arguments in the connection<p>
 * therefore we bind in user_hook_listen
 * 
 * @param env
 * @param hook
 * 
 * @return 
 * @see user_hook_listen
 */
uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
	va_list vl;
	va_start(vl, hook);

	int s                   = va_arg(vl,  int);
	struct sockaddr* addr   = va_arg(vl,  struct sockaddr *);
	/*socklen_t addrlen 		= */(void)va_arg(vl,  socklen_t );
	va_end(vl);

	struct connection *con;
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL )
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return 0;
	}

	struct sockaddr_in *si = (struct sockaddr_in *)addr;
	char addrstr[128] = "::";
	inet_ntop(si->sin_family, &si->sin_addr, addrstr, 128); 
	int port = ntohs(si->sin_port);
	connection_bind(con, addrstr, port, NULL);

	return 0;
}

struct async_connect_helper
{
	struct connection *parent;
	struct connection *con;
	char *hostname;
	int port;
};

/**
 * Helper function for async_cmd
 * sets a connection into the ev_loop by calling connection_connect
 * 
 * @param data the required async_helper information 
 * @see user_hook_connect 
 */
void async_connection_connect(void *data)
{
	g_debug("%s data %p", __PRETTY_FUNCTION__, data);
	struct async_connect_helper *help = data;
	struct connection *con = help->con;
	con->protocol.established = proto_emu_connect_established;

	// bind to parent address
	connection_bind(help->con, help->parent->local.ip_string, 0, NULL);
	

	connection_connect(con, help->hostname, help->port, NULL);
//	connection_connect(con, "127.0.0.1", 4444, NULL);

	struct incident *i = incident_new("dionaea.connection.link");
	incident_value_con_set(i, "parent", help->parent);
	incident_value_con_set(i, "child", help->con);
	incident_report(i);
	incident_free(i);

	g_free(help->hostname);
	g_free(help);
}

/**
 * libemu callback for connect()
 *  
 * halts the emulation,
 * connects the socket,
 * puts it into the ev_loop<p>
 * waits for the callbacks
 * 
 * @param env
 * @param hook
 * 
 * @return 
 * @see async_connection_connect 
 * @see proto_emu_connect_established
 * @see proto_emu_error
 */
uint32_t user_hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;

	va_list vl;
	va_start(vl, hook);

	int s                   = va_arg(vl,  int);
	struct sockaddr* addr   = va_arg(vl,  struct sockaddr *);
	/*socklen_t addrlen		  =*/ (void) va_arg(vl,  socklen_t);

	va_end(vl);

	struct connection *con;
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL )
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return -1;
	}


	struct sockaddr_in *si = (struct sockaddr_in *)addr;
	char addrstr[128] = "::";
	if( inet_ntop(si->sin_family, &si->sin_addr, addrstr, 128) == NULL )
		ctx->state = failed;

	int port = ntohs(si->sin_port);

	struct async_connect_helper *help = g_malloc0(sizeof(struct async_connect_helper));
	help->parent = ctx->ctxcon;
	help->con = con;
	help->hostname = g_strdup(addrstr);
	help->port = port;

	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	g_async_queue_push(aq, async_cmd_new(async_connection_connect, help));
	g_async_queue_unref(aq);
	ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);

	ctx->state = waiting;
	return 0;
}



/**
 * libemu hook for close()
 * 
 * closes the connection
 * Does not remove the connection from our tracking, as we will 
 * cleanup later on. 
 *  
 * @param env
 * @param hook
 * 
 * @return 
 */
uint32_t user_hook_close(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;

	va_list vl;
	va_start(vl, hook);
	int s                   = va_arg(vl,  int);
	va_end(vl);

	struct connection *con;
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL )
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return -1;
	}

	if( con->state != connection_state_close )
	{
		GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
		g_async_queue_push(aq, async_cmd_new((async_cmd_cb)connection_close, con));
		g_async_queue_unref(aq);
		ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);
	}
	
	return 0;
}

struct async_listen_helper
{
	struct connection *parent;
	struct connection *con;
};


void async_connection_listen(void *a)
{
	struct async_listen_helper *help = a;
	struct incident *i = incident_new("dionaea.connection.tcp.listen");
	incident_value_con_set(i, "con", help->con);
	incident_report(i);
	incident_free(i);

	i = incident_new("dionaea.connection.link");
	incident_value_con_set(i, "parent", help->parent);
	incident_value_con_set(i, "child", help->con);
	incident_report(i);
	incident_free(i);

	connection_unref(help->con);
	g_free(help);
}

/**
 * libemu hook for listen()
 *  
 * we can not use connection_listen, as this would make the 
 * connection accepting connections directly. 
 *  
 * therefore we bind&listen here too 
 *  
 * @param env
 * @param hook
 * 
 * @return 
 * @see user_hook_bind 
 */
uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
	va_list vl;
	va_start(vl, hook);

	int s                   = va_arg(vl,  int);
	/*int backlog			 	= */(void)va_arg(vl,  int);
	va_end(vl);

	struct connection *con;
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL )
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return 0;
	}


	// as we do not accept connections yet ...
	// duplicate code from connection_listen

	switch( con->trans )
	{
	case connection_transport_tcp:
		con->type = connection_type_listen;

		if( bind_local(con) != true )
		{
			g_warning("Could not bind %s:%i (%s)", con->local.hostname, ntohs(con->local.port), strerror(errno));
			ctx->state = failed;
			return 0;
		}


		if( listen(con->socket, 1) != 0 )
		{
			close(con->socket);
			con->socket = -1;
			g_warning("Could not listen %s:%i (%s)", con->local.hostname, ntohs(con->local.port), strerror(errno));
			ctx->state = failed;
			return 0;
		}
		connection_set_nonblocking(con);

		struct async_listen_helper *help = g_malloc0(sizeof(struct async_listen_helper));
		help->parent = ctx->ctxcon;
		help->con = con;
		connection_ref(con);
		GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
		g_async_queue_push(aq, async_cmd_new(async_connection_listen, help));
		g_async_queue_unref(aq);
		ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);

		break;

	case connection_transport_dtls:
	case connection_transport_tls:
	case connection_transport_io:
	case connection_transport_udp:
		ctx->state = failed;
		return 0;
		break;
	}

	return 0;
}


/**
 * Helper function for ll_win_hook_recv
 * adds the connection to the ev_loop
 * 
 * @param data   the connection
 */
void async_connection_io_in(void *data)
{
	g_debug("%s data %p", __PRETTY_FUNCTION__, data);
	struct connection *con = data;
	struct emu_emulate_ctx *ctx = con->data;
	struct emu_config *conf = ctx->config;

	switch( con->trans )
	{
	case connection_transport_tcp:
		ev_io_init(&con->events.io_in, connection_tcp_io_in_cb, con->socket, EV_READ);
		ev_io_start(CL, &con->events.io_in);
		g_warning("at %f", con->events.sustain_timeout.at);
		g_warning("repeat %f", con->events.sustain_timeout.repeat);

		if( con->events.sustain_timeout.repeat == 0. )
			connection_sustain_timeout_set(con, conf->limits.sustain);
		else
			connection_sustain_timeout_set(con, ev_timer_remaining(CL, &con->events.sustain_timeout));
		break;

	case connection_transport_dtls:
	case connection_transport_tls:
	case connection_transport_io:
	case connection_transport_udp:
		break;
	}

	if( con->events.listen_timeout.repeat > 0. )
		ev_timer_again(CL, &con->events.listen_timeout);
}


/**
 * libemu callback for recv() 
 * if the underlying connection has
 *  * some bytes spare, use them
 *  * no bytes spare and
 *    * is connected
 *      * halt the emulation
 *   * add the socket to the ev_loop
 *    * is not connected any longer
 *      * set EAX to 0 (recv returned 0)
 * If the emulation gets halted, and the connection gets into
 * the ev_loop, we wait for io_in and sustain_timeout In case of
 * any, the callback will continue, and maybe finish the
 * emulation.
 * 
 * @param env
 * @param hook
 * 
 * @return 0
 * @see proto_emu_io_in
 * @see proto_emu_sustain_timeout
 * @see async_connection_io_in
 */
int32_t ll_win_hook_recv(struct emu_env *env, struct emu_env_hook *hook)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
	struct emu_cpu *c = emu_cpu_get(env->emu);

	BACKUP_ESP(env);
	uint32_t eip_save;

	POP_DWORD(c, &eip_save);
/*
int recv(
  SOCKET s,
  char* buf,
  int len,
  int flags
);
*/

	uint32_t s;
	POP_DWORD(c, &s);

	uint32_t buf;
	POP_DWORD(c, &buf);

	uint32_t len;
	POP_DWORD(c, &len);

	uint32_t flags;
	POP_DWORD(c, &flags);


	struct connection *con;
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL )
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return 0;
	}

	int returnvalue = 0;
	if( con->transport.tcp.io_in->len > 0 )
	{
		/** 
		 *  Case 1:
		 *  we still have data pending, so we can provide it to the
		 *  shellcode
		 */
		g_debug("data availible (%i bytes)",  (int)con->transport.tcp.io_in->len);
		returnvalue = MIN(con->transport.tcp.io_in->len, len);
		emu_cpu_reg32_set(c, eax, returnvalue);

		if( (int32_t)returnvalue > 0 )
			emu_memory_write_block(emu_memory_get(env->emu), buf, con->transport.tcp.io_in->str, returnvalue);
		g_string_erase(con->transport.tcp.io_in, 0, returnvalue);
		emu_cpu_eip_set(c, eip_save);
		return 0;
	}

	/**
	 * Case 2: 
	 * No data avalible
	 *  
	 */
	g_debug("recv connection state %s", connection_state_to_string(con->state));
	if( con->state == connection_state_close )
	{
		/**
		 * Case 2a: 
		 * Connection was closed, notify the shellcode about it by 
		 * returning 0 to recv() 
		 *  
		 */
		emu_cpu_reg32_set(c, eax, 0);
		emu_cpu_eip_set(c, eip_save);
		return 0;
	}

	/**
	 * Case 2b: 
	 * Connection is still alive, 
	 * discard emulation, 
	 * poll for data
	 *  
	 */

	RESTORE_ESP(env);
	ctx->state = waiting;

	g_debug("polling for io in ...");
	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	g_async_queue_push(aq, async_cmd_new(async_connection_io_in, con));
	g_async_queue_unref(aq);
	ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);

	return 0;
}

struct async_send_helper
{
	struct connection *con;
	void *data;
	int size;
};

/**
 * Helper function for connection_send
 * calls connection_send within the main loop
 * 
 * @param data   async_send_helper 
 * @see user_hook_send 
 */
void async_connection_send(void *data)
{
	struct async_send_helper *help = data;
	struct connection *con = help->con;
	connection_send(con, help->data, help->size);
	g_free(help->data);
	g_free(help);
}

/**
 * libemu hook for send()
 * 
 * send the data, enqueue in async_cmd, send from main loop, as 
 * sending may change the events of the connection 
 *  
 * Discards emulation and waits for	protocol.io_out to make sure 
 * the queue is flushed before proceeding, as more calls to the
 * connection may call connection_stop, preventing it from 
 * sending data. 
 *  
 * @param env
 * @param hook
 * 
 * @return 
 * @see async_connection_send 
 * @see async_cmd 
 */
uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;

	va_list vl;
	va_start(vl, hook);
	/* ssize_t send(int sockfd, const void *buf, size_t len, int flags); */
	int s       = va_arg(vl,  int);
	char* buf   = va_arg(vl,  char *);
	int len     = va_arg(vl,  int);
	/*int flags	= */(void)va_arg(vl,  int);
	va_end(vl);

	struct connection *con;
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL )
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return 0;
	}

	struct async_send_helper *help = g_malloc0(sizeof(struct async_send_helper));
	help->con = con;
	help->data = g_malloc0(len);
	memcpy(help->data, buf, len);
	help->size = len;

	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	g_async_queue_push(aq, async_cmd_new(async_connection_send, help));
	g_async_queue_unref(aq);
	ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);

	ctx->state = waiting;

	return len;
}

/**
 * libemu hook for socket()
 * 
 * create a new connection with the apropriate type, 
 * for now only tcp.
 * 
 * Set the connections free.repeat timeout to 0., 
 * so the connection is never! free'd, and we can rely on the pointers beeing valid all time
 * 
 * Create a 'fake' socket as protocol data, has to be uniq, therefore we use a serial. 
 * Associate the 'fake' socket with the connection in the 
 * hashtable. 
 * 
 * @param env
 * @param hook
 * 
 * @return the fake socket
 */
uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
	struct emu_config *conf = ctx->config;


	va_list vl;
	va_start(vl, hook);
	/* int socket(int domain, int type, int protocol); */
	/*int domain 	= */(void)va_arg(vl,  int);
	int type        = va_arg(vl,  int);
	/*int protocol 	= */(void)va_arg(vl, int);
	va_end(vl);


	if( g_hash_table_size(ctx->sockets) > conf->limits.sockets )
	{
		g_warning("Too many open sockets (%i)", g_hash_table_size(ctx->sockets));
		ctx->state = failed;
		return -1;
	}

	struct connection *con = NULL;
	if( type == SOCK_STREAM )
		con = connection_new(connection_transport_tcp);

	if( con == NULL )
		return -1;

	/* this connection will not get free'd! */
	con->events.free.repeat = 0.;

	con->socket = socket(AF_INET, SOCK_STREAM, 0);
	connection_protocol_set(con, &proto_emu);
	con->protocol.ctx = g_malloc0(sizeof(int));
	*(int *)con->protocol.ctx = ctx->serial++;
	con->data = ctx;
	g_hash_table_insert(ctx->sockets, con->protocol.ctx, con);

	return *(int *)con->protocol.ctx;
}

/**
 * libemu hook for CreateFile()<p>
 * Creates a tempfile.
 * 
 * @param env
 * @param hook
 * 
 * @return 
 * @see user_hook_WriteFile
 * @see user_hook_CloseHandle 
 * @see tempdownload_new 
 */
uint32_t user_hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
	struct emu_config *conf = ctx->config;

/*
HANDLE CreateFile(
  LPCTSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile
);
*/

	va_list vl;
	va_start(vl, hook);
	/*char *lpFileName			=*/(void)va_arg(vl, char *);
	/*int dwDesiredAccess		=*/(void)va_arg(vl, int);
	/*int dwShareMode			=*/(void)va_arg(vl, int);
	/*int lpSecurityAttributes	=*/(void)va_arg(vl, int);
	/*int dwCreationDisposition	=*/(void)va_arg(vl, int);
	/*int dwFlagsAndAttributes	=*/(void)va_arg(vl, int);
	/*int hTemplateFile			=*/(void)va_arg(vl, int);
	va_end(vl);

	if( g_hash_table_size(ctx->files) > conf->limits.files )
	{
		g_warning("Too many open files (%i)", g_hash_table_size(ctx->files));
		ctx->state = failed;
		return -1;
	}

	struct tempfile *tf = tempdownload_new("emu-");
	g_hash_table_insert(ctx->files, &tf->fd, tf);

	return(uint32_t)tf->fd;
}

/**
 * libemu hook for WriteFile()<p>
 * Writes to the tempfile
 * 
 * @param env
 * @param hook
 * 
 * @return 
 * @see user_hook_CreateFile
 * @see user_hook_CloseHandle
 */
uint32_t user_hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
	struct emu_config *conf = ctx->config;
/*
BOOL WriteFile(
  HANDLE hFile,
  LPCVOID lpBuffer,
  DWORD nNumberOfBytesToWrite,
  LPDWORD lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);
*/

	va_list vl;
	va_start(vl, hook);
	uint32_t hFile              = va_arg(vl, uint32_t);
	void *lpBuffer              = va_arg(vl, void *);
	int   nNumberOfBytesToWrite = va_arg(vl, int);
	/* int *lpNumberOfBytesWritten  =*/(void)va_arg(vl, int*);
	/* int *lpOverlapped 		    =*/(void)va_arg(vl, int*);
	va_end(vl);

	struct tempfile *tf = NULL;
	if( (tf = g_hash_table_lookup(ctx->files, &hFile)) == NULL )
	{
		g_warning("invalid file requested %i", hFile);
		ctx->state = failed;
		return 0;
	}

	if( tf->fd != -1 )
	{
		if( fwrite(lpBuffer, 1, nNumberOfBytesToWrite, tf->fh) != 1 )
		{
			g_warning("fwrite failed %s",  strerror(errno));
		}
		long size;
		if( (size = ftell(tf->fh)) >  conf->limits.filesize )
		{
			g_warning("File too large");
			ctx->state = failed;
		}
	}
	return 1;
}


/**
 * libemu hook for CloseHandle<p>
 * Closes the tempfile
 * 
 * @param env
 * @param hook
 * 
 * @return 
 * @see user_hook_CreateFile
 * @see user_hook_WriteFile 
 * @see tempfile_close 
 */
uint32_t user_hook_CloseHandle(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
/*	
BOOL CloseHandle(
  HANDLE hObject
);
*/

	va_list vl;
	va_start(vl, hook);
	uint32_t hObject = va_arg(vl, uint32_t);
	va_end(vl);

	struct tempfile *tf = NULL;
	if( (tf = g_hash_table_lookup(ctx->files, &hObject)) != NULL )
 	{
		/**
		 * if shellcode closes a file, it should be ready for further
		 * inspection, but we are in a thread, and if we submit an
		 * incident to report the new file, the file could be gone if
		 * the thread finishes before the incident is handled
		 * therefore we do not report the new file here, but wait for
		 * the shellcode emulation to finish, and report done files from
		 * the emulation_ctx_free function which is run from the
		 * main-process
		 * 
		 */
		tempfile_close(tf);
		return 0;
	}
	return 0;
}

/**
 * libemu hook for CreateProcess<p>
 * If a cmd redirect is requested, the 'fake' socket is used as
 * threadid for later use in WaitForSingleObject
 * 
 * @param env
 * @param hook
 * 
 * @return 
 * @see user_hook_WaitForSingleObject
 */
uint32_t user_hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;

	va_list vl;
	va_start(vl, hook);

	/* char *pszImageName				  = */ (void)va_arg(vl, char *);
	char *pszCmdLine                   = va_arg(vl, char *);               
	/* void *psaProcess, 				  = */ (void)va_arg(vl, void *);
	/* void *psaThread,  				  = */ (void)va_arg(vl, void *);
	/* bool fInheritHandles,              = */ (void)va_arg(vl, char *);
	/* uint32_t fdwCreate,                = */ (void)va_arg(vl, uint32_t);
	/* void *pvEnvironment             	  = */ (void)va_arg(vl, void *);
	/* char *pszCurDir                 	  = */ (void)va_arg(vl, char *);
	STARTUPINFO *psiStartInfo          = va_arg(vl, STARTUPINFO *);
	PROCESS_INFORMATION *pProcInfo     = va_arg(vl, PROCESS_INFORMATION *); 
	va_end(vl);

	if( pszCmdLine != NULL && strncasecmp(pszCmdLine, "cmd", 3) == 0 )
	{

		struct connection *con = NULL;
		if( (con = g_hash_table_lookup(ctx->sockets, &psiStartInfo->hStdInput)) == NULL )
		{
			g_warning("invalid socket requested %i", psiStartInfo->hStdInput);
			//		g_hash_table_foreach(ctx->sockets, dump_sockets, NULL);
			return 0;
		}

		struct incident *ix = incident_new("dionaea.module.emu.mkshell");
		incident_value_con_set(ix, "con", con);
		connection_ref(con);
		GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
		g_async_queue_push(aq, async_cmd_new(async_incident_report, ix));
		g_async_queue_unref(aq);
		ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);

		//	psiStartInfo = NULL;
		//	pProcInfo = NULL;

		pProcInfo->hProcess = *(int *)con->protocol.ctx;
		g_hash_table_insert(ctx->processes, con->protocol.ctx, con);
	}

	return 0;
}

/**
 * libemu hook for WaitForSingleObject<p>
 * halts the emulation if the processid is known
 * 
 * @param env
 * @param hook
 * 
 * @return 
 * @see user_hook_CreateProcess
 */
uint32_t user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;

	/*
	DWORD WINAPI WaitForSingleObject(
	  HANDLE hHandle,
	  DWORD dwMilliseconds
	);
	*/

	va_list vl;
	va_start(vl, hook);

	int32_t hHandle = va_arg(vl, int32_t);
	/*int32_t dwMilliseconds = */ (void)va_arg(vl, int32_t);
	va_end(vl);

	struct connection *con = NULL;
	int h = hHandle;
	if( (con = g_hash_table_lookup(ctx->processes, &h)) != NULL )
	{
		ctx->state = waiting;
		return 0;
	}

	return 0;
}

/**
 * libemu hook for WSASocket()
 * 
 * calls user_hook_socket
 * 
 * @param env
 * @param hook
 *  
 * @see user_hook_socket 
 *  
 * @return 
 */
uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
//	struct emu_emulate_ctx *ctx = env->userdata;

	va_list vl;
	va_start(vl, hook);
	/* int socket(int domain, int type, int protocol); */
	int domain      = va_arg(vl,  int);
	int type        = va_arg(vl,  int);
	int protocol    = va_arg(vl, int);
	(void)va_arg(vl, int);
	(void)va_arg(vl, int);
	(void)va_arg(vl, int);

	va_end(vl);

	return user_hook_socket(env, hook, domain, type, protocol);
}



/**
 * libemu hook for _lcreat()<p>
 * Creates a tempfile.
 * 
 * @param env
 * @param hook
 * 
 * @return 
 * @see user_hook__lwrite
 * @see user_hook__lclose
 * @see tempdownload_new 
 */
uint32_t user_hook__lcreat(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
	struct emu_config *conf = ctx->config;

	va_list vl;
	va_start(vl, hook);
	/*char *lpFileName			=*/(void)va_arg(vl, char *);
	/*int dwDesiredAccess		=*/(void)va_arg(vl, int);
	va_end(vl);

	if( g_hash_table_size(ctx->files) > conf->limits.files )
	{
		g_warning("Too many open files (%i)", g_hash_table_size(ctx->files));
		ctx->state = failed;
		return -1;
	}

	struct tempfile *tf = tempdownload_new("emu-");
	g_hash_table_insert(ctx->files, &tf->fd, tf);

	return(uint32_t)tf->fd;
}

/**
 * libemu hook for _lwrite()<p>
 * Writes to the tempfile
 * 
 * @param env
 * @param hook
 * 
 * @return 
 * @see user_hook__lcreat
 * @see user_hook__lclose
 */
uint32_t user_hook__lwrite(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
	struct emu_config *conf = ctx->config;

	va_list vl;
	va_start(vl, hook);
	uint32_t hFile              = va_arg(vl, uint32_t);
	void *lpBuffer              = va_arg(vl, void *);
	int   nNumberOfBytesToWrite = va_arg(vl, int);
	va_end(vl);

	struct tempfile *tf = NULL;
	if( (tf = g_hash_table_lookup(ctx->files, &hFile)) == NULL )
	{
		g_warning("invalid file requested %i", hFile);
		ctx->state = failed;
		return 0;
	}

	if( tf->fd != -1 )
	{
		if( fwrite(lpBuffer, 1, nNumberOfBytesToWrite, tf->fh) != 1 )
		{
			g_warning("fwrite failed %s",  strerror(errno));
		}
		long size;
		if( (size = ftell(tf->fh)) >  conf->limits.filesize )
		{
			g_warning("File too large");
			ctx->state = failed;
		}
	}
	return 1;
}


/**
 * libemu hook for _lclose<p>
 * Closes the tempfile
 * 
 * @param env
 * @param hook
 * 
 * @return 
 * @see user_hook__lcreat
 * @see user_hook__lwrite
 * @see tempfile_close 
 */
uint32_t user_hook__lclose(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;

	va_list vl;
	va_start(vl, hook);
	uint32_t hObject = va_arg(vl, uint32_t);
	va_end(vl);

	struct tempfile *tf = NULL;
	if( (tf = g_hash_table_lookup(ctx->files, &hObject)) != NULL )
 	{
		tempfile_close(tf);
		return 0;
	}
	return 0;
}

