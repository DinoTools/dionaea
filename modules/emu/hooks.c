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

#define BACKUP_ESP(env) ((struct emu_emulate_ctx *)env->userdata)->esp = emu_cpu_reg32_get(emu_cpu_get(env->emu),esp)
#define RESTORE_ESP(env) emu_cpu_reg32_set(emu_cpu_get(env->emu),esp, ((struct emu_emulate_ctx *)env->userdata)->esp)

void dump_sockets(gpointer key, gpointer value,	gpointer user_data)
{
	printf("key %p %i value %p \n", key, *(int *)key, value);
}


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
	*(int *)con->protocol.ctx = con->socket;
	g_hash_table_insert(ctx->sockets, con->protocol.ctx, con);

	emu_cpu_reg32_set(c, eax, *(int32_t *)con->protocol.ctx);
	emu_cpu_eip_set(c, eip_save);

	connection_stop(con);

	GError *thread_error;
	struct thread *t = thread_new(NULL, ctx, emulate_thread);
	g_thread_pool_push(g_dionaea->threads->pool, t, &thread_error);

	return 0;
}


void proto_emu_established(struct connection *con)
{
	g_debug("%s con %p ctx %p",__PRETTY_FUNCTION__, con, con->protocol.ctx);
	hook_connection_accept_cb(con);
}

void proto_emu_connect_established(struct connection *con)
{
	g_debug("%s con %p ctx %p",__PRETTY_FUNCTION__, con, con->protocol.ctx);
	struct emu_emulate_ctx *ctx = con->data;

	connection_stop(con);
	GError *thread_error;
	struct thread *t = thread_new(NULL, ctx, emulate_thread);
	g_thread_pool_push(g_dionaea->threads->pool, t, &thread_error);
}


void proto_emu_error(struct connection *con, enum connection_error error)
{
	g_debug("%s con %p error %i",__PRETTY_FUNCTION__, con, error);
	struct emu_emulate_ctx *ctx = con->data;
//	g_message("error %i %s", error, connection_strerror(error));
	ctx->state = failed;
}

uint32_t proto_emu_io_in(struct connection *con, void *context, unsigned char *data, uint32_t size)
{
	g_debug("%s con %p ctx %p data %p size %i",__PRETTY_FUNCTION__, con, context, data, size);
	struct emu_emulate_ctx *ctx = con->data;

	connection_stop(con);

	GError *thread_error;
	struct thread *t = thread_new(NULL, ctx, emulate_thread);
	g_thread_pool_push(g_dionaea->threads->pool, t, &thread_error);
	return 0;
}

bool proto_emu_disconnect(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	struct emu_emulate_ctx *ctx = con->data;

	GError *thread_error;
	struct thread *t = thread_new(NULL, ctx, emulate_thread);
	g_thread_pool_push(g_dionaea->threads->pool, t, &thread_error);

	return false;
}

bool proto_emu_idle_timeout(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	struct emu_emulate_ctx *ctx = con->data;

	ctx->state = failed;

	return false;
}

bool proto_emu_sustain_timeout(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	struct emu_emulate_ctx *ctx = con->data;

	ctx->state = failed;

	return false;
}

bool proto_emu_listen_timeout(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	struct emu_emulate_ctx *ctx = con->data;

	ctx->state = failed;

	return false;
}

void *proto_emu_ctx_new(struct connection *con)
{
	g_debug("%s con %p ctx %p", __PRETTY_FUNCTION__, con, con->protocol.ctx);
	return con->protocol.ctx;
}

void proto_emu_ctx_free(void *context)
{
	g_debug("%s ctx %p ",__PRETTY_FUNCTION__, context);
}

struct protocol proto_emu = 
{
	.ctx_new = proto_emu_ctx_new,
	.ctx_free = proto_emu_ctx_free,
	.established = proto_emu_established,
	.error = proto_emu_error,
	.idle_timeout = proto_emu_idle_timeout,
	.listen_timeout = proto_emu_listen_timeout,
	.sustain_timeout = proto_emu_sustain_timeout,
	.disconnect = proto_emu_disconnect,
	.io_in = proto_emu_io_in,
	.ctx = NULL,
} ;

void async_connection_accept(void *data)
{
	g_debug("%s data %p", __PRETTY_FUNCTION__, data);
	struct connection *con = data;
	switch ( con->trans )
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

	case connection_transport_io:
	case connection_transport_udp:
		break;
	}

	if ( con->events.listen_timeout.repeat > 0. )
		ev_timer_again(CL, &con->events.listen_timeout);
}

int32_t	ll_win_hook_accept(struct emu_env *env, struct emu_env_hook *hook)
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
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL)
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

uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
	va_list vl;
	va_start(vl, hook);

	int s 					= va_arg(vl,  int);
	struct sockaddr* addr 	= va_arg(vl,  struct sockaddr *);
	/*socklen_t addrlen 		= */(void)va_arg(vl,  socklen_t );
	va_end(vl);

	struct connection *con;
	g_debug("socket ht %p", ctx->sockets);
	g_debug("s %i", s);

	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL)
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
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL)
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return -1;
	}

	con->protocol.established = proto_emu_connect_established;
	struct sockaddr_in *si = (struct sockaddr_in *)addr;
	char addrstr[128] = "::";
	inet_ntop(si->sin_family, &si->sin_addr, addrstr, 128); 
// 	int port = ntohs(si->sin_port)						  ;
// 	connection_connect(con, addrstr, port, NULL);													  ;

	connection_connect(con, "127.0.0.1", 4444, NULL);
	ctx->state = waiting;
	return 0;
}

uint32_t user_hook_close(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;

	va_list vl;
	va_start(vl, hook);
	int s 					= va_arg(vl,  int);
	va_end(vl);

	struct connection *con;
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL)
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return -1;
	}

//	g_hash_table_remove(ctx->sockets, &s);

	if( con->state != connection_state_close )
	{		
		GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
		g_async_queue_push(aq, async_cmd_new((async_cmd_cb)connection_close, con));
		g_async_queue_unref(aq);
		ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);
	}

	return 0;
}

uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
	va_list vl;
	va_start(vl, hook);

	int s 					= va_arg(vl,  int);
	/*int backlog			 	= */(void)va_arg(vl,  int);
	va_end(vl);

	struct connection *con;
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL)
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return 0;
	}


	// as we do not accept connections yet ...
	// duplicate code from connection_listen

	switch ( con->trans )
	{
	case connection_transport_tcp:
		con->type = connection_type_listen;

		if ( bind_local(con) != true )
			return -1;

		if ( listen(con->socket, 1) != 0 )
		{
			close(con->socket);
			con->socket = -1;
			g_warning("Could not listen %s:%i (%s)", con->local.hostname, ntohs(con->local.port), strerror(errno));
			ctx->state = failed;
			return 0;
		}
		connection_set_nonblocking(con);
		break;

	case connection_transport_tls:
	case connection_transport_io:
	case connection_transport_udp:
		return -1;
		break;
	}

    return 0;
}


void async_connection_io_in(void *data)
{
	g_debug("%s data %p", __PRETTY_FUNCTION__, data);
	struct connection *con = data;
	switch ( con->trans )
	{
	case connection_transport_tcp:
		ev_io_init(&con->events.io_in, connection_tcp_io_in_cb, con->socket, EV_READ);
		ev_io_start(CL, &con->events.io_in);
		break;

	case connection_transport_tls:
	case connection_transport_io:
	case connection_transport_udp:
		break;
	}

	if ( con->events.listen_timeout.repeat > 0. )
		ev_timer_again(CL, &con->events.listen_timeout);
}


int32_t	ll_win_hook_recv(struct emu_env *env, struct emu_env_hook *hook)
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
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL)
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return 0;
	}

	int returnvalue = 0;
	if( con->transport.tcp.io_in->len > 0 )
	{
		g_debug("data availible (%i bytes)",  (int)con->transport.tcp.io_in->len);
		returnvalue = MIN(con->transport.tcp.io_in->len, len);
		emu_cpu_reg32_set(c, eax, returnvalue);

		if ((int32_t)returnvalue > 0)
			emu_memory_write_block(emu_memory_get(env->emu), buf, con->transport.tcp.io_in->str, returnvalue);
		con->transport.tcp.io_in->len -= returnvalue;
		emu_cpu_eip_set(c, eip_save);
		return 0;
	}else
	{
		g_debug("recv connection state %s", connection_state_to_string(con->state));
		if( con->state == connection_state_close )
		{
			emu_cpu_reg32_set(c, eax, 0);
			emu_cpu_eip_set(c, eip_save);
			return 0;
		}
	}

	RESTORE_ESP(env);
	ctx->state = waiting;

	g_debug("polling for io in ...");
	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	g_async_queue_push(aq, async_cmd_new(async_connection_io_in, con));
	g_async_queue_unref(aq);
	ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);

	return 0;
}

uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;

	va_list vl;
	va_start(vl, hook);
	/* ssize_t send(int sockfd, const void *buf, size_t len, int flags); */
	int s		= va_arg(vl,  int);
	char* buf	= va_arg(vl,  char *);
	int len		= va_arg(vl,  int);
	/*int flags	= */(void)va_arg(vl,  int);
	va_end(vl);

	struct connection *con;
	if( (con = g_hash_table_lookup(ctx->sockets, &s)) == NULL)
	{
		g_warning("invalid socket requested %i", s);
		ctx->state = failed;
		return 0;
	}

	connection_send(con, buf, len);

	return len;
}

uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;

	va_list vl;
	va_start(vl, hook);
	/* int socket(int domain, int type, int protocol); */
	/*int domain 	= */(void)va_arg(vl,  int);
	int type 		= va_arg(vl,  int);
	/*int protocol 	= */(void)va_arg(vl, int);
	va_end(vl);

	struct connection *con = NULL;
	if( type == SOCK_STREAM )
		con = connection_new(connection_transport_tcp);

	if( con == NULL )
		return -1;

	/* this connection will not get free'd! */
	con->events.free.repeat = 0.;
	con->socket = socket(AF_INET, SOCK_STREAM, 0);
	memcpy(&con->protocol, &proto_emu, sizeof(struct protocol));
	con->protocol.ctx = g_malloc0(sizeof(int));
	*(int *)con->protocol.ctx = con->socket;
	con->data = ctx;
	g_hash_table_insert(ctx->sockets, con->protocol.ctx, con);

	return con->socket;
}

uint32_t user_hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
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
	/*char *lpFileName			=*/ va_arg(vl, char *);
	/*int dwDesiredAccess		=*/(void)va_arg(vl, int);
	/*int dwShareMode			=*/(void)va_arg(vl, int);
	/*int lpSecurityAttributes	=*/(void)va_arg(vl, int);
	/*int dwCreationDisposition	=*/(void)va_arg(vl, int);
	/*int dwFlagsAndAttributes	=*/(void)va_arg(vl, int);
	/*int hTemplateFile			=*/(void)va_arg(vl, int);
	va_end(vl);


	struct tempfile *tf = tempdownload_new("emu-");
	g_hash_table_insert(ctx->files, &tf->fd, tf);

	return (uint32_t)tf->fd;
}

uint32_t user_hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
	struct emu_emulate_ctx *ctx = env->userdata;
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
	uint32_t hFile				= va_arg(vl, uint32_t);
	void *lpBuffer 				= va_arg(vl, void *);
	int   nNumberOfBytesToWrite = va_arg(vl, int);
	/* int *lpNumberOfBytesWritten  =*/(void)va_arg(vl, int*);
	/* int *lpOverlapped 		    =*/(void)va_arg(vl, int*);
	va_end(vl);

	struct tempfile *tf = NULL;
	if( (tf = g_hash_table_lookup(ctx->files, &hFile)) == NULL)
	{
		g_warning("invalid file requested %i", hFile);
		ctx->state = failed;
		return 0;
	}

	fwrite(lpBuffer, nNumberOfBytesToWrite, 1, tf->fh);

	return 1;
}


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
	if( (tf = g_hash_table_lookup(ctx->files, &hObject)) != NULL)
	{
		tempfile_close(tf);
		return 0;
	}
	return 0;
}

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

	if ( pszCmdLine != NULL && strncasecmp(pszCmdLine, "cmd", 3) == 0 )
	{
	
		struct connection *con = NULL;
		if( (con = g_hash_table_lookup(ctx->sockets, &psiStartInfo->hStdInput)) == NULL)
		{
			g_warning("invalid socket requested %i", psiStartInfo->hStdInput);
	//		g_hash_table_foreach(ctx->sockets, dump_sockets, NULL);
			return 0;
		}
	
		struct incident *ix = incident_new("dionaea.module.emu.mkshell");
		incident_value_ptr_set(ix, "con", (uintptr_t)con);
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
	if( (con = g_hash_table_lookup(ctx->processes, &h)) != NULL)
	{
		ctx->state = waiting;
		return 0;
	}

	return 0;
}

uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	g_debug("%s env %p emu_env_hook %p ...", __PRETTY_FUNCTION__, env, hook);
//	struct emu_emulate_ctx *ctx = env->userdata;

	va_list vl;
	va_start(vl, hook);
	/* int socket(int domain, int type, int protocol); */
	int domain 		= va_arg(vl,  int);
	int type 		= va_arg(vl,  int);
	int protocol 	= va_arg(vl, int);
	(void)va_arg(vl, int);
	(void)va_arg(vl, int);
	(void)va_arg(vl, int);

	va_end(vl);

	return user_hook_socket(env, hook, domain, type, protocol);
}
