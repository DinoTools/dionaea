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

#include <unistd.h>

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
#include "threads.h"
#include "dionaea.h"
#include "log.h"
#include "util.h"

#define D_LOG_DOMAIN "emulate"

int32_t emu_ll_w32_export_hook(struct emu_env *env, const char *exportname, int32_t (*llhook)(struct emu_env *env, struct emu_env_hook *hook), void *userdata)
{
	int numdlls=0;
	while( env->env.win->loaded_dlls[numdlls] != NULL )
	{
		struct emu_hashtable_item *ehi = emu_hashtable_search(env->env.win->loaded_dlls[numdlls]->exports_by_fnname, (void *)exportname);
		if( ehi != NULL )
		{
#if 0
			printf("hooked %s\n",  exportname);
#endif
			struct emu_env_hook *hook = (struct emu_env_hook *)ehi->value;
			hook->hook.win->fnhook = llhook;
			hook->hook.win->userdata = userdata;
			return 0;
		}
		numdlls++;
	}
#if 0
	printf("hooking %s failed\n", exportname);
#endif
	return -1;
}




void emulate(struct emu_config *conf, struct connection *con, void *data, unsigned int size, unsigned int offset)
{
	struct emu_emulate_ctx *ctx = g_malloc0(sizeof(struct emu_emulate_ctx));
	ctx->config = conf;

	ctx->sockets = g_hash_table_new(g_int_hash, g_int_equal);
	ctx->processes = g_hash_table_new(g_int_hash, g_int_equal);
	ctx->files = g_hash_table_new(g_int_hash, g_int_equal);

	ctx->emu = emu_new();
	ctx->env = emu_env_new(ctx->emu);
	struct emu_env * env = ctx->env;
	struct emu *e = ctx->emu;
	struct emu_cpu *cpu = emu_cpu_get(ctx->emu);
	ctx->env->userdata = ctx;
	ctx->mutex = g_mutex_new();
	ctx->serial = 67;

	emu_env_w32_load_dll(env->env.win,"ws2_32.dll");
	emu_ll_w32_export_hook(env, "accept", ll_win_hook_accept, NULL);
	emu_env_w32_export_hook(env, "bind", user_hook_bind, NULL);
	emu_env_w32_export_hook(env, "closesocket", user_hook_close, NULL);
	emu_env_w32_export_hook(env, "connect", user_hook_connect, NULL);

	emu_env_w32_export_hook(env, "listen", user_hook_listen, NULL);
	emu_ll_w32_export_hook(env, "recv", ll_win_hook_recv, NULL);
	emu_env_w32_export_hook(env, "send", user_hook_send, NULL);
	emu_env_w32_export_hook(env, "socket", user_hook_socket, NULL);
	emu_env_w32_export_hook(env, "WSASocketA", user_hook_WSASocket, NULL);
	emu_env_w32_export_hook(env, "CreateProcessA", user_hook_CreateProcess, NULL);
	emu_env_w32_export_hook(env, "WaitForSingleObject", user_hook_WaitForSingleObject, NULL);

	emu_env_w32_export_hook(env, "CreateFileA", user_hook_CreateFile, NULL);
	emu_env_w32_export_hook(env, "WriteFile", user_hook_WriteFile, NULL);
	emu_env_w32_export_hook(env, "CloseHandle", user_hook_CloseHandle, NULL);

//	emu_env_linux_syscall_hook(env, "exit", user_hook_exit, NULL);
//	emu_env_linux_syscall_hook(env, "socket", user_hook_socket, NULL);
//	emu_env_linux_syscall_hook(env, "bind", user_hook_bind, NULL);
//	emu_env_linux_syscall_hook(env, "listen", user_hook_listen, NULL);
//	emu_env_linux_syscall_hook(env, "accept", user_hook_accept, NULL);

#define CODE_OFFSET 0x417000

	int j;
	for( j=0; j<8; j++ )
		emu_cpu_reg32_set(cpu,j , 0);

// set flags
	emu_cpu_eflags_set(cpu, 0);

// write code to offset
	emu_memory_write_block(emu_memory_get(ctx->emu), CODE_OFFSET, data,  size);

// set eip to code
	emu_cpu_eip_set(emu_cpu_get(e), CODE_OFFSET + offset);
	emu_cpu_reg32_set(emu_cpu_get(e), esp, 0x0012fe98);
	emulate_thread(NULL, ctx);
}

void emulate_ctx_free(void *data)
{
	struct emu_emulate_ctx *ctx = data;

	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, ctx->files);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		g_debug("file key %p %i value %p \n", key, *(int *)key, value);
		struct tempfile *tf = value;
		tempfile_close(tf);
		tempfile_free(tf);
	}
	g_hash_table_destroy(ctx->files);

	g_hash_table_iter_init (&iter, ctx->processes);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		g_debug("process key %p %i value %p \n", key, *(int *)key, value);
	}
	g_hash_table_destroy(ctx->processes);

	g_hash_table_iter_init (&iter, ctx->sockets);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		g_debug("connection key %p %i value %p \n", key, *(int *)key, value);
		struct connection *con = value;
		if( con->state != connection_state_close )
		{/* avoid callbacks from connection_close() */
			close(con->socket);
			con->socket = -1;
		}

		g_free(key);

		con->protocol.ctx = NULL;
		con->events.free.repeat = .5;
		connection_free(con);
	}
	g_hash_table_destroy(ctx->sockets);

	if( ctx->time != NULL )
		g_timer_destroy(ctx->time);
}

void emulate_thread(gpointer data, gpointer user_data)
{
	struct emu_emulate_ctx *ctx = user_data;
	struct emu_config *conf = ctx->config;
	struct emu *e = ctx->emu;
	struct emu_env *env = ctx->env;
	int ret;

	g_mutex_lock(ctx->mutex);

	if( ctx->state == waiting )
		ctx->state = running;


	if( ctx->time == NULL )
		ctx->time = g_timer_new();
	else
		g_timer_continue(ctx->time);

	while( ctx->state == running )
	{
		if( (ctx->steps % (1024*1024)) == 0 )
		{
			g_debug("steps %li", ctx->steps);
			if( ctx->steps > conf->limits.steps )
			{
				g_info("shellcode took too many steps ... (%li steps)",  ctx->steps);
				ctx->state = failed;
				break;
			}
			if( conf->limits.cpu > 0. )
			{
				double elapsed = g_timer_elapsed(ctx->time, NULL);
				if( elapsed > conf->limits.cpu )
				{
					g_info("shellcode took too long ... (%f seconds)",  elapsed);
					ctx->state = failed;
					break;
				}
			}
		}
		ctx->steps++;
		struct emu_env_hook *hook = NULL;
		hook = emu_env_w32_eip_check(env);

		if( hook != NULL )
		{
			if( hook->hook.win->fnhook == NULL )
			{
				g_critical("unhooked call to %s", hook->hook.win->fnname);
				break;
			} else
				if( ctx->state == waiting )
				/* for now, we stop!
				 * had a blocking io call
				 * callback from main will come at a given point
				 * and requeue us to the threadpool
				 */
				goto unlock_and_return;
		} else
		{
			ret = emu_cpu_parse(emu_cpu_get(e));
			struct emu_env_hook *hook =NULL;
			if( ret != -1 )
			{
				hook = emu_env_linux_syscall_check(env);
				if( hook == NULL )
				{
					ret = emu_cpu_step(emu_cpu_get(e));
				} else
				{
					if( hook->hook.lin->fnhook != NULL )
					{
						hook->hook.lin->fnhook(env, hook);
						if( ctx->state == waiting )
							/* stop 
							 * as mentioned previously
							 */
							goto unlock_and_return;
					}
				}
			}

			if( ret == -1 )
			{
				g_debug("cpu error %s", emu_strerror(e));
				break;
			}
		}
	}

	g_timer_stop(ctx->time);

	if( ctx->state == failed )
		g_debug("emulating shellcode failed");

	g_mutex_unlock(ctx->mutex);

	double elapsed = g_timer_elapsed(ctx->time, NULL);
	g_debug("shellcode took %f seconds on cpu, %li steps", elapsed, ctx->steps);

	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	g_async_queue_push(aq, async_cmd_new(emulate_ctx_free, ctx));
	g_async_queue_unref(aq);
	ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);
	return;


	unlock_and_return:
	g_timer_stop(ctx->time);
	g_mutex_unlock(ctx->mutex);
}

int run(struct emu *e, struct emu_env *env)
{
	int j=0;
	int ret; //= emu_cpu_run(emu_cpu_get(e));

	for( j=0;j< 1000000;j++ )
	{
		struct emu_env_hook *hook = NULL;
		hook = emu_env_w32_eip_check(env);

		if( hook != NULL )
		{
			if( hook->hook.win->fnhook == NULL )
			{
				g_critical("unhooked call to %s", hook->hook.win->fnname);
				break;
			}
		} else
		{
			ret = emu_cpu_parse(emu_cpu_get(e));
			struct emu_env_hook *hook =NULL;
			if( ret != -1 )
			{
				hook = emu_env_linux_syscall_check(env);
				if( hook == NULL )
				{
					ret = emu_cpu_step(emu_cpu_get(e));
				} else
				{
					if( hook->hook.lin->fnhook != NULL )
						hook->hook.lin->fnhook(env, hook);
					else
						break;
				}
			}

			if( ret == -1 )
			{
				g_debug("cpu error %s", emu_strerror(e));
				break;
			}
		}
	}

	return 0;
}
