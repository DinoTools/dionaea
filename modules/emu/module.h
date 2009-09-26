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

struct connection;
struct processor_data;
struct emu;
struct emu_env;
struct lcfgx_tree_node;

struct emu_ctx 
{
	struct emu_config *config;
	int offset;
};

struct emu_config
{
	struct 
	{
		int files;
		int filesize;
		int sockets;
		double sustain;
		double idle;
		int steps;
		double cpu;
	}limits;
};

void *proc_emu_ctx_new(void *cfg);
void proc_emu_ctx_free(void *ctx);
void *proc_emu_ctx_cfg_new(struct lcfgx_tree_node *node);
void proc_emu_on_io_in(struct connection *con, struct processor_data *pd);
void proc_emu_on_io_out(struct connection *con, struct processor_data *pd);

int run(struct emu *e, struct emu_env *env);
void profile(struct emu_config *conf, struct connection *con, void *data, unsigned int size, unsigned int offset);



void emulate_thread(gpointer data, gpointer user_data);
void emulate(struct emu_config *conf, struct connection *con, void *data, unsigned int size, unsigned int offset);

/* hooks.c */
struct emu_env;
struct emu_env_hook;

enum emu_state { running, waiting, failed };

struct emu_emulate_ctx 
{
	struct emu_config *config;

	GMutex *mutex;
	struct emu *emu;
	struct emu_env *env;

	/**
	 * mapping 'virtual' fd to struct connection *
	 */
	GHashTable *sockets;
	/**
	 * mapping struct connection * to int32_t processhandle
	 */
	GHashTable *processes;
	GHashTable *files;
	unsigned long steps;
	uint32_t esp;
	enum emu_state state;
	GTimer *time;

	int serial;
};

struct emu_file
{
	FILE *fh;
	char *path;
};

void user_hook_accept_cb(EV_P_ struct ev_io *w, int revents);
uint32_t user_hook_accept(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...);
void user_hook_connect_cb(EV_P_ struct ev_io *w, int revents);
uint32_t user_hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_close(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_recv(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
void user_hook_WaitForSingleObject_cb(EV_P_ struct ev_child *w,  int revents);
uint32_t user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_hook *hook, ...);


uint32_t user_hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CloseHandle(struct emu_env *env, struct emu_env_hook *hook, ...);
		 
int32_t	ll_win_hook_recv(struct emu_env *env, struct emu_env_hook *hook);
int32_t	ll_win_hook_accept(struct emu_env *env, struct emu_env_hook *hook);

extern struct processor proc_emu;
