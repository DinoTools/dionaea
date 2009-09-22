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

#include <glib.h>
#include <ev.h>


struct connection;


struct threads
{
	GThreadPool *pool;
	struct ev_async trigger;
	struct ev_periodic surveillance;
	GAsyncQueue *cmds;
};

void trigger_cb(struct ev_loop *loop, struct ev_async *w, int revents);
void surveillance_cb(struct ev_loop *loop, struct ev_periodic *w, int revents);
void threadpool_wrapper(gpointer data, gpointer user_data);


struct thread
{
	GFunc function;
	struct connection *con;
	void *data;
};

struct thread *thread_new(struct connection *con, void *data, GFunc function);


/**
 * prototype for callbacks and data which are meant to be run in 
 * the main loop - from threads 
 * @see threads.cmds 
 */
typedef void (*async_cmd_cb)(void *data);


/**
 * data for async cmds
 * pointer to function and data, 
 * insert into dionaea->threads.cmds
 * trigger dionaea->threads.trigger
 * and your function will be run in the main loop
 * 
 * @see threads.cmds
 * @see threads.trigger
 */
struct async_cmd
{
	async_cmd_cb function;
	void *data;
};


struct async_cmd *async_cmd_new(async_cmd_cb function, void *data);
void async_cmd_free(struct async_cmd *cmd);
/*
void async_add_io(void *data);
void async_del_io(void *data);

void async_add_child(void *data);
void async_del_child(void *data);
*/
void async_incident_report(void *data);
