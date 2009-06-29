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

#include <stdlib.h>
#include <glib.h>
#include <ev.h>
#include <unistd.h>


#include "dionaea.h"
#include "threads.h"
#include "log.h"

#define D_LOG_DOMAIN "thread"


void threadpool_wrapper(gpointer data, gpointer user_data)
{
	struct thread *t = data;
	t->function(t->con, t->data);
	g_free(data);
}

void trigger_cb(struct ev_loop *loop, struct ev_async *w, int revents)
{
	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	struct async_cmd *cmd;
	while ( (cmd = g_async_queue_try_pop(aq)) != NULL )
	{
		cmd->function(cmd->data);
		g_free(cmd);
	}
	g_async_queue_unref(aq);
}

void thread_test(gpointer a, gpointer b)
{
	int s = rand()%10;
	g_debug("%p sleeping %i", g_thread_self(), s);
	sleep(s);
	g_debug("%p done", g_thread_self());
}

void surveillance_cb(struct ev_loop *loop, struct ev_periodic *w, int revents)
{
	g_debug("%s %i %i", 
			__PRETTY_FUNCTION__,
			g_thread_pool_unprocessed(g_dionaea->threads->pool),
			g_thread_pool_get_max_threads(g_dionaea->threads->pool));

	bool crowded = false;
	while( g_thread_pool_unprocessed(g_dionaea->threads->pool) > 
		   g_thread_pool_get_max_threads(g_dionaea->threads->pool) )
	{
		g_critical("Threadpool is crowded %i/%i, suspending *all* activity",
				   g_thread_pool_unprocessed(g_dionaea->threads->pool),
				   g_thread_pool_get_max_threads(g_dionaea->threads->pool));
		sleep(1);
		crowded = true;
	}

	if( crowded == false )
	{
		int m = rand()%15;
		g_debug("creating %i jobs", m);
		for( int i=0;i<m;i++ )
		{
			struct thread *t = thread_new(NULL, NULL, thread_test);
			g_thread_pool_push(g_dionaea->threads->pool, t, NULL);
		}
	}

}


struct thread *thread_new(struct connection *con, void *data, GFunc function)
{
	struct thread *t = g_malloc0(sizeof(struct thread));
	t->con = con;
	t->data = data;
	t->function = function;
	return t;
}

