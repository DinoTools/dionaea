/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <glib.h>
#include <ev.h>
#include <unistd.h>


#include "dionaea.h"
#include "threads.h"
#include "log.h"
#include "incident.h"
#include "connection.h"

#define D_LOG_DOMAIN "thread"


void threadpool_wrapper(gpointer data, gpointer user_data)
{
	struct thread *t = data;
#ifdef DEBUG
	GTimer *timer = g_timer_new();
#endif
	t->function(t->con, t->data);
#ifdef DEBUG
	g_timer_stop(timer);
	g_debug("Thread fn %p con %p data %p took %f ms", t->function, t->con, t->data, g_timer_elapsed(timer, NULL));
	g_timer_destroy(timer);
#endif
	g_free(data);
}

void trigger_cb(struct ev_loop *loop, struct ev_async *w, int revents)
{
	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	struct async_cmd *cmd;
	while( (cmd = g_async_queue_try_pop(aq)) != NULL )
	{
		cmd->function(cmd->data);
		g_free(cmd);
	}
	g_async_queue_unref(aq);
}

void surveillance_cb(struct ev_loop *loop, struct ev_periodic *w, int revents)
{
/*	g_debug("%s %i %i",
			__PRETTY_FUNCTION__,
			g_thread_pool_unprocessed(g_dionaea->threads->pool),
			g_thread_pool_get_max_threads(g_dionaea->threads->pool));
*/
	while( g_thread_pool_unprocessed(g_dionaea->threads->pool) >
		   g_thread_pool_get_max_threads(g_dionaea->threads->pool) )
	{
		g_critical("Threadpool is crowded %i/%i, suspending *all* activity",
				   g_thread_pool_unprocessed(g_dionaea->threads->pool),
				   g_thread_pool_get_max_threads(g_dionaea->threads->pool));
		sleep(1);
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


struct async_cmd *async_cmd_new(async_cmd_cb function, void *data)
{
	struct async_cmd *cmd = g_malloc0(sizeof(struct async_cmd));
	cmd->data = data;
	cmd->function = function;
	return cmd;
}

void async_incident_report(void *data)
{
	struct incident *i = data;
	incident_report(i);
	struct connection *con;
	if( incident_value_con_get(i, "con", &con ) )
		connection_unref(con);
	incident_free(i);
}
