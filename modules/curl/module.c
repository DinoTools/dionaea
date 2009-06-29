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
#include <stdio.h>

#include <lcfg/lcfg.h>
#include <lcfgx/lcfgx_tree.h>
#include <curl/curl.h>

#include "config.h"
#include "modules.h"
#include "connection.h"
#include "dionaea.h"

#include "module.h"
#include "incident.h"
#include "log.h"

#define D_LOG_DOMAIN "curl"

static struct 
{
	struct lcfgx_tree_node *config;
	struct ev_timer timer_event;
	CURLM *multi;
	int prev_running;
	int still_running;
	struct ihandler *ihandler;
} curl_runtime;


struct session
{
	CURL *easy;
	char *url;
	char error[CURL_ERROR_SIZE];
};

struct session_socket
{
	curl_socket_t sockfd;
	struct session *session;
	int action;
	struct ev_io io;
};


static void timer_cb(struct ev_loop *loop,  struct ev_timer *w, int revents);

/* Update the event timer after curl_multi library calls */
static int multi_timer_cb(CURLM *multi, long timeout_ms)
{
	g_debug("%s %li", __PRETTY_FUNCTION__,  timeout_ms);
	ev_timer_stop(g_dionaea->loop, &curl_runtime.timer_event);
	if( timeout_ms > 0 )
	{
		double  t = timeout_ms / 1000;
		ev_timer_init(&curl_runtime.timer_event, timer_cb, t, 0.);
		ev_timer_start(g_dionaea->loop, &curl_runtime.timer_event);
	} else
		timer_cb(g_dionaea->loop, &curl_runtime.timer_event, 0);
	return 0;
}

/* Check for completed transfers, and remove their easy handles */
static void check_run_count(void)
{
	g_debug("%s prev %i still %i", __PRETTY_FUNCTION__, curl_runtime.prev_running, curl_runtime.still_running);
	if( curl_runtime.prev_running > curl_runtime.still_running )
	{
		char *eff_url=NULL;
		CURLMsg *msg;
		int msgs_left;
		struct session *conn=NULL;
		CURL*easy;
		CURLcode res;

		g_debug("REMAINING: %d", curl_runtime.still_running);
		easy=NULL;
		while( (msg = curl_multi_info_read(curl_runtime.multi, &msgs_left)) )
		{
			if( msg->msg == CURLMSG_DONE )
			{
				easy=msg->easy_handle;
				curl_easy_getinfo(easy, CURLINFO_PRIVATE, &conn);
				curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &eff_url);
				if ( msg->data.result == CURLE_OK )
				{
					g_debug("DONE: %s => (%d) %s", eff_url, res, conn->error);
				}else
				{
					g_debug("FAIL: %s => (%d) %s", eff_url, msg->data.result, conn->error);
				}
				curl_multi_remove_handle(curl_runtime.multi, easy);
				curl_easy_cleanup(easy);
				g_free(conn->url);
				g_free(conn);
			}
		}
	}
	curl_runtime.prev_running = curl_runtime.still_running;
}

static void event_cb(struct ev_loop *loop,  struct ev_io *w, int revents)
{
	g_debug("%s  w %p revents %i", __PRETTY_FUNCTION__, w, revents);
	CURLMcode rc;

	int action = (revents&EV_READ?CURL_POLL_IN:0)|(revents&EV_WRITE?CURL_POLL_OUT:0);
	do
	{
		rc = curl_multi_socket_action(curl_runtime.multi, w->fd, action, &curl_runtime.still_running);
	} while( rc == CURLM_CALL_MULTI_PERFORM );

	check_run_count();

	if( curl_runtime.still_running <= 0 )
	{
		g_debug("last transfer done, kill timeout");
		ev_timer_stop(g_dionaea->loop, &curl_runtime.timer_event);
	}
}



static void timer_cb(struct ev_loop *loop,  struct ev_timer *w, int revents)
{
	g_debug("%s  w %p revents %i", __PRETTY_FUNCTION__, w, revents);
	CURLMcode rc;
	do
	{
		rc = curl_multi_socket_action(curl_runtime.multi, CURL_SOCKET_TIMEOUT, 0, &curl_runtime.still_running);
	} while( rc == CURLM_CALL_MULTI_PERFORM );
	check_run_count();
}

static void session_info_free(struct session_socket *info)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	if( info )
	{
		if( ev_is_active(&info->io) )
			ev_io_stop(g_dionaea->loop, &info->io);
		g_free(info);
	}
}

static void session_set_socket(struct session *session, struct session_socket *info, curl_socket_t s, int action)
{
	g_debug("%s", __PRETTY_FUNCTION__);

	int kind = (action&CURL_POLL_IN?EV_READ:0)|(action&CURL_POLL_OUT?EV_WRITE:0);

	info->sockfd = s;
	info->action = action;
	info->session = session;
	if( ev_is_active(&info->io) )
		ev_io_stop(g_dionaea->loop, &info->io);
	ev_io_init(&info->io, event_cb, info->sockfd, kind);
	if( kind != 0 )
		ev_io_start(g_dionaea->loop, &info->io);
}

/* CURLMOPT_SOCKETFUNCTION */
static int curl_socketfunction_cb(CURL *easy, curl_socket_t s, int action, void *cbp, void *sockp)
{
	g_debug("%s e %p s %i what %i cbp %p sockp %p", __PRETTY_FUNCTION__, easy, s, action, cbp, sockp);

	struct session_socket *info = (struct session_socket*) sockp;
	struct session *conn;
	curl_easy_getinfo(easy, CURLOPT_PRIVATE, &conn);

	const char *action_str[]={ "none", "IN", "OUT", "INOUT", "REMOVE"};

	g_debug("socket callback: s=%d e=%p what=%s ", s, easy, action_str[action]);
	if( action == CURL_POLL_REMOVE )
	{
		session_info_free(info);
	} else
	{
		if( !info )
		{
			g_debug("Adding data: %s", action_str[action]);
			info = g_malloc0(sizeof(struct session_socket));
			session_set_socket(conn, info, s, action);
			curl_multi_assign(curl_runtime.multi, s, info);
		} else
		{
			g_debug("Changing action from %s to %s", action_str[info->action], action_str[action]);
			session_set_socket(conn, info, s, action);
		}
	}
	return 0;
}



/* CURLOPT_WRITEFUNCTION */
static size_t curl_writefunction_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
	size_t realsize = size * nmemb;
	struct session *conn = (struct session *) data;
	(void)ptr;
	(void)conn;
	return realsize;
}


/* CURLOPT_PROGRESSFUNCTION */
static int curl_progressfunction_cb (void *p, double dltotal, double dlnow, double ult,
									 double uln)
{
	struct session *conn = (struct session *)p;
	(void)ult;
	(void)uln;

	g_debug("Progress: %s (%g/%g)", conn->url, dlnow, dltotal);
	return 0;
}


/* Create a new easy handle, and add it to the global curl_multi */
static void session_new(char *url)
{
	struct session *conn;
	CURLMcode rc;

	conn = g_malloc0(sizeof(struct session));
	conn->error[0]='\0';

	conn->easy = curl_easy_init();
	if( !conn->easy )
	{
		g_error("curl_easy_init() failed, exiting!");
	}
	conn->url = g_strdup(url);

	curl_easy_setopt(conn->easy, CURLOPT_URL, conn->url);
	curl_easy_setopt(conn->easy, CURLOPT_WRITEFUNCTION, curl_writefunction_cb);
	curl_easy_setopt(conn->easy, CURLOPT_WRITEDATA, &conn);
//	curl_easy_setopt(conn->easy, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(conn->easy, CURLOPT_ERRORBUFFER, conn->error);
	curl_easy_setopt(conn->easy, CURLOPT_PRIVATE, conn);
	curl_easy_setopt(conn->easy, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(conn->easy, CURLOPT_PROGRESSFUNCTION, curl_progressfunction_cb);
	curl_easy_setopt(conn->easy, CURLOPT_PROGRESSDATA, conn);
	curl_easy_setopt(conn->easy, CURLOPT_LOW_SPEED_TIME, 3L);
	curl_easy_setopt(conn->easy, CURLOPT_LOW_SPEED_LIMIT, 10L);

	g_debug("Adding easy %p to multi %p (%s)", conn->easy, curl_runtime.multi, url);
	rc = curl_multi_add_handle(curl_runtime.multi, conn->easy);
//	curl_runtime.prev_running++;
	do
	{
		rc = curl_multi_socket_all(curl_runtime.multi, &curl_runtime.still_running);
	} while( CURLM_CALL_MULTI_PERFORM == rc );

	check_run_count();
}

static void curl_ihandler_cb(struct incident *i, void *ctx)
{
	g_debug("%s i %p ctx %p", __PRETTY_FUNCTION__, i, ctx);
	GString *url;
	if ( incident_value_string_get(i, "url", &url) )
		session_new(url->str);
	else
		g_critical("download without url?");
}

static bool curl_config(struct lcfgx_tree_node *node)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	curl_runtime.config = node;
	return true;
}

static bool curl_prepare(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool curl_new(struct dionaea *d)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	curl_runtime.multi = curl_multi_init();
	ev_timer_init(&curl_runtime.timer_event, timer_cb, 0., 0.);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_SOCKETFUNCTION, curl_socketfunction_cb);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_SOCKETDATA, NULL);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_TIMERDATA, NULL);
	CURLMcode rc;
	do
	{
		rc = curl_multi_socket_all(curl_runtime.multi, &curl_runtime.still_running);
	} while( CURLM_CALL_MULTI_PERFORM == rc );

	curl_runtime.ihandler = ihandler_new("dionaea.download.offer", curl_ihandler_cb, NULL);
	return true;
}

static bool curl_freex(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool curl_hup(struct lcfgx_tree_node *node)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

struct module_api *module_init(struct dionaea *d)
{
    g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, d);
	static struct module_api curl_api =
	{
		.config = &curl_config,
		.prepare = &curl_prepare,
		.new = &curl_new,
		.free = &curl_freex,
		.hup = &curl_hup
	};

    return &curl_api;
}

