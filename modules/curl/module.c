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
#include <stdlib.h>
#include <unistd.h>

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
	struct ihandler *ihandler;
	int queued;
	int active;
	char *download_dir;
} curl_runtime;


struct session
{
	CURL *easy;
	char *url;
	char *laddr;
	char error[CURL_ERROR_SIZE];

	union
	{
		struct
		{
			int file;
			char *path;
		}download;

		struct
		{

		}upload;
	}action;
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
	g_debug("%s queued %i active %i", __PRETTY_FUNCTION__, curl_runtime.queued, curl_runtime.active);
	if( curl_runtime.queued > curl_runtime.active )
	{
		char *eff_url=NULL;
		CURLMsg *msg;
		int msgs_left;
		struct session *session=NULL;
		CURL*easy;

		g_debug("REMAINING: %d", curl_runtime.queued);
		easy=NULL;
		while( (msg = curl_multi_info_read(curl_runtime.multi, &msgs_left)) )
		{
			if( msg->msg == CURLMSG_DONE )
			{
				curl_runtime.queued--;

				easy=msg->easy_handle;
				curl_easy_getinfo(easy, CURLINFO_PRIVATE, &session);
				curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &eff_url);
				if( msg->data.result == CURLE_OK )
				{
					g_info("DONE: %s => (%d) %s", eff_url, msg->data.result, session->error);
					close(session->action.download.file);
					struct incident *i = incident_new("dionaea.download.complete");
					incident_value_string_set(i, "path", g_string_new(session->action.download.path));
					incident_report(i);
					incident_free(i);
				}else
				{
					g_warning("FAIL: %s => (%d) %s", eff_url, msg->data.result, session->error);
					close(session->action.download.file);
				}
				curl_multi_remove_handle(curl_runtime.multi, easy);
				curl_easy_cleanup(easy);
				g_free(session->url);
				if( session->laddr )
					g_free(session->laddr);
				unlink(session->action.download.path);
				if( session->action.download.path )
					g_free(session->action.download.path);
				g_free(session);
			}
		}
	}
}

static void event_cb(struct ev_loop *loop,  struct ev_io *w, int revents)
{
	g_debug("%s  w %p revents %i", __PRETTY_FUNCTION__, w, revents);
	CURLMcode rc;

	int action = (revents&EV_READ?CURL_POLL_IN:0)|(revents&EV_WRITE?CURL_POLL_OUT:0);
	do
	{
		rc = curl_multi_socket_action(curl_runtime.multi, w->fd, action, &curl_runtime.active);
	} while( rc == CURLM_CALL_MULTI_PERFORM );

	check_run_count();

	if( curl_runtime.queued <= 0 )
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
		rc = curl_multi_socket_action(curl_runtime.multi, CURL_SOCKET_TIMEOUT, 0, &curl_runtime.active);
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
	struct session *session;
	curl_easy_getinfo(easy, CURLOPT_PRIVATE, &session);

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
			session_set_socket(session, info, s, action);
			curl_multi_assign(curl_runtime.multi, s, info);
		} else
		{
			g_debug("Changing action from %s to %s", action_str[info->action], action_str[action]);
			session_set_socket(session, info, s, action);
		}
	}
	return 0;
}



/* CURLOPT_WRITEFUNCTION */
static size_t curl_writefunction_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
	
	struct session *session = (struct session *) data;
	g_debug("session %p file %i", session, session->action.download.file);
//	fwrite(ptr, size, nmemb, session->action.download.file);
	write(session->action.download.file, ptr, size*nmemb);
	return size * nmemb;
}


/* CURLOPT_PROGRESSFUNCTION */
static int curl_progressfunction_cb (void *p, double dltotal, double dlnow, double ult, double uln)
{
	struct session *session = (struct session *)p;
	(void)ult;
	(void)uln;

	g_debug("Progress: %s (%g/%g)", session->url, dlnow, dltotal);
	return 0;
}

/* CURLOPT_DEBUGFUNCTION */
static int curl_debugfunction_cb(CURL *easy, curl_infotype type, char *data, size_t size, void *userp)
{

	struct session *session;
	curl_easy_getinfo(easy, CURLINFO_PRIVATE, &session);
	switch ( type )
	{
	case CURLINFO_TEXT:
		{
			char *text = g_strdup(data);
			int len = strlen(text);
			if ( text[len-1] == '\n' )
				text[len-1] = '\0';
			g_debug("%s: %s", session->url, text);
			g_free(text);
		}
		break;

	case CURLINFO_HEADER_OUT:
	case CURLINFO_DATA_OUT:
	case CURLINFO_SSL_DATA_OUT:
	case CURLINFO_HEADER_IN:
	case CURLINFO_DATA_IN:
	case CURLINFO_SSL_DATA_IN:
	default:
		break;
	}
	
	return 0;
}

/* Create a new easy handle, and add it to the global curl_multi */
static struct session *session_new(void)
{
	struct session *session;
	session = g_malloc0(sizeof(struct session));
	session->error[0]='\0';
	session->easy = curl_easy_init();
	return session;
}

static void session_download_new(const char *url, const char *laddr)
{
	struct session *session = session_new();
	CURLMcode rc;

	session->url = g_strdup(url);
	if( laddr )
		session->laddr = g_strdup(laddr);
	curl_easy_setopt(session->easy, CURLOPT_URL, session->url);
	curl_easy_setopt(session->easy, CURLOPT_WRITEFUNCTION, curl_writefunction_cb);
	curl_easy_setopt(session->easy, CURLOPT_WRITEDATA, session);
	curl_easy_setopt(session->easy, CURLOPT_DEBUGFUNCTION, curl_debugfunction_cb);
	curl_easy_setopt(session->easy, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(session->easy, CURLOPT_ERRORBUFFER, session->error);
	curl_easy_setopt(session->easy, CURLOPT_PRIVATE, session);
	curl_easy_setopt(session->easy, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(session->easy, CURLOPT_PROGRESSFUNCTION, curl_progressfunction_cb);
	curl_easy_setopt(session->easy, CURLOPT_PROGRESSDATA, session);
	curl_easy_setopt(session->easy, CURLOPT_LOW_SPEED_TIME, 3L);
	curl_easy_setopt(session->easy, CURLOPT_LOW_SPEED_LIMIT, 10L);
	curl_easy_setopt(session->easy, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)");  

	if( laddr )
		curl_easy_setopt(session->easy, CURLOPT_INTERFACE, session->laddr);
	g_debug("Adding easy %p to multi %p (%s)", session->easy, curl_runtime.multi, url);
	rc = curl_multi_add_handle(curl_runtime.multi, session->easy);
	curl_runtime.queued++;
	check_run_count();

	session->action.download.path = g_strdup(curl_runtime.download_dir);
	session->action.download.file = mkstemp(session->action.download.path);

	g_debug("session %p file %i path %s", session, session->action.download.file, session->action.download.path);
}

static void curl_ihandler_cb(struct incident *i, void *ctx)
{
	g_debug("%s i %p ctx %p", __PRETTY_FUNCTION__, i, ctx);
	GString *url;
	if ( incident_value_string_get(i, "url", &url) )
	{
		if ( strncasecmp(url->str,  "http", 4) != 0)
			return;

		char *addr = NULL;
		struct connection *con;
		if ( incident_value_ptr_get(i, "con", (uintptr_t *)&con) )
			addr = con->local.ip_string;
		session_download_new(url->str, addr);
	}
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

	struct lcfgx_tree_node *node;
	if( lcfgx_get_string(g_dionaea->config.root, &node, "downloads.dir") != LCFGX_PATH_FOUND_TYPE_OK )
	{
		g_warning("missing downloads.dir in dionaea.conf");
		return false;
	}

	curl_runtime.download_dir = g_strdup_printf("%s/http-XXXXXX", (char *)node->value.string.data);


	if( curl_global_init(CURL_GLOBAL_ALL) != 0 )
		return false;

	curl_version_info_data *curlinfo;
	curlinfo = curl_version_info(CURLVERSION_NOW);

	GString *features = g_string_new("");
	GString *protocols = g_string_new("");
	if ( curlinfo->features )
	{
		
		struct curl_feature
		{
			const char *name;
			int bitmask;
		};
		static const struct curl_feature feats[] = {
			{"c-ares", CURL_VERSION_ASYNCHDNS},
			{"debug", CURL_VERSION_DEBUG},
#ifdef CURL_VERSION_CURLDEBUG
			{"debugmemory", CURL_VERSION_CURLDEBUG},
#endif
			{"gss", CURL_VERSION_GSSNEGOTIATE},
			{"idn", CURL_VERSION_IDN},
			{"ipv6", CURL_VERSION_IPV6},
			{"largefile", CURL_VERSION_LARGEFILE},
			{"ntlm", CURL_VERSION_NTLM},
			{"spnego", CURL_VERSION_SPNEGO},
			{"ssl",  CURL_VERSION_SSL},
			{"sspi",  CURL_VERSION_SSPI},
			{"krb4", CURL_VERSION_KERBEROS4},
			{"libz", CURL_VERSION_LIBZ},
			{"charconv", CURL_VERSION_CONV}
		};
		for (unsigned int i=0; i<sizeof(feats)/sizeof(feats[0]); i++ )
			if ( curlinfo->features & feats[i].bitmask )
				g_string_append_printf(features, ",%s", feats[i].name);

	}
	if ( curlinfo->protocols )
		for (const char * const *proto=curlinfo->protocols; *proto; ++proto )
			g_string_append_printf(protocols, ",%s", *proto);

	g_info("curl version %s features:%s protocols:%s ", curlinfo->version, features->str+1, protocols->str+1);


	curl_runtime.multi = curl_multi_init();
	ev_timer_init(&curl_runtime.timer_event, timer_cb, 0., 0.);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_SOCKETFUNCTION, curl_socketfunction_cb);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_SOCKETDATA, NULL);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
	curl_multi_setopt(curl_runtime.multi, CURLMOPT_TIMERDATA, NULL);
	CURLMcode rc;
	do
	{
		rc = curl_multi_socket_all(curl_runtime.multi, &curl_runtime.active);
	} while( CURLM_CALL_MULTI_PERFORM == rc );

	curl_runtime.ihandler = ihandler_new("dionaea.download.offer", curl_ihandler_cb, NULL);
	return true;
}

static bool curl_freex(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	curl_global_cleanup();
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

