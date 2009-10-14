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


#include "modules.h"
#include "connection.h"
#include "dionaea.h"

#include "nc.h"
#include "log.h"

#define D_LOG_DOMAIN "nc"




static struct 
{
	struct lcfgx_tree_node *config;
} nc_runtime;

static bool nc_config(struct lcfgx_tree_node *node)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	nc_runtime.config = node;
	return true;
}

static bool nc_prepare(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool nc_new(struct dionaea *d)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	struct lcfgx_tree_node *v;
//	if(lcfgx_get_list(nc_runtime.config, &v, "services") != LCFGX_PATH_FOUND_TYPE_OK)
//		return false;

//	lcfgx_tree_dump(nc_runtime.config, 0);
	for( v = nc_runtime.config->value.elements; v != NULL; v = v->next )
	{
		g_message("node %s", (char *)v->key);
		if( strcmp(v->key, "services" ) != 0 && 
			strcmp(v->key, "clients" ) != 0 )
			continue;

		for( struct lcfgx_tree_node *it = v->value.elements; it != NULL; it = it->next )
		{
			struct lcfgx_tree_node *node;
			enum connection_transport trans = connection_transport_tcp;

			if( lcfgx_get_string(it, &node, "type") == LCFGX_PATH_FOUND_TYPE_OK )
				if( connection_transport_from_string(node->value.string.data, &trans) == false )
					continue;

			struct connection *con = connection_new(trans);

			char *host = "::";
			if( lcfgx_get_string(it, &node, "host") == LCFGX_PATH_FOUND_TYPE_OK )
				host = node->value.string.data;

			int port = 4711;
			if( lcfgx_get_string(it, &node, "port") == LCFGX_PATH_FOUND_TYPE_OK )
				port = atoi(node->value.string.data);

			char *iface = NULL;
			if( lcfgx_get_string(it, &node, "iface") == LCFGX_PATH_FOUND_TYPE_OK )
				iface = node->value.string.data;

			if( strcmp(v->key, "services" ) == 0 )
			{
				connection_bind(con, host, port, iface);
				connection_listen(con, 10);
			}

			if( lcfgx_get_string(it, &node, "throttle.in") == LCFGX_PATH_FOUND_TYPE_OK )
				connection_throttle_io_in_set(con, atoi(node->value.string.data));
			g_message("throttle in %s", (char *)node->value.string.data);

			if( lcfgx_get_string(it, &node, "throttle.out") == LCFGX_PATH_FOUND_TYPE_OK )
				connection_throttle_io_out_set(con, atoi(node->value.string.data));

			if( strcmp(v->key, "services" ) == 0 )
				if( lcfgx_get_string(it, &node, "timeout.listen") == LCFGX_PATH_FOUND_TYPE_OK )
					connection_listen_timeout_set(con,  atoi(node->value.string.data));

			if( strcmp(v->key, "clients" ) == 0 )
				if( lcfgx_get_string(it, &node, "timeout.reconnect") == LCFGX_PATH_FOUND_TYPE_OK )
					connection_reconnect_timeout_set(con,  atoi(node->value.string.data));

			if( lcfgx_get_string(it, &node, "timeout.connect") == LCFGX_PATH_FOUND_TYPE_OK )
				connection_idle_timeout_set(con,  atoi(node->value.string.data));

			if( lcfgx_get_string(it, &node, "proto") == LCFGX_PATH_FOUND_TYPE_OK )
			{
				if( memcmp("redir", node->value.string.data, MIN(strlen("redir"), node->value.string.len) ) == 0 )
					connection_protocol_set(con, &proto_nc_redir);
				else
					if( memcmp("source", node->value.string.data, MIN(strlen("source"), node->value.string.len) ) == 0 )
					connection_protocol_set(con, &proto_nc_source);
				else
					if( memcmp("sink", node->value.string.data, MIN(strlen("sink"), node->value.string.len) ) == 0 )
					connection_protocol_set(con, &proto_nc_sink);
				else
					connection_protocol_set(con, &proto_nc_redir);
			} else
				connection_protocol_set(con, &proto_nc_redir);


			if( strcmp(v->key, "clients" ) == 0 )
				connection_connect(con, host, port, iface);
		}
	}

	return true;
}

static bool nc_free(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool nc_hup(struct lcfgx_tree_node *node)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

struct module_api *module_init(struct dionaea *d)
{
	g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, d);
	static struct module_api nc_api =
	{
		.config = &nc_config,
		.prepare = &nc_prepare,
		.new = &nc_new,
		.free = &nc_free,
		.hup = &nc_hup
	};

    return &nc_api;
}


struct protocol proto_nc_source =
{
	.ctx_new = proto_nc_ctx_new,
	.ctx_free = proto_nc_ctx_free,
	.established = proto_nc_established_source,
	.error = proto_nc_error,
	.idle_timeout = proto_nc_timeout,
	.disconnect = proto_nc_disconnect,
	.io_in = proto_nc_io_in,
	.ctx = NULL,
};

struct protocol proto_nc_sink =
{
	.ctx_new = proto_nc_ctx_new,
	.ctx_free = proto_nc_ctx_free,
	.established = proto_nc_established,
	.error = proto_nc_error,
	.idle_timeout = proto_nc_timeout,
	.disconnect = proto_nc_disconnect,
	.io_in = proto_nc_io_in,
	.ctx = NULL,
};


struct protocol proto_nc_redir =
{
	.ctx_new = proto_nc_ctx_new,
	.ctx_free = proto_nc_ctx_free,
	.established = proto_nc_established,
	.error = proto_nc_error,
	.idle_timeout = proto_nc_timeout,
	.disconnect = proto_nc_disconnect,
	.io_in = proto_nc_io_in_redir,
	.ctx = NULL,
};



void proto_nc_established(struct connection *con)
{
	g_debug("%s con %p ctx %p",__PRETTY_FUNCTION__, con, con->protocol.ctx);
}

void proto_nc_established_source(struct connection *con)
{
	g_debug("%s con %p ctx %p",__PRETTY_FUNCTION__, con, con->protocol.ctx);
	char *x = g_malloc0(1024*1024);
	connection_send(con, x, 1024*1024);
	g_free(x);
}


void proto_nc_error(struct connection *con, enum connection_error error)
{
	g_debug(__PRETTY_FUNCTION__);
	g_message("error %i %s", error, connection_strerror(error));
}

uint32_t proto_nc_io_in(struct connection *con, void *context, unsigned char *data, uint32_t size)
{
	g_debug("%s con %p ctx %p data %p size %i",__PRETTY_FUNCTION__, con, context, data, size);
	return size;
}

uint32_t proto_nc_io_in_redir(struct connection *con, void *context, unsigned char *data, uint32_t size)
{
	g_debug("%s con %p ctx %p data %p size %i",__PRETTY_FUNCTION__, con, context, data, size);
	connection_send(con, data, size);
	return size;
}


bool proto_nc_disconnect(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	if (con->events.reconnect_timeout.repeat > 0.)
		return true;
	return false;
}

bool proto_nc_timeout(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	return false;
}



void *proto_nc_ctx_new(struct connection *con)
{
	g_debug("%s con %p ctx %p", __PRETTY_FUNCTION__, con, con->protocol.ctx);
	return NULL;
}


void proto_nc_ctx_free(void *context)
{
	g_debug("%s ctx %p ",__PRETTY_FUNCTION__, context);
}


