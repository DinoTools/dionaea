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
#include <ev.h>

#include <lcfg/lcfg.h>
#include <lcfgx/lcfgx_tree.h>

struct nlattr;

#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/addr.h>
#include <netlink/object.h>
#include <netlink/object-api.h>
#include <netlink/cache.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/neightbl.h>
#include <netlink/route/route.h>
#include <netlink/route/rule.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/class.h>
#include <netlink/route/classifier.h>
#include <netlink/fib_lookup/lookup.h>
#include <netlink/fib_lookup/request.h>
#include <linux/if.h>

#include "modules.h"
#include "connection.h"
#include "dionaea.h"

#include "log.h"
#include "processor.h"
#include "incident.h"

#define D_LOG_DOMAIN "nl"


static struct 
{
	struct lcfgx_tree_node *config;
	struct nl_sock  *sock;
	struct nl_cache *link_cache;
	struct nl_cache *addr_cache;
	struct nl_cache *neigh_cache;
	struct ev_io io_in;
	struct ihandler *ihandler;
	GHashTable 	*link_addr_cache;
//	struct link_addr **cache;
//	int    cache_size;
} nl_runtime;

struct link_addr
{
	char 	*iface;
	int 	ifindex;
	bool 	active;
	GHashTable *addrs;
};

struct link_addr *link_addr_new(char *iface, int ifindex, bool active)
{
	struct link_addr *nla = g_malloc0(sizeof(struct link_addr));
	nla->iface = g_strdup(iface);
	nla->ifindex = ifindex;
	nla->active = active;
	nla->addrs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	return nla;
}

void link_addr_free(struct link_addr *nla)
{
	g_hash_table_destroy(nla->addrs);
	g_free(nla->iface);
	g_free(nla);
}

static void nl_io_in_cb(struct ev_loop *loop, struct ev_io *w, int revents)
{
	nl_recvmsgs_default(nl_runtime.sock);
}

static bool nl_config(struct lcfgx_tree_node *node)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	nl_runtime.config = node;
	return true;
}

static bool nl_prepare(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static void nl_obj_input(struct nl_object *obj, void *arg)
{
	struct _obj
	{
		NLHDR_COMMON
	};

	struct _obj *o = (struct _obj *)obj;

	if( o->ce_msgtype == RTM_NEWLINK  || o->ce_msgtype == RTM_DELLINK ) 
	{
		struct rtnl_link *link = (struct rtnl_link *)obj;
		struct nl_addr *a = rtnl_link_get_addr(link);
		char buf[123];
		nl_addr2str(a, buf, sizeof(buf));
		int ifindex = rtnl_link_get_ifindex(link);
		bool active = rtnl_link_get_flags(link) & IFF_UP;
		char *iface = rtnl_link_get_name(link);
		if( o->ce_msgtype == RTM_NEWLINK ) 
		{
			struct link_addr *nla = g_hash_table_lookup(nl_runtime.link_addr_cache, &ifindex);
			if( nla == NULL )
			{
				g_critical("LINK NEW %s %i", iface, ifindex);
				struct link_addr *nla = link_addr_new(iface, ifindex, active);
				g_hash_table_insert(nl_runtime.link_addr_cache, &nla->ifindex, nla);
			}else
			{
				g_critical("LINK CHANGE %s %i", iface, ifindex);
				GHashTableIter iter;
				gpointer key, value;
				g_hash_table_iter_init(&iter, nla->addrs);
				if( active != nla->active )
				{
					while( g_hash_table_iter_next(&iter, &key, &value) )
					{
						struct incident *i;
						if( active )
						{
							g_critical("LINK UP");
							i = incident_new("dionaea.module.nl.addr.new");
						}else
						{
							g_critical("LINK DOWN");
							i = incident_new("dionaea.module.nl.addr.del");
						}
						incident_value_string_set(i, "addr", g_string_new(key));
						incident_value_string_set(i, "iface", g_string_new(nla->iface));
						incident_value_int_set(i, "scope", nla->ifindex);
						incident_report(i);
						incident_free(i);
					}
					nla->active = active;
				}
			}
		}else
		if( o->ce_msgtype == RTM_DELLINK ) 
		{
			g_critical("LINK DEL %s %i", iface, ifindex);
			struct link_addr *nla = g_hash_table_lookup(nl_runtime.link_addr_cache, &ifindex);
			g_hash_table_remove(nl_runtime.link_addr_cache, &ifindex);
			link_addr_free(nla);
		}
	}else
	if( o->ce_msgtype == RTM_NEWADDR  || o->ce_msgtype == RTM_DELADDR ) 
	{
		char buf[128];
		struct rtnl_addr *addr = (struct rtnl_addr *)obj;
		struct nl_addr *a = rtnl_addr_get_local(addr);
		int ifindex = rtnl_addr_get_ifindex(addr);
		nl_addr2str(a, buf, 128);
		char *slash; 
		if( (slash = strstr(buf, "/")) != NULL)
			*slash = '\0';
		char *saddr = NULL;

		struct link_addr *nla = g_hash_table_lookup(nl_runtime.link_addr_cache, &ifindex);
		if( !nla )
			return;

		if( o->ce_msgtype == RTM_NEWADDR ) 
		{
			if( g_hash_table_lookup(nla->addrs, buf) == NULL )
			{
				g_warning("NEW ADDR %s!", buf);
				saddr = g_strdup(buf);
				g_hash_table_insert(nla->addrs, saddr, saddr);

				if( nla->active )
				{
					struct incident *i = incident_new("dionaea.module.nl.addr.new");
					incident_value_string_set(i, "addr", g_string_new(saddr));
					incident_value_string_set(i, "iface", g_string_new(nla->iface));
					incident_value_int_set(i, "scope", nla->ifindex);
					incident_report(i);
					incident_free(i);
				}
			}
		}else
		if( o->ce_msgtype == RTM_DELADDR )
		{
			if( ( saddr = g_hash_table_lookup(nla->addrs, buf) ) != NULL )
			{
				g_warning("DEL ADDR! %s", buf);
				if( nla->active )
				{
					struct incident *i = incident_new("dionaea.module.nl.addr.del");
					incident_value_string_set(i, "addr", g_string_new(saddr));
					incident_value_string_set(i, "iface", g_string_new(nla->iface));
					incident_value_int_set(i, "scope", nla->ifindex);
					incident_report(i);
					incident_free(i);
				}
				g_hash_table_remove(nla->addrs, buf);
				g_free(saddr);
			}
		}
	}
/*
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_STATS,
		.dp_fd = stdout,
		.dp_dump_msgtype = 1,
	};

	nl_object_dump(obj, &dp);

	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
		.dp_prefix = 1,
	};
	g_debug("addr cache");
	nl_cache_dump(nl_runtime.addr_cache, &params);
	g_debug("arp cache");
	nl_cache_dump(nl_runtime.neigh_cache, &params);
	g_debug("link cache");
	nl_cache_dump(nl_runtime.link_cache, &params);
*/
}

static int nl_event_input(struct nl_msg *msg, void *arg)
{
	if (nl_msg_parse(msg, &nl_obj_input, NULL) < 0)
		g_critical("<<EVENT>> Unknown message type\n");

	/* Exit nl_recvmsgs_def() and return to the main select() */
	return NL_STOP;
}

static void cache_lookup_cb(struct nl_object *obj, void *arg)
{
	g_critical("%s obj %p arg %p", __PRETTY_FUNCTION__, obj, arg);
	uintptr_t *a = arg;
	*a = (uintptr_t)obj;
}

static void nl_ihandler_cb(struct incident *i, void *ctx)
{
	g_debug("%s i %p ctx %p", __PRETTY_FUNCTION__, i, ctx);
	struct connection *con;
	incident_value_con_get(i, "con", &con);

	char *remote = con->remote.ip_string;
	char *local = con->local.ip_string;
	char *prefix = "::ffff:";
	if( strncmp(local, prefix, strlen(prefix)) == 0)
		local += strlen(prefix);
	if( strncmp(remote, prefix, strlen(prefix)) == 0)
		remote += strlen(prefix);


	int ifindex;
	int err;
	{
		g_debug("local addr %s remote addr %s", local, remote);
		struct rtnl_addr *addr = rtnl_addr_alloc();
	
		struct nl_addr *a;

		if ( ( err = nl_addr_parse(local, AF_UNSPEC, &a)) != 0 )
			g_critical("could not parse addr %s (%s)", local, nl_geterror(err));
		rtnl_addr_set_local(addr, a);
		nl_addr_put(a);
	
		struct rtnl_addr *res = NULL;
		nl_cache_foreach_filter(nl_runtime.addr_cache, OBJ_CAST(addr), cache_lookup_cb, &res);
	
		g_critical("LOCAL RTNL_ADDR %p", res);
	
	/*	struct nl_dump_params params = {
			.dp_type = NL_DUMP_LINE,
			.dp_fd = stdout,
		};
		nl_cache_dump_filter(nl_runtime.addr_cache, &params, OBJ_CAST(addr));
	*/
		ifindex = rtnl_addr_get_ifindex(res);
	}
	

	struct rtnl_neigh *res = NULL;
	{
		struct rtnl_neigh *neigh = rtnl_neigh_alloc();
		rtnl_neigh_set_ifindex(neigh, ifindex);
		struct nl_addr *a;
		if ( ( err = nl_addr_parse(remote, AF_UNSPEC, &a)) != 0 )
			g_critical("could not parse addr %s (%s)", remote, nl_geterror(err));
		rtnl_neigh_set_dst(neigh, a);
		nl_addr_put(a);

		nl_cache_foreach_filter(nl_runtime.neigh_cache, OBJ_CAST(neigh), cache_lookup_cb, &res);
	}

	if( res )
	{
		g_critical("GOT NEIGH %p", res);
		struct nl_addr *lladdr = rtnl_neigh_get_lladdr(res);
		char buf[123];
		nl_addr2str(lladdr, buf, sizeof(buf));
		g_critical("GOT NEIGH %s", buf);

		struct incident *i = incident_new("dionaea.module.nl.connection.info.mac");
		incident_value_string_set(i, "mac", g_string_new(buf));
		incident_value_con_set(i, "con", con);
		incident_report(i);
		incident_free(i);
	}
}

static bool nl_new(struct dionaea *d)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	nl_runtime.sock = nl_socket_alloc();
	struct nl_sock  *sock = nl_runtime.sock;
	nl_socket_disable_seq_check(sock);
	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, nl_event_input, NULL);
	nl_join_groups(sock, RTMGRP_LINK);
	int err;
	if ( (err = nl_connect(sock, NETLINK_ROUTE)) < 0) 
	{
		g_error("Could not connect netlink (%s)", nl_geterror(err));
	}

	nl_socket_add_membership(sock, RTNLGRP_LINK);
	nl_socket_add_membership(sock, RTNLGRP_NEIGH);
	nl_socket_add_membership(sock, RTNLGRP_IPV4_IFADDR);
	nl_socket_add_membership(sock, RTNLGRP_IPV6_IFADDR);

	if( (err=rtnl_neigh_alloc_cache(sock, &nl_runtime.neigh_cache)) != 0 )
	{
		g_error("Could not allocate neigh cache! (%s)", nl_geterror(err));
	}

	if( (err=rtnl_link_alloc_cache(sock, &nl_runtime.link_cache)) != 0 )
	{
		g_error("Could not allocate link cache! (%s)", nl_geterror(err));
	}

	if( (err=rtnl_addr_alloc_cache(sock, &nl_runtime.addr_cache)) != 0 )
	{
		g_error("Could not allocate addr cache! (%s)", nl_geterror(err));
	}

	nl_cache_mngt_provide(nl_runtime.neigh_cache);
	nl_cache_mngt_provide(nl_runtime.link_cache);
	nl_cache_mngt_provide(nl_runtime.addr_cache);
	
	nl_runtime.ihandler = ihandler_new("dionaea.connection.*.accept", nl_ihandler_cb, NULL);

	ev_io_init(&nl_runtime.io_in, nl_io_in_cb, nl_socket_get_fd(sock), EV_READ);
	ev_io_start(g_dionaea->loop, &nl_runtime.io_in);
	nl_runtime.link_addr_cache = g_hash_table_new(g_int_hash, g_int_equal);
	nl_cache_foreach(nl_runtime.link_cache, nl_obj_input, NULL);
	nl_cache_foreach(nl_runtime.addr_cache, nl_obj_input, NULL);
    return true;
}

static bool nl_free(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool nl_hup(struct lcfgx_tree_node *node)
{
	g_debug("%s", __PRETTY_FUNCTION__);

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, nl_runtime.link_addr_cache);
	while( g_hash_table_iter_next(&iter, &key, &value) )
	{
		struct link_addr *nla = value;

		if( nla == NULL )
			continue;

		g_debug("doing %s", nla->iface);
		if( nla->active )
		{
			GHashTableIter addr_iter;
			gpointer addr_key, addr_value;
			g_hash_table_iter_init(&addr_iter, nla->addrs);
			while( g_hash_table_iter_next(&addr_iter, &addr_key, &addr_value) )
			{
				struct incident *i;
				i = incident_new("dionaea.module.nl.addr.hup");
				incident_value_string_set(i, "addr", g_string_new(addr_key));
				incident_value_string_set(i, "iface", g_string_new(nla->iface));
				incident_value_int_set(i, "scope", nla->ifindex);
				incident_report(i);
				incident_free(i);
			}
		}
	}
	return true;
}

struct module_api *module_init(struct dionaea *d)
{
    g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, d);
	static struct module_api nl_api =
	{
		.config = &nl_config,
		.prepare = &nl_prepare,
		.new = &nl_new,
		.free = &nl_free,
		.hup = &nl_hup
	};

    return &nl_api;
}

