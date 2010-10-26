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

#include "modules.h"
#include "connection.h"
#include "dionaea.h"

#include "module.h"
#include "processor.h"

#define D_LOG_DOMAIN "xmatch"


static bool xmatch_config(struct lcfgx_tree_node *node)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool xmatch_prepare(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	g_hash_table_insert(g_dionaea->processors->names, (void *)proc_xmatch.name, &proc_xmatch);
	return true;
}

static bool xmatch_new(struct dionaea *d)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool xmatch_free(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool xmatch_hup(struct lcfgx_tree_node *node)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

struct module_api *module_init(struct dionaea *d)
{
    g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, d);
	static struct module_api xmatch_api =
	{
		.config = &xmatch_config,
		.prepare = &xmatch_prepare,
		.new = &xmatch_new,
		.free = &xmatch_free,
		.hup = &xmatch_hup
	};

    return &xmatch_api;
}
