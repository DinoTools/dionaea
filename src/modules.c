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

#include <stdbool.h>
#include <errno.h>
#include <stdio.h>

#include <gmodule.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <dirent.h>

#include <stdio.h>
#include <glib.h>
#include <glib/gprintf.h>

#include "config.h"
#include "modules.h"
#include "dionaea.h"
#include "log.h"

#define D_LOG_DOMAIN "modules"

struct module *module_new(const char *name, const char *module_path)
{
    GModule *module = g_module_open(module_path, 0);

    if ( module == NULL )
    {
        g_warning("could not load %s %s",module_path, g_module_error());
        return NULL;
    }

    gpointer initfn;
    if ( g_module_symbol(module, "module_init", &initfn) == false )
    {
        g_warning("could not find module_init in module (%s)", strerror(errno));
        return NULL;
    }

    struct module *m = g_malloc0(sizeof(struct module));

    m->module = module;
    m->module_init = initfn;
	m->name = g_strdup(name);

    return m;

}

void module_free(struct module *m)
{
	g_debug("%s module %p name %s", __PRETTY_FUNCTION__, m, m->name);
	g_module_close(m->module);
	g_free(m->name);
	g_free(m);

}


void modules_load(struct lcfgx_tree_node *node)
{
    g_debug("%s node %p", __PRETTY_FUNCTION__, node);

//	lcfgx_tree_dump(node, 0);
	struct lcfgx_tree_node *it = node->value.elements;
	for(it = node->value.elements; it != NULL; it = it->next)
	{
		
		gchar module_path[1024];
		if ( g_snprintf(module_path, 1023, PREFIX"/lib/dionaea/%s.so", it->key) == -1 )
			return;

		g_message("loading module %s (%s)", it->key, module_path);

		struct module *m = module_new(it->key, module_path);
		if (m == NULL)
		{
			g_warning("could not load module %s (%s)", it->key, strerror(errno));
			continue;
		}

		struct module_api *n;
		if ( (n = m->module_init(g_dionaea)) == NULL )
		{
			g_warning("error,  module returned no module api");
			continue;
		}

		m->config = it;

		memcpy(&m->api, n, sizeof(struct module_api));

        g_dionaea->modules->modules = g_list_append(g_dionaea->modules->modules, m);
	}

	GList *lit;
	for (lit = g_list_first(g_dionaea->modules->modules); lit != NULL; lit = g_list_next(lit))
	{
		struct module *m = lit->data;
		g_message("loaded module %s name %s module %p gmodule %p config %p prepare %p new %p free %p", 
			   g_module_name(m->module),
			   m->name,
			   m,
			   m->module,
			   m->api.config,
			   m->api.prepare,
			   m->api.new,
			   m->api.free);
	}
}

void modules_unload(void)
{
	GList *it;
	while ((it = g_list_first(g_dionaea->modules->modules)) != NULL)
	{
		g_dionaea->modules->modules = g_list_remove_link(g_dionaea->modules->modules, it);
		struct module *m = it->data;
		module_free(m);
		g_list_free_1(it);
	}
}



void modules_config(void)
{
	GList *it;
	for (it = g_list_first(g_dionaea->modules->modules); it != NULL; it = g_list_next(it))
	{
		g_message("configure module %p", it->data);
		struct module *m = it->data;
		if(m->api.config != NULL)
			m->api.config(m->config);
	}
}

void modules_prepare(void)
{
	GList *it;
	for (it = g_list_first(g_dionaea->modules->modules); it != NULL; it = g_list_next(it))
	{
		g_message("prepare module %p", it->data);
		struct module *m = it->data;
		if(m->api.prepare != NULL)
			m->api.prepare();
	}
}

void modules_new(void)
{
	GList *it;
	for (it = g_list_first(g_dionaea->modules->modules); it != NULL; it = g_list_next(it))
	{
		struct module *m = it->data;
		g_message("new module %s %p fn %p", g_module_name(m->module), it->data, m->api.new);

		if(m->api.new != NULL)
			m->api.new(g_dionaea);
	}
}

void modules_free(void)
{
	GList *it;
	for (it = g_list_first(g_dionaea->modules->modules); it != NULL; it = g_list_next(it))
	{
		struct module *m = it->data;
		g_message("free module %s %p fn %p", g_module_name(m->module), it->data, m->api.free);

		if(m->api.free != NULL)
			m->api.free();
	}

}

void modules_hup(void)
{
	GList *it;
	for (it = g_list_first(g_dionaea->modules->modules); it != NULL; it = g_list_next(it))
	{
		struct module *m = it->data;

		if(m->api.hup == NULL)
		{
			g_message("module %s does not support hup", m->name);
			continue;
		}


		g_message("re-configure module %s", m->name);

		char *path;
		if (asprintf(&path, "modules.%s", m->name) == -1)
			return;
		struct lcfgx_tree_node *n;
		if( lcfgx_get_map(g_dionaea->config.root, &n, path) == LCFGX_PATH_FOUND_TYPE_OK )
		{
				m->api.hup(n);
		}
		free(path);
	}
}
