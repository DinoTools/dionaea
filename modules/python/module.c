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
#include <stdint.h>
#include <unistd.h>
#include <dirent.h>
#include <Python.h>

#include <lcfg/lcfg.h>
#include <lcfgx/lcfgx_tree.h>

#include "connection.h"
#include "dionaea.h"
#include "modules.h"

#include "config.h"
#include "log.h"

#define D_LOG_DOMAIN "python"
PyObject *PyInit_python(void);


static struct python_runtime
{
	struct lcfgx_tree_node *config;
	struct ev_io python_cli_io_in;
	FILE *stdin;
} runtime;

static bool config(struct lcfgx_tree_node *node)
{
	lcfgx_tree_dump(node,0);
	runtime.config = node;
	return true;
}

void python_io_in_cb(EV_P_ struct ev_io *w, int revents)
{
	PyRun_InteractiveOne(runtime.stdin, "<stdin>");
	printf("python>");
}


static bool freepy(void)
{
	g_debug("%s %s", __PRETTY_FUNCTION__, __FILE__);
	ev_io_stop(g_dionaea->loop, &runtime.python_cli_io_in);
	Py_Finalize();
	return true;
}

static bool new(struct dionaea *dionaea)
{
	g_debug("%s %s %p", __PRETTY_FUNCTION__, __FILE__, g_dionaea);
	PyImport_AppendInittab("dionaea", &PyInit_python);
	Py_Initialize();

	struct lcfgx_tree_node *files;
	static GList *py_script_files_list = NULL;
	if(lcfgx_get_list(runtime.config, &files, "files") == LCFGX_PATH_FOUND_TYPE_OK)
	{
		struct lcfgx_tree_node *file;
		for (file = files->value.elements; file != NULL; file = file->next)
		{
			char relpath[1024];
			char *name = file->value.string.data;
			if ( *name == '/' )
				strncpy(relpath, name, 1023);
			else
				sprintf(relpath, "%s/lib/dionaea/python/%s", PREFIX, name);
			py_script_files_list = g_list_append(py_script_files_list, strdup(relpath));
			g_debug("py file %s", relpath);
		}
	}

	GList *iterator;
	for ( iterator = g_list_first(py_script_files_list); iterator; iterator = g_list_next(iterator) )
	{
		char *relpath = iterator->data;
		FILE *f = fopen(relpath, "r");
		int ret = 1;

		if ( f )
        {
			g_debug("Initializing file %s %i %p -> %p -> %p", relpath, ret, iterator->prev, iterator, iterator->next);
			ret = PyRun_SimpleFile(f, relpath);
			fclose(f);
		}
	}
	signal(SIGINT, SIG_DFL);


	runtime.stdin = fdopen(STDIN_FILENO, "r");
	ev_io_init(&runtime.python_cli_io_in, python_io_in_cb, STDIN_FILENO, EV_READ);
	ev_io_start(g_dionaea->loop, &runtime.python_cli_io_in);
	printf("python> ");

	return true;
}

struct module_api *module_init(struct dionaea *dionaea)
{
    g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, dionaea);
	static struct module_api python_api =
	{
		.config = &config,
		.prepare = NULL,
		.new = &new,
		.free = &freepy
	};
    return &python_api;
}

void log_wrap(char *name, int number, char *file, int line, char *msg)
{
	char *log_domain;
	GLogLevelFlags log_level;
	int x = 0;

#ifdef DEBUG
	x = asprintf(&log_domain, "%s %s:%i", name, file, line);
#else
	x = asprintf(&log_domain, "%s", name);
#endif

	if ( number == 0 || number == 10 )	
		log_level = G_LOG_LEVEL_DEBUG;
	else
	if ( number == 20 )	
		log_level = G_LOG_LEVEL_INFO;
	if ( number == 30 )	
		log_level = G_LOG_LEVEL_MESSAGE;
	if ( number == 40 )	
		log_level = G_LOG_LEVEL_WARNING;
	if ( number == 50 )	
		log_level = G_LOG_LEVEL_ERROR;
	if ( number == 60 )	
		log_level = G_LOG_LEVEL_CRITICAL;

	g_log(log_domain, log_level, "%s", msg);
	free(log_domain);
}

