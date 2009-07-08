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


#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdlib.h> // qsort
#include <ifaddrs.h> // getifaddrs
#include <stddef.h> // offsetof
#include <net/if.h> // if_nametoindex

#include <netpacket/packet.h> // af_packet



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
	GHashTable *imports;
} runtime;

struct import
{
	char *name;
	PyObject *module;
};

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

static bool hupy(struct lcfgx_tree_node *node)
{
	runtime.config = node;
	struct lcfgx_tree_node *files;
	if(lcfgx_get_list(runtime.config, &files, "files") == LCFGX_PATH_FOUND_TYPE_OK)
	{
		struct lcfgx_tree_node *file;
		for (file = files->value.elements; file != NULL; file = file->next)
		{
			char *name = file->value.string.data;
			struct import *i;
			if( (i = g_hash_table_lookup(runtime.imports, name)) != NULL )
			{
				g_message("Import %s exists, reloading", name);

				PyObject *func = PyObject_GetAttrString(i->module, "stop");
				if( func != NULL )
				{
					PyObject *arglist = Py_BuildValue("()");
					PyObject *r = PyEval_CallObject(func, arglist);
					PyErr_Print();
					Py_DECREF(arglist);
					Py_XDECREF(r);
					Py_DECREF(func);
				}else
					PyErr_Clear();

				PyObject *module = PyImport_ReloadModule(i->module);
				if( module == NULL )
				{
					PyErr_Print();
					g_critical("Reloading module %s failed", i->name);
					module = i->module;
				}else
				{
					Py_DECREF(module); 
					i->module = module;
				}
				func = PyObject_GetAttrString(module, "start");
				if( func != NULL )
				{
					PyObject *arglist = Py_BuildValue("()");
					PyObject *r = PyEval_CallObject(func, arglist);
					Py_DECREF(arglist);
					Py_XDECREF(r);
					Py_DECREF(func);
				}else
					PyErr_Clear();

			}else
			{
				g_message("New Import %s", name);
				PyObject *module = PyImport_ImportModule(name);
				Py_DECREF(module); 
				if( module == NULL )
				{
					g_critical("Could not import module %s", name);
					continue;
				}
				i = g_malloc0(sizeof(struct import));
				i->name = g_strdup(name);
				i->module = module;
				g_hash_table_insert(runtime.imports, i->name, i);

				PyObject *func = PyObject_GetAttrString(module, "start");
				if( func != NULL )
				{
					PyObject *arglist = Py_BuildValue("()");
					PyObject *r = PyEval_CallObject(func, arglist);
					Py_DECREF(arglist);
					Py_XDECREF(r);
					Py_DECREF(func);
				}else
					PyErr_Clear();

			}
		}
	}
	return true;
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

	g_debug("Python Interpreter %s", PYTHON_PATH);
	size_t pybinsize = mbstowcs(NULL, PYTHON_PATH, 0);
	wchar_t *pybin = g_malloc0((pybinsize + 1) * sizeof(wchar_t));
	mbstowcs(pybin, PYTHON_PATH, pybinsize + 1);
	Py_SetProgramName(pybin);

	Py_Initialize();

	PyRun_SimpleString("import sys");

	char relpath[1024];
	int i=0;
	struct lcfgx_tree_node *paths;
	if(lcfgx_get_list(runtime.config, &paths, "sys_path") == LCFGX_PATH_FOUND_TYPE_OK)
	{
		struct lcfgx_tree_node *path;
		for (path = paths->value.elements; path != NULL; path = path->next)
		{
			char *name = path->value.string.data;
			if( strcmp(name, "default") == 0 )
				sprintf(relpath, "sys.path.insert(%i, '%s/lib/dionaea/python/')", i, PREFIX);
			else 
			if( *name == '/' )
				sprintf(relpath, "sys.path.insert(%i, '%s')", i, name);
			else
				sprintf(relpath, "sys.path.insert(%i, '%s/%s')", i, PREFIX, name);
			g_debug("running %s %s", relpath, name);
			PyRun_SimpleString(relpath); 
			i++;
		}
	}

	runtime.imports = g_hash_table_new(g_str_hash, g_str_equal);
	struct lcfgx_tree_node *files;
	if(lcfgx_get_list(runtime.config, &files, "imports") == LCFGX_PATH_FOUND_TYPE_OK)
	{
		struct lcfgx_tree_node *file;
		for (file = files->value.elements; file != NULL; file = file->next)
		{
			char *name = file->value.string.data;
			PyObject *module = PyImport_ImportModule(name);
			if( module == NULL )
			{
				PyErr_Print();
				g_error("Import failed %s", name);
			}
			Py_DECREF(module); 
			struct import *i = g_malloc0(sizeof(struct import));
			i->name = g_strdup(name);
			i->module = module;
			g_hash_table_insert(runtime.imports, i->name, i);
			PyObject *func = PyObject_GetAttrString(module, "start");
			if( func != NULL )
			{
				PyObject *arglist = Py_BuildValue("()");
				PyObject *r = PyEval_CallObject(func, arglist);
				Py_DECREF(arglist);
				Py_XDECREF(r);
				Py_DECREF(func);
			}else
				PyErr_Clear();
		}
	}

	signal(SIGINT, SIG_DFL);

	if ( isatty(STDOUT_FILENO) )
	{
		g_debug("Interactive Python shell");
		runtime.stdin = fdopen(STDIN_FILENO, "r");
		ev_io_init(&runtime.python_cli_io_in, python_io_in_cb, STDIN_FILENO, EV_READ);
		ev_io_start(g_dionaea->loop, &runtime.python_cli_io_in);
		printf("python> ");
	}

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
		.free = &freepy,
		.hup = &hupy
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
		log_level = G_LOG_LEVEL_WARNING;
	if ( number == 40 )	
		log_level = G_LOG_LEVEL_ERROR;
	if ( number == 50 )	
		log_level = G_LOG_LEVEL_CRITICAL;

	g_log(log_domain, log_level, "%s", msg);
	free(log_domain);

}

static int cmp_ifaddrs_by_ifa_name(const void *p1, const void *p2)
{
	return strcmp((*(struct ifaddrs **)p1)->ifa_name, (*(struct ifaddrs **)p2)->ifa_name);
}


PyObject *pygetifaddrs(PyObject *self, PyObject *args)
{
#define ADDROFFSET(x) \
(x) ? \
	((((struct sockaddr *)(x))->sa_family == AF_INET) ?  \
		((void *)(x) + offsetof(struct sockaddr_in, sin_addr)) :  \
		(((struct sockaddr *)(x))->sa_family == AF_INET6) ? \
			((void *)(x) + offsetof(struct sockaddr_in6, sin6_addr)) : \
			NULL) : \
	NULL


	struct ifaddrs *iface, *head;
	PyObject *result;

	result = PyDict_New();

	if( getifaddrs(&head) < 0 )
		return result;

	PyObject *pyiface, *pyaddr, *pynetmask, *pybroadcast, *pypointtopoint, *pyaf, *pyafdict, *pyaflist, *pyafdetails, *pyscopeid;

	int count=0;
	for( iface=head; iface != NULL; iface=iface->ifa_next )
		count++;

	struct ifaddrs *ifaces[count];
	memset(ifaces, 0, count*sizeof(struct ifaces *));

	for( count=0,iface=head; iface != NULL; iface=iface->ifa_next )
		ifaces[count++] = iface;

	qsort(ifaces, count, sizeof(struct ifaddrs *), cmp_ifaddrs_by_ifa_name);

	int i=0;

	char *old_ifa_name = "";
	for( iface=ifaces[0]; i < count; iface = ifaces[i], i++ )
	{
		if( iface->ifa_addr == NULL )
			continue;

		if( iface->ifa_addr->sa_family != AF_INET && iface->ifa_addr->sa_family != AF_INET6 && iface->ifa_addr->sa_family != AF_PACKET )
			continue;

		if( !(iface->ifa_flags & IFF_UP) )
			continue;

		if( strcmp(old_ifa_name, iface->ifa_name) != 0 )
		{
			old_ifa_name = iface->ifa_name;
			pyiface = PyUnicode_FromString(iface->ifa_name);
			pyafdict = PyDict_New();
			PyDict_SetItemString (result, iface->ifa_name, pyafdict);
			Py_DECREF(pyiface);
		}

		pyaf = PyLong_FromLong(iface->ifa_addr->sa_family);
		if( ! PyDict_Contains(pyafdict, pyaf) )
		{
			pyaflist = PyList_New(0);
			PyDict_SetItem(pyafdict, pyaf, pyaflist);
		}else
		{
			pyaflist = PyDict_GetItem(pyafdict, pyaf);
		}
		Py_DECREF(pyaf);

		pyafdetails = PyDict_New();

		pyaddr = NULL;
		char ip_string[INET6_ADDRSTRLEN+1] = "";
		void *offset = ADDROFFSET(iface->ifa_addr);
		if( offset )
		{
			inet_ntop(iface->ifa_addr->sa_family, offset, ip_string, INET6_ADDRSTRLEN);
			pyaddr = PyUnicode_FromString(ip_string);
			PyDict_SetItemString(pyafdetails, "addr", pyaddr);
			Py_DECREF(pyaddr);
		}else
		if( iface->ifa_addr->sa_family == AF_PACKET && PyList_Size(pyaflist) == 0)
		{
	        struct sockaddr_ll *lladdr = (struct sockaddr_ll *)iface->ifa_addr;

			int len = lladdr->sll_halen;
			char *data = (char *)lladdr->sll_addr;
			char *ptr = ip_string;
			int j;
			for( j = 0; j < len; j++ )
			{
				sprintf (ptr, "%02x:", data[j] & 0xff);
				ptr += 3;
			}
			*--ptr = '\0';
			pyaddr = PyUnicode_FromString(ip_string);
			PyDict_SetItemString(pyafdetails, "addr", pyaddr);
			Py_DECREF(pyaddr);
		}

		if( pyaddr )
			PyList_Append(pyaflist, pyafdetails);
		Py_DECREF(pyafdetails);


		offset = ADDROFFSET(iface->ifa_netmask);
		if( offset && iface->ifa_addr->sa_family != AF_PACKET)
		{
			inet_ntop(iface->ifa_addr->sa_family, offset, ip_string, INET6_ADDRSTRLEN);
			pynetmask = PyUnicode_FromString(ip_string);
			PyDict_SetItemString(pyafdetails, "netmask", pynetmask);
			Py_DECREF(pynetmask);
		}

		if( iface->ifa_addr->sa_family == AF_INET6)
 		{
			struct sockaddr_in6 *sa6 = iface->ifa_addr;

			if ( ipv6_addr_linklocal(&sa6->sin6_addr) )
			{	// local scope address
				pyscopeid = PyLong_FromLong(if_nametoindex(iface->ifa_name));
				PyDict_SetItemString(pyafdetails, "scope", pyscopeid);
				Py_DECREF(pyscopeid);
			}
		}

		if( iface->ifa_flags & IFF_BROADCAST )
		{
			offset = ADDROFFSET(iface->ifa_ifu.ifu_broadaddr);
			if( offset )
			{	
				inet_ntop(iface->ifa_addr->sa_family, offset, ip_string, INET6_ADDRSTRLEN);
				pybroadcast = PyUnicode_FromString(ip_string);
				PyDict_SetItemString(pyafdetails, "broadcast", pybroadcast);
				Py_DECREF(pybroadcast);
			}
		}

		if( iface->ifa_flags & IFF_POINTOPOINT )
		{
			offset = ADDROFFSET(iface->ifa_ifu.ifu_dstaddr);
			if( offset )
			{	
				inet_ntop(iface->ifa_addr->sa_family, offset, ip_string, INET6_ADDRSTRLEN);
				pypointtopoint = PyUnicode_FromString(ip_string);
				PyDict_SetItemString(pyafdetails, "pointtopoint", pypointtopoint);
				Py_DECREF(pypointtopoint);
			}
		}
	}
#undef ADDROFFSET
	freeifaddrs(head);
	return result;


}


