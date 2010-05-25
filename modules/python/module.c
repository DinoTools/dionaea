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

#include <Python.h>
#include <glib.h>
#include <stdio.h>
#include <ev.h>
#include <stdint.h>
#include <unistd.h>
#include <dirent.h>


// set terminal to char mode
#include <termios.h>


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

#include "connection.h"
#include "protocol.h"
#include "incident.h"
#include "processor.h"
#include "util.h"
#include "module.h"

#define D_LOG_DOMAIN "python"
PyObject *PyInit_core(void);

struct protocol *trace_proto;

static struct python_runtime
{
	struct lcfgx_tree_node *config;
	struct ev_io python_cli_io_in;
	FILE *stdin;
	GHashTable *imports;
	struct termios read_termios;
	struct termios poll_termios;
	struct ihandler *mkshell_ihandler;
	struct 
	{
		PyObject *module;
		PyObject *export_tb;
	}traceback;

	struct 
	{
		struct protocol proto;
		struct ihandler pyhandler;
		struct processor processor;
	} traceables;
	GString *sys_path;
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
	PyCompilerFlags cf;
	cf.cf_flags = 0;

	tcsetattr(0, TCSANOW, &runtime.read_termios);
	PyRun_InteractiveOneFlags(runtime.stdin, "<stdin>", &cf);
	traceback();
	tcsetattr(0, TCSANOW, &runtime.poll_termios);
}

static void python_mkshell_ihandler_cb(struct incident *i, void *ctx)
{
	g_debug("%s i %p ctx %p", __PRETTY_FUNCTION__, i, ctx);
	struct connection *con;
	if( incident_value_con_get(i, "con", &con) )
	{
		g_debug("mkshell for %p", con);
		const char *name = "cmd";
		PyObject *module = PyImport_ImportModule(name);
		if( module == NULL )
		{
			PyErr_Print();
			g_error("Import failed %s", name);
		}
		Py_DECREF(module);
		PyObject *func = PyObject_GetAttrString(module, "remoteshell");
		PyObject *arglist = Py_BuildValue("()");
		PyObject *r = PyEval_CallObject(func, arglist);
		Py_DECREF(arglist);
		g_debug("r %p", r);
		struct head 
		{
			PyObject_HEAD
		};
		struct connection **pp = (struct connection **)((char *)r + sizeof(struct head));
		g_debug("p %p %p", pp, *pp);
		struct connection *p = *pp;
		con->protocol.ctx = p->protocol.ctx;
		con->protocol.ctx = p->protocol.ctx_new(con);
		con->protocol.io_in = p->protocol.io_in;
		con->protocol.idle_timeout = p->protocol.idle_timeout;
		con->protocol.sustain_timeout = p->protocol.sustain_timeout;
		con->protocol.established = p->protocol.established;
		ev_io_start(g_dionaea->loop, &con->events.io_in);
//		ev_io_start(g_dionaea->loop, &con->events.io_out);
		con->protocol.established(con);
	} else
		g_critical("mkshell fail");

}

static bool hupy(struct lcfgx_tree_node *node)
{
	g_debug("%s node %p",  __PRETTY_FUNCTION__, node);
	runtime.config = node;
	struct lcfgx_tree_node *files;
	if( lcfgx_get_list(runtime.config, &files, "imports") == LCFGX_PATH_FOUND_TYPE_OK )
	{
		struct lcfgx_tree_node *file;
		for( file = files->value.elements; file != NULL; file = file->next )
		{
//			char *name = file->value.string.data;
			char *name;
			if( asprintf(&name, "dionaea.%s", (char *)file->value.string.data) == 0)
				continue;

			struct import *i;
			if( (i = g_hash_table_lookup(runtime.imports, name)) != NULL )
			{
				g_message("Import %s exists, reloading", name);

				PyObject *func = PyObject_GetAttrString(i->module, "stop");
				if( func != NULL )
				{
					PyObject *arglist = Py_BuildValue("()");
					PyObject *r = PyEval_CallObject(func, arglist);
					traceback();
//					PyErr_Print();
					Py_DECREF(arglist);
					Py_XDECREF(r);
					Py_DECREF(func);
				} else
				{
					traceback();
				}

				PyObject *module = PyImport_ReloadModule(i->module);
				if( module == NULL )
				{
					PyErr_Print();
					g_critical("Reloading module %s failed", i->name);
					module = i->module;
				} else
				{
					Py_DECREF(module); 
					i->module = module;
				}
				func = PyObject_GetAttrString(module, "start");
				if( func != NULL )
				{
					PyObject *arglist = Py_BuildValue("()");
					PyObject *r = PyEval_CallObject(func, arglist);
					traceback();
					Py_DECREF(arglist);
					Py_XDECREF(r);
					Py_DECREF(func);
				} else
				{
					traceback();
				}

			} else
			{
				g_message("New Import %s", name);
				PyObject *module = PyImport_ImportModule(name);
				if( module == NULL )
				{
					g_critical("Could not import module %s", name);
					free(name);
					continue;
				}
				Py_DECREF(module); 
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
				} else
					PyErr_Clear();

			}
			free(name);
		}
	}
	return true;
}

static bool freepy(void)
{
	g_debug("%s %s", __PRETTY_FUNCTION__, __FILE__);
	ev_io_stop(g_dionaea->loop, &runtime.python_cli_io_in);
	if( isatty(STDOUT_FILENO) )
		tcsetattr(0, TCSADRAIN, &runtime.read_termios);

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init (&iter, runtime.imports);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		char *name = key;
		struct import *imp = value;
		PyObject *module = imp->module;
		g_info("stop %s %p %p", name, imp, imp->module);

		PyObject *func = PyObject_GetAttrString(module, "stop");
		if( func != NULL )
		{
			PyObject *arglist = Py_BuildValue("()");
			PyObject *r = PyEval_CallObject(func, arglist);
			Py_DECREF(arglist);
			Py_XDECREF(r);
			Py_DECREF(func);
		} else
			PyErr_Clear();
		traceback();
	}
	Py_Finalize();
	return true;
}

static bool new(struct dionaea *dionaea)
{
	g_debug("%s %s %p", __PRETTY_FUNCTION__, __FILE__, g_dionaea);
//	int v = PyImport_AppendInittab("dionaea.core", &PyInit_core);
//	g_warning("PyImport_AppendInittab %i", v);

	g_debug("Python Interpreter %s", PYTHON_PATH);
	size_t pybinsize = mbstowcs(NULL, PYTHON_PATH, 0);
	wchar_t *pybin = g_malloc0((pybinsize + 1) * sizeof(wchar_t));
	mbstowcs(pybin, PYTHON_PATH, pybinsize + 1);
	Py_SetProgramName(pybin);

	Py_Initialize();

	runtime.sys_path = g_string_new(PREFIX"/lib/dionaea/python/");

	PyObject *name = PyUnicode_FromString("traceback");
	runtime.traceback.module = PyImport_Import(name);
	Py_DECREF(name);
	runtime.traceback.export_tb = PyObject_GetAttrString(runtime.traceback.module, "extract_tb");

	PyRun_SimpleString("import sys");
	char relpath[1024];
	int i=0;
	struct lcfgx_tree_node *paths;
	if( lcfgx_get_list(runtime.config, &paths, "sys_path") == LCFGX_PATH_FOUND_TYPE_OK )
	{
		struct lcfgx_tree_node *path;
		for( path = paths->value.elements; path != NULL; path = path->next )
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
	PyRun_SimpleString("from dionaea.core import init_traceables");
	PyRun_SimpleString("init_traceables()");

	runtime.imports = g_hash_table_new(g_str_hash, g_str_equal);
	struct lcfgx_tree_node *files;
	if( lcfgx_get_list(runtime.config, &files, "imports") == LCFGX_PATH_FOUND_TYPE_OK )
	{
		struct lcfgx_tree_node *file;
		for( file = files->value.elements; file != NULL; file = file->next )
		{
			char *name;
			if( asprintf(&name, "dionaea.%s", (char *)file->value.string.data) == 0)
				continue;

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
			} else
				PyErr_Clear();
			traceback();
			free(name);
		}
	}

	signal(SIGINT, SIG_DFL);

	if( isatty(STDOUT_FILENO) )
	{
		g_debug("Interactive Python shell");
		runtime.stdin = fdopen(STDIN_FILENO, "r");
		ev_io_init(&runtime.python_cli_io_in, python_io_in_cb, STDIN_FILENO, EV_READ);
		ev_io_start(g_dionaea->loop, &runtime.python_cli_io_in);

		PyObject *v;
		v = PySys_GetObject("ps1");
		if( v == NULL )
		{
			PySys_SetObject("ps1", v = PyUnicode_FromString(">>> "));
			Py_XDECREF(v);
		}
		v = PySys_GetObject("ps2");
		if( v == NULL )
		{
			PySys_SetObject("ps2", v = PyUnicode_FromString("... "));
			Py_XDECREF(v);
		}

		v = PyImport_ImportModule("readline");
		if( v == NULL )
			PyErr_Clear();
		else
			Py_DECREF(v);

		tcgetattr(0, &runtime.read_termios);
		memcpy(&runtime.poll_termios, &runtime.read_termios, sizeof(struct termios));
		runtime.read_termios.c_lflag |= (ICANON|ECHOCTL|ECHO);
		runtime.poll_termios.c_lflag &= ~(ICANON|ECHOCTL|ECHO);
		tcsetattr(0, TCSANOW, &runtime.poll_termios);
	}

	runtime.mkshell_ihandler = ihandler_new("dionaea.*.mkshell", python_mkshell_ihandler_cb, NULL);
	return true;
}

void log_wrap(char *name, int number, char *file, int line, char *msg)
{
	char *log_domain;
	GLogLevelFlags log_level = G_LOG_LEVEL_DEBUG;
	int x = 0;

#ifdef DEBUG
	if ( strncmp(file, runtime.sys_path->str, runtime.sys_path->len) == 0 )
		file += runtime.sys_path->len;

	x = asprintf(&log_domain, "%s %s:%i", name, file, line);
#else
	x = asprintf(&log_domain, "%s", name);
#endif

	if( number == 0 || number == 10 )
		log_level = G_LOG_LEVEL_DEBUG;
	else
		if( number == 20 )
		log_level = G_LOG_LEVEL_INFO;
	if( number == 30 )
		log_level = G_LOG_LEVEL_WARNING;
	if( number == 40 )
		log_level = G_LOG_LEVEL_ERROR;
	if( number == 50 )
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
	pyafdict = NULL;
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
		} else
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
		} else
			if( iface->ifa_addr->sa_family == AF_PACKET && PyList_Size(pyaflist) == 0 )
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
		if( offset && iface->ifa_addr->sa_family != AF_PACKET )
		{
			inet_ntop(iface->ifa_addr->sa_family, offset, ip_string, INET6_ADDRSTRLEN);
			pynetmask = PyUnicode_FromString(ip_string);
			PyDict_SetItemString(pyafdetails, "netmask", pynetmask);
			Py_DECREF(pynetmask);
		}

		if( iface->ifa_addr->sa_family == AF_INET6 )
		{
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)iface->ifa_addr;

			if( ipv6_addr_linklocal(&sa6->sin6_addr) )
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


PyObject *pylcfgx_tree(struct lcfgx_tree_node *node)
{
	PyObject *obj = NULL;
	if( node->type == lcfgx_map )
	{
		obj = PyDict_New();
		struct lcfgx_tree_node *it;
		for( it = node->value.elements; it != NULL; it = it->next )
		{
			PyObject *val = pylcfgx_tree(it);
			PyDict_SetItemString(obj, it->key, val);
			Py_DECREF(val);
		}
	} else
		if( node->type == lcfgx_list )
	{
		obj = PyList_New(0);
		struct lcfgx_tree_node *it;
		for( it = node->value.elements; it != NULL; it = it->next )
		{
			PyObject *val = pylcfgx_tree(it);
			PyList_Append(obj, val);
			Py_DECREF(val);
		}
	} else
		if( node->type == lcfgx_string )
	{
		obj = PyUnicode_FromStringAndSize(node->value.string.data, node->value.string.len);
	}
	return obj; 
}

PyObject *pylcfg(PyObject *self, PyObject *args)
{
	PyObject *obj = pylcfgx_tree(g_dionaea->config.root);
	return obj;
}

/**
 * traceback requirements
 * cython is rather special for exceptions
 * you can create try/catch blocks, but you do not get access to the
 * exception/traceback
 * therefore we proxy all calls to cython code, and ask cython to preserve
 * the exception flags, so we can take care in our proxy
 *  
 */


void set_ihandler(struct ihandler *ih)
{
	memcpy(&runtime.traceables.pyhandler, ih, sizeof(struct ihandler));
}

void traceable_ihandler_cb (struct incident *i, void *ctx)
{
	g_debug("%s incident %p ctx %p",__PRETTY_FUNCTION__, i, ctx);
	runtime.traceables.pyhandler.cb(i, ctx);
	traceback();
}

/**
 * called from cython code, 
 * exports pointers to the cython protocol functions
 * 
 * @param p      the cython protocol
 */
void set_protocol(struct protocol *p)
{
	memcpy(&runtime.traceables.proto, p,  sizeof(struct protocol));
}


void *traceable_ctx_new_cb(struct connection *con)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
	void *ctx = runtime.traceables.proto.ctx_new(con);
	traceback();
	return ctx;
}

void traceable_ctx_free_cb(void *ctx)
{
	g_debug("%s ctx %p", __PRETTY_FUNCTION__, ctx);
	runtime.traceables.proto.ctx_free(ctx);
	traceback();
}

void traceable_origin_cb(struct connection *con, struct connection *origin)
{
	g_debug("%s origin %p con %p", __PRETTY_FUNCTION__, origin, con);
	runtime.traceables.proto.origin(con, origin);
	traceback();
}

void traceable_established_cb(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	runtime.traceables.proto.established(con);
	traceback();
}


uint32_t traceable_io_in_cb(struct connection *con, void *context, unsigned char *data, uint32_t size)
{
	g_debug("%s con %p ctx %p data %p size %i",__PRETTY_FUNCTION__, con, context, data, size);
	uint32_t s = runtime.traceables.proto.io_in(con, context, data, size);
	traceback();
	return s;
}

void traceable_io_out_cb(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p",__PRETTY_FUNCTION__, con, context);
	runtime.traceables.proto.io_out(con, context);
	traceback();
}

bool traceable_error_cb(struct connection *con, enum connection_error error)
{
	g_debug("%s con %p error %i",__PRETTY_FUNCTION__, con, error);
	bool ret = runtime.traceables.proto.error(con, error);
	traceback();
	return ret;
}

bool traceable_disconnect_cb(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	bool ret = runtime.traceables.proto.disconnect(con, context);
	traceback();
	return ret;
}

bool traceable_idle_timeout_cb(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	bool ret = runtime.traceables.proto.idle_timeout(con, context);
	traceback();
	return ret;
}

bool traceable_listen_timeout_cb(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	bool ret = runtime.traceables.proto.listen_timeout(con, context);
	traceback();
	return ret;
}

bool traceable_sustain_timeout_cb(struct connection *con, void *context)
{
	g_debug("%s con %p ctx %p ",__PRETTY_FUNCTION__, con, context);
	bool ret = runtime.traceables.proto.sustain_timeout(con, context);
	traceback();
	return ret;
}

/**
 * python bistreams are special 
 * we want to allow python to access the bistream dump as part 
 * of the connection object, therefore we create a dummy stream 
 * processor, which is only attached to python connections 
 *  
 *  
 */

void set_processor(struct processor *p)
{
	memcpy(&runtime.traceables.processor, p, sizeof(struct processor));
}

void python_processor_bistream_create(struct connection *con);
void python_processor_bistream_remove(struct connection *con);
void python_processor_bistream_io_in(struct connection *con, struct processor_data *pd, void *data, int size);
void python_processor_bistream_io_out(struct connection *con, struct processor_data *pd, void *data, int size);
void python_processor_bistream_free(void *data);

struct processor proc_python_bistream =
{
	.name = "python-processor-bistream",
	.free = python_processor_bistream_free,
	.io_in = python_processor_bistream_io_in,
	.io_out = python_processor_bistream_io_out,
};

struct processor_data proc_python_bistream_processor_data = 
{
	.processor = &proc_python_bistream,
};

void python_processor_bistream_create(struct connection *con)
{

	struct processor_data *pd = processor_data_new();
	pd->processor = &proc_python_bistream;
	con->processor_data->filters = g_list_append(con->processor_data->filters, pd);
}

void python_processor_bistream_remove(struct connection *con)
{
	GList *it;
	for( it = g_list_first(con->processor_data->filters); it != NULL; it = g_list_next(it) )
	{
		if( it->data == &proc_python_bistream_processor_data )
		{
			con->processor_data->filters = g_list_remove(con->processor_data->filters, it);
			return;
		}
	}
}


void python_processor_bistream_io_in(struct connection *con, struct processor_data *pd, void *data, int size)
{
	runtime.traceables.processor.io_in(con, NULL, data, size);
}

void python_processor_bistream_io_out(struct connection *con, struct processor_data *pd, void *data, int size)
{
	runtime.traceables.processor.io_out(con, NULL, data, size);
}

void python_processor_bistream_free(void *data)
{
}

static char *pyobjectstring(PyObject *obj)
{
	PyObject *pyobjectstr;

	if( obj == NULL )
		return g_strdup("<null>");

	if( obj == Py_None )
		return g_strdup("None");

	if( PyType_Check(obj) )
		return g_strdup(((PyTypeObject* ) obj)->tp_name);

	if( PyUnicode_Check(obj) )
		pyobjectstr = obj;
	else 
	if( (pyobjectstr = PyObject_Repr(obj)) != NULL )
	{
		if( PyUnicode_Check(pyobjectstr) == 0 )
		{
			Py_XDECREF(pyobjectstr);
			return g_strdup("<!utf8>");
		}
	} else
		return g_strdup("<!repr>");

	Py_ssize_t pysize = PyUnicode_GetSize(pyobjectstr);
	wchar_t * str = (wchar_t *) malloc((pysize + 1) * sizeof(wchar_t));
	PyUnicode_AsWideChar((PyUnicodeObject *) pyobjectstr, str, pysize);
	str[pysize] = '\0';

	if( pyobjectstr != obj )
		Py_DECREF(pyobjectstr);

	// measure size
	size_t csize = wcstombs(0, str, 0);
	if( csize == (size_t) -1 )
		return g_strdup("<!wcstombs>");

	char *cstr = (char *) g_malloc(csize + 1);

	// convert
	wcstombs(cstr, str, csize + 1);
	free(str);
	return cstr;
}


void traceback(void)
{
	if( !PyErr_Occurred() )
	{
		return;
	}

	PyObject *type;
	PyObject *value;
	PyObject *traceback;
	PyErr_Fetch(&type, &value, &traceback);

	char *type_string = NULL;
	char *value_string = NULL;

	if( type != NULL )
		type_string = pyobjectstring(type);
	else
		type_string	= g_strdup("unknown type");

	if( value != NULL )
		value_string = pyobjectstring(value);
	else
		value_string = g_strdup("unknown value");

	g_warning("%s at %s", type_string, value_string);

	g_free(type_string);
	g_free(value_string);

	PyObject *args = PyTuple_Pack(1, traceback);
	PyObject *res = PyObject_CallObject(runtime.traceback.export_tb, args);

	if( res && PyList_Check(res) )
	{
		size_t k;
		for( k = PyList_GET_SIZE(res); k; --k )
		{
			PyObject *tuple = PyList_GET_ITEM(res, k-1);
			char *filename = pyobjectstring(PyTuple_GET_ITEM(tuple, 0));
			char *line_no = pyobjectstring(PyTuple_GET_ITEM(tuple, 1));
			char *function_name = pyobjectstring(PyTuple_GET_ITEM(tuple, 2));
			char *text = pyobjectstring(PyTuple_GET_ITEM(tuple, 3));
//			g_warning(" %s:%s in %s \n\t %s", filename, line_no, function_name, text);
			g_warning("%s:%s in %s", filename, line_no, function_name);
			g_warning("\t %s", text);

			g_free(filename);
			g_free(line_no);
			g_free(function_name);
			g_free(text);

		}
	}

	Py_XDECREF(res);
	Py_XDECREF(args);

	Py_XDECREF(type);
	Py_XDECREF(value);
	Py_XDECREF(traceback);

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

