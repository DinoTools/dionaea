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
#include <stdbool.h>
#include <string.h>
#include "incident.h"
#include "dionaea.h"
#include "log.h"

#define D_LOG_DOMAIN "incident"


struct opaque_data *opaque_data_new(void)
{
	struct opaque_data * d = g_malloc0(sizeof(struct opaque_data));
	return d;
}

void opaque_data_free(struct opaque_data *d)
{
	if( d->type == opaque_type_string )
		g_string_free(d->opaque.string, TRUE);
	g_free(d);
}

struct ihandler *ihandler_new(char *pattern, ihandler_cb cb, void *ctx)
{
	g_debug("%s pattern %s cb %p ctx %p", __PRETTY_FUNCTION__, pattern, cb, ctx);
	struct ihandler *i = g_malloc0(sizeof(struct ihandler));
	g_debug("ihandler %p pattern %s cb %p ctx %p", i, pattern, cb, ctx);
	i->path = g_strdup(pattern);
	i->match = g_pattern_spec_new(pattern);
	i->cb = cb;
	i->ctx = ctx;
	g_dionaea->ihandlers->handlers = g_list_append(g_dionaea->ihandlers->handlers, i);
	return i;
}

void ihandler_free(struct ihandler *i)
{
	g_debug("%s i %p", __PRETTY_FUNCTION__, i);
	g_dionaea->ihandlers->handlers = g_list_remove(g_dionaea->ihandlers->handlers, i);
	g_free(i);
}



struct incident *incident_new(const char *path)
{
	struct incident *e = g_malloc0(sizeof(struct incident));
	e->origin = g_strdup(path);
	e->data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)opaque_data_free);
	return e;
}

void incident_free(struct incident *e)
{
	g_hash_table_destroy(e->data);
	g_free(e->origin);
	g_free(e);
}

struct opaque_data *incident_value_get(struct incident *e, const char *name, enum opaque_data_type t)
{
	struct opaque_data *d;
	if( ( d = g_hash_table_lookup(e->data, name)) == NULL )
	{
		g_debug("could not find key '%s'", name);
		return NULL;
	}
	if( d->type != t )
		return NULL;
	return d;
}

bool incident_value_int_set(struct incident *e, const char *name, long int val)
{
	struct opaque_data *d = opaque_data_new();
	d->type = opaque_type_int;
	d->opaque.integer = val;
	d->name = g_strdup(name);
	g_hash_table_insert(e->data, (gpointer)d->name, d);
	return true;
}

bool incident_value_int_get(struct incident *e, const char *name, long int *val)
{
	struct opaque_data *d = incident_value_get(e, name, opaque_type_int);
	if( d == NULL )
		return false;
	*val = d->opaque.integer;
	return true;
}


bool incident_value_con_set(struct incident *e, const char *name, struct connection *con)
{
	struct opaque_data *d = opaque_data_new();
	d->type = opaque_type_ptr;
	d->opaque.con = con;
	d->name = g_strdup(name);
	g_hash_table_insert(e->data, d->name, d);
	return true;
}

bool incident_value_con_get(struct incident *e, const char *name, struct connection **con)
{
	struct opaque_data *d = incident_value_get(e, name, opaque_type_ptr);
	if( d == NULL )
		return false;
	*con = d->opaque.con;
	return true;
}

bool incident_value_string_set(struct incident *e, const char *name, GString *val)
{
	struct opaque_data *d = opaque_data_new();
	d->type = opaque_type_string;
	d->opaque.string = val;
	d->name = g_strdup(name);
	g_hash_table_insert(e->data, (gpointer)d->name, d);
	return true;
}

bool incident_value_string_get(struct incident *e, const char *name, GString **val)
{
	struct opaque_data *d = incident_value_get(e, name, opaque_type_string);
	if( d == NULL )
		return false;
	*val = d->opaque.string;
	return true;
}

bool incident_keys_get(struct incident *e, char ***keys)
{
	int c= g_hash_table_size(e->data);
	char **kexs = g_malloc0((c+5)*sizeof(char **));
	int i=0;
	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init (&iter, e->data);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		kexs[i] = (char *)g_strdup(key);
		i++;
 	};
	kexs[i] = NULL;

	*keys = kexs;
	return true;
}

void incident_dump(struct incident *e)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, e->data);
	g_debug("incident %p %s", e, e->origin);
	while( g_hash_table_iter_next (&iter, &key, &value) )
	{
		char x[1024];
		char *name = key;
		struct opaque_data *d = value;
		if( d->type == opaque_type_int )
		{
			g_snprintf(x, 1023, "%s: (int) %li", name, d->opaque.integer);
		} else
			if( d->type == opaque_type_string )
		{
			g_snprintf(x, 1023, "%s: (string) %.*s", name, (int)d->opaque.string->len, d->opaque.string->str);
		} else
			if( d->type == opaque_type_ptr )
		{
			g_snprintf(x, 1023, "%s: (ptr) %p", name, (void *)d->opaque.ptr);
		}
		g_debug("\t%s", x);
	}
}


void incident_report(struct incident *i)
{
	g_debug("reporting %p", i);
	incident_dump(i);
	for( GList *it=g_dionaea->ihandlers->handlers; it != NULL; it = g_list_next(it) )
	{
		struct ihandler *ih = it->data;
		if( g_pattern_match(ih->match, strlen(i->origin), i->origin, NULL ) == TRUE )
		{
			ih->cb(i, ih->ctx);
		}
	}
}
