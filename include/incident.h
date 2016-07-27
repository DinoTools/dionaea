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
#include <stdint.h>
#include <stdbool.h>

struct incident;

struct ihandlers
{
	GList *handlers;
};


typedef void (*ihandler_cb)(struct incident *i, void *ctx);
struct ihandler
{
	const char *path;
	GPatternSpec *match;
	ihandler_cb cb;
	void *ctx;
};

struct ihandler *ihandler_new(char *pattern, ihandler_cb cb, void *ctx);
void ihandler_free(struct ihandler *i);

enum opaque_data_type
{
	opaque_type_none,
	opaque_type_bytes,
	opaque_type_string,
	opaque_type_int,
	opaque_type_ptr,
	opaque_type_list,
	opaque_type_dict
};

struct connection;

struct opaque_data
{
	enum opaque_data_type type;
	char *name;
	union
	{
		GString     *string;
		long int    integer;
		uintptr_t   ptr;
		struct connection *con;
		GList *list;
		GHashTable *dict;
	}opaque;
};
struct opaque_data *opaque_data_new(void);
void opaque_data_free(struct opaque_data *d);
void opaque_data_bytes_set(struct opaque_data *d, GString *val);
void opaque_data_bytes_get(struct opaque_data *d, GString **val);
void opaque_data_string_set(struct opaque_data *d, GString *val);
void opaque_data_string_get(struct opaque_data *d, GString **val);
void opaque_data_int_set(struct opaque_data *d, long int val);
void opaque_data_int_get(struct opaque_data *d, long int *val);
void opaque_data_con_set(struct opaque_data *d, struct connection *val);
void opaque_data_con_get(struct opaque_data *d, struct connection **val);
void opaque_data_list_set(struct opaque_data *d, GList *val);
void opaque_data_list_get(struct opaque_data *d, GList **val);
void opaque_data_dict_set(struct opaque_data *d, GHashTable *val);
void opaque_data_dict_get(struct opaque_data *d, GHashTable **val);
void opaque_data_none_set(struct opaque_data *d);
void opaque_data_none_get(struct opaque_data *d);

struct incident
{
	char *origin;
	GHashTable  *data;
};



struct incident *incident_new(const char *origin);
void incident_free(struct incident *e);
bool incident_value_int_set(struct incident *e, const char *name, long int val);
bool incident_value_int_get(struct incident *e, const char *name, long int *val);
bool incident_value_con_set(struct incident *e, const char *name, struct connection *val);
bool incident_value_con_get(struct incident *e, const char *name, struct connection **val);
bool incident_value_bytes_set(struct incident *e, const char *name, GString *str);
bool incident_value_bytes_get(struct incident *e, const char *name, GString **str);
bool incident_value_string_set(struct incident *e, const char *name, GString *str);
bool incident_value_string_get(struct incident *e, const char *name, GString **str);
bool incident_value_list_set(struct incident *e, const char *name, GList *list);
bool incident_value_list_get(struct incident *e, const char *name, GList **list);
bool incident_value_dict_set(struct incident *e, const char *name, GHashTable *val);
bool incident_value_dict_get(struct incident *e, const char *name, GHashTable **val);
bool incident_value_none_set(struct incident *e, const char *name);
bool incident_value_none_get(struct incident *e, const char *name);

void incident_dump(struct incident *e);

bool incident_keys_get(struct incident *e, char ***keys);
void incident_report(struct incident *i);

/*
	struct incident *e = incident_new("test");
	incident_value_int_set(e, "int_test", 4711);
	incident_value_string_set(e, "string_test", g_string_new("4711"));
	incident_value_con_set(e, "ptr_test", 0x4711);
	incident_dump(e);
	incident_report(e);
	incident_free(e)
*/

