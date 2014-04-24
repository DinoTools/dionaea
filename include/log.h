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
#include <glib.h>
#include <stdio.h>
#include "config.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT __FILE__ ":" TOSTRING(__LINE__)

#ifdef G_LOG_DOMAIN
#undef G_LOG_DOMAIN
#ifdef DEBUG
#define G_LOG_DOMAIN D_LOG_DOMAIN " " AT
#else
#define G_LOG_DOMAIN D_LOG_DOMAIN
#endif /* DEBUG */
#endif

// g_info() was added in glib 2.40
#ifndef g_info
#define g_info(...) g_log(G_LOG_DOMAIN,	G_LOG_LEVEL_INFO, __VA_ARGS__)
#endif

#ifdef NDEBUG
#undef g_debug
#define g_debug(...)
#endif

#ifdef PERFORMANCE
#undef g_info
#define g_info(...)
#undef g_message
#define g_message(...)
#undef g_warning
#define g_warning(...)
#endif


struct logging
{
	GMutex *lock;
	GList *loggers;
};

struct log_level_map
{
	const char *name;
	int mask;
};

struct domain_filter
{
	char *domain;
	GPatternSpec *pattern;
};

struct log_filter
{
	struct domain_filter **domains;
	int mask;
};
struct log_filter *log_filter_new(const char *domains, const char *levels);
bool log_filter_match(struct log_filter *filter, const char *log_domain, int log_level);

extern struct log_level_map log_level_mapping[];

struct logger;
typedef bool (*log_util_fn)(struct logger *, void *data);
struct logger
{
	log_util_fn open;
	log_util_fn close;
	log_util_fn hup;
	log_util_fn flush;
	GLogFunc log;
	int fd;
	void *data;
};
struct logger *logger_new(GLogFunc log, log_util_fn xopen, log_util_fn hup, log_util_fn xclose, log_util_fn xflush, void *data);


void log_multiplexer(const gchar *log_domain, 
					 GLogLevelFlags log_level,
					 const gchar *message,
					 gpointer user_data);


struct logger_file_data
{
	char file[PATH_MAX+1];
	FILE *f;
	struct log_filter *filter;
};

void logger_file_log(const gchar *log_domain, 
					 GLogLevelFlags log_level,
					 const gchar *message,
					 gpointer user_data);
bool logger_file_open(struct logger *l, void *data);
bool logger_file_close(struct logger *l, void *data);
bool logger_file_hup(struct logger *l, void *data);


bool logger_stdout_open(struct logger *l, void *data);
void logger_stdout_log(const gchar *log_domain, 
					   GLogLevelFlags log_level,
					   const gchar *message,
					   gpointer user_data);
bool logger_file_flush(struct logger *l, void *data);

