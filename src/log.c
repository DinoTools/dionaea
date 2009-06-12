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
#include <string.h>
#include <ev.h>
#include <stdbool.h>
#include <errno.h>

#include "dionaea.h"
#include "log.h"

#define D_LOG_DOMAIN "log"

struct logger *logger_new(GLogFunc xlog, log_util_fn xopen, log_util_fn xhup, log_util_fn xclose, void *data)
{
	struct logger *l = g_malloc0(sizeof(struct logger));
	l->open = xopen;
	l->log = xlog;
	l->data = data;
	l->hup = xhup;
	l->close = xclose;
	return l;
}


struct log_filter *log_filter_new(const char *domains, const char *levels)
{
	int mask = 0;
	if ( levels != NULL )
	{
		static struct log_level_map log_level_mapping[] = 
		{
			{"error",		G_LOG_LEVEL_ERROR},
			{"critical", 	G_LOG_LEVEL_CRITICAL},
			{"warning", 	G_LOG_LEVEL_WARNING},
			{"message",		G_LOG_LEVEL_MESSAGE},
			{"info",		G_LOG_LEVEL_INFO},
			{"debug",		G_LOG_LEVEL_DEBUG},
			{"all",			G_LOG_LEVEL_MASK},
			{ NULL, 0 }
		};
		char **flags = g_strsplit(levels, ",", 0);
		for ( unsigned int i=0; flags[i] != NULL; i++ )
		{
			for ( unsigned int j=0; log_level_mapping[j].name != NULL; j++)
			{
				if ( strcmp(log_level_mapping[j].name, flags[i]) == 0 )
				{
					mask |= log_level_mapping[j].mask;
					goto found_flag;
				}
			}
			g_error("%s is not a valid message filter flag", flags[i]);
			return NULL;
found_flag:
			continue;
		}
	}

	struct log_filter *f = g_malloc0(sizeof(struct log_filter));

	f->mask = mask;
	f->domains = g_malloc0(sizeof(struct domain_filter *));
	f->domains[0] = NULL;

	if ( domains != NULL )
	{
		char **flags = g_strsplit(domains, ",", 0);
		for ( unsigned int i=0; flags[i] != NULL; i++ )
		{
			f->domains = g_realloc(f->domains, sizeof(struct domain_filter *) * (i+2));
			f->domains[i] = g_malloc0(sizeof(struct domain_filter));
			f->domains[i]->domain = g_strdup(flags[i]);
			f->domains[i]->pattern = g_pattern_spec_new(flags[i]);
			f->domains[i+1] = NULL;
		}
	}

	return f;
}

bool log_filter_match(struct log_filter *filter, const char *log_domain, int log_level)
{
	char *log_domain_work;

	if ( filter != NULL )
	{
		if ( (log_level & filter->mask ) == 0 )
			return false;

		if ( !log_domain )
			goto no_log_domain;

#ifdef DEBUG
		log_domain_work =  g_strdup(log_domain);
		char *x = strstr(log_domain_work, " ");
		if ( x != NULL )
			*x = '\0';
#else 
		log_domain_work = (char *)log_domain;
#endif

		for ( unsigned int i=0; filter->domains[i] != NULL; i++)
		{
			if ( g_pattern_match(filter->domains[i]->pattern, 
								 strlen(log_domain_work), 
								 log_domain_work,  NULL) == TRUE)
				goto domain_matched;
		}
#ifdef DEBUG
		g_free(log_domain_work);
#endif
		return false;

domain_matched:
#ifdef DEBUG
		g_free(log_domain_work);
#endif
		log_domain_work = NULL;
	}else
		return false;

no_log_domain:
	return true;
}

void log_multiplexer(const gchar *log_domain, 
			GLogLevelFlags log_level,
			const gchar *message,
            gpointer user_data)
{

	for (	GList *it = g_dionaea->logging->loggers; it != NULL; it = it->next)
	{
		struct logger *logger = it->data;
		logger->log(log_domain, log_level, message, logger->data);
	}
}

void logger_stdout_log(const gchar *log_domain, 
			GLogLevelFlags log_level,
			const gchar *message,
            gpointer user_data)
{
	const char *level = NULL;

	if ( user_data && log_filter_match(user_data, log_domain, log_level) == false )
		return;

	static struct log_level_map log_level_mapping[] = 
	{
		/* Terminal Colors
		 * Attribute codes:
		 * 00=none 01=bold 04=underscore 05=blink 07=reverse 08=concealed
		 * Text color codes:
		 * 30=black 31=red 32=green 33=yellow 34=blue 35=magenta 36=cyan 37=white
		 * Background color codes:
		 * 40=black 41=red 42=green 43=yellow 44=blue 45=magenta 46=cyan 47=white 
		 *  
		 * 
		 */
		{"\033[31;1merror\033[0m]",		G_LOG_LEVEL_ERROR},
		{"\033[31;1mcritical\033[0m]", 	G_LOG_LEVEL_CRITICAL},
		{"\033[35;1mwarning\033[0m]", 	G_LOG_LEVEL_WARNING},
		{"\033[33;1mmessage\033[0m]",		G_LOG_LEVEL_MESSAGE},
		{"\033[32;1minfo\033[0m]",		G_LOG_LEVEL_INFO},
		{"\033[36;1mdebug\033[0m]",		G_LOG_LEVEL_DEBUG},
		{ NULL, 0 }
	};

	for ( unsigned int i=0; log_level_mapping[i].name != NULL; i++)
	{
		if ( log_level & log_level_mapping[i].mask )
		{
			level = log_level_mapping[i].name;
			break;
		}
	}

	time_t stamp;
	if ( g_dionaea != NULL && g_dionaea->loop != NULL)
		stamp = ev_now(g_dionaea->loop);
	else
		stamp = time(NULL);

	struct tm t;
	localtime_r(&stamp, &t);
	printf("[%02d%02d%04d %02d:%02d:%02d] %s-%s: %s\n", 
		   t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, t.tm_hour, t.tm_min, t.tm_sec, 
		   log_domain, level, message);
}

bool logger_file_open(void *data)
{
	struct logger_file_data *d = data;
	if ( (d->f = fopen(d->file, "a+")) == NULL)
	{
		g_critical("Could not open logfile %s (%s)", d->file, strerror(errno));
		return false;
	}
	g_debug("LOG OPEN");
	return true;
}

bool logger_file_close(void *data)
{
	g_debug("LOG CLOSE");
	struct logger_file_data *d = data;
	if ( d->f != NULL )
	{
		fclose(d->f);
		d->f = NULL;
	}
	return true;	
}

bool logger_file_hup(void *data)
{
	g_debug("LOG HUP");
	logger_file_close(data);
	logger_file_open(data);
	return true;
}

void logger_file_log(const gchar *log_domain, 
			GLogLevelFlags log_level,
			const gchar *message,
            gpointer user_data)
{
	const char *level = NULL;

	struct logger_file_data *data = user_data;

	if ( data->f == NULL )
		return;

	if ( log_filter_match(data->filter, log_domain, log_level) == false )
		return;

	static struct log_level_map log_level_mapping[] = 
	{
		{"error",		G_LOG_LEVEL_ERROR},
		{"critical", 	G_LOG_LEVEL_CRITICAL},
		{"warning", 	G_LOG_LEVEL_WARNING},
		{"message",		G_LOG_LEVEL_MESSAGE},
		{"info",		G_LOG_LEVEL_INFO},
		{"debug",		G_LOG_LEVEL_DEBUG},
		{ NULL, 0 }
	};

	for ( unsigned int i=0; log_level_mapping[i].name != NULL; i++)
	{
		if ( log_level & log_level_mapping[i].mask )
		{
			level = log_level_mapping[i].name;
			break;
		}
	}

	time_t stamp;
	if ( g_dionaea != NULL && g_dionaea->loop != NULL)
		stamp = ev_now(g_dionaea->loop);
	else
		stamp = time(NULL);

	struct tm t;
	localtime_r(&stamp, &t);
	fprintf(data->f, "[%02d%02d%04d %02d:%02d:%02d] %s-%s: %s\n", 
		   t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, t.tm_hour, t.tm_min, t.tm_sec, 
		   log_domain, level, message);
//	fflush(data->f);
}
