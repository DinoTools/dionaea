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

struct log_level_map
{
	const char *name;
	int mask;
};

struct domain_match
{
	char *domain;
	GPatternSpec *pattern;
};

extern struct log_level_map log_level_mapping[];


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT __FILE__ ":" TOSTRING(__LINE__)

#ifdef G_LOG_DOMAIN
#undef G_LOG_DOMAIN
#ifdef NDEBUG
#define G_LOG_DOMAIN D_LOG_DOMAIN
#else
#define G_LOG_DOMAIN D_LOG_DOMAIN " " AT
#endif /* NDEBUG */
#endif


#define g_info(...) g_log(G_LOG_DOMAIN,	G_LOG_LEVEL_INFO, __VA_ARGS__)

