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

#define _XOPEN_SOURCE
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#include <getopt.h>
#include <glib.h>
#include <sys/utsname.h>
#include <stdio.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <ctype.h>

#include <lcfg/lcfg.h>
#include <lcfgx/lcfgx_tree.h>


#include "dionaea.h"
#include "config.h"

void show_version(void);
void show_help(bool defaults);

#ifdef G_LOG_DOMAIN
#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "dionaea"
#endif


struct options
{
	gchar *root;
	struct
	{
		gchar *name;
		uid_t id;
	}user;
	struct
	{
		gchar *name;
		gid_t id;
	}group;
	gchar *workingdir;
	gchar *config;
	bool daemon;

};


bool options_parse(struct options* options, int argc, char* argv[])
{
	while( 1 )
	{
		int option_index = 0;
		static struct option long_options[] = {
			{ "help", 			0, 0, 'h' },
			{ 0, 0, 0, 0 }
		};

		int c = getopt_long(argc, argv, "c:Dg:hHr:u:Vw:", long_options, (int *)&option_index);
		if (c == -1)
			break;

		switch (c)
		{
		case 'c':
			options->config = g_strdup(optarg);
			break;

		case 'D':
			options->daemon = true;	
            break;

		case 'g':
			options->group.name = g_strdup(optarg);
            break;

		case 'h':
			show_help(false);
			return false;
			break;

		case 'H':
			show_help(true);
			return false;
			break;

		case 'r':
			options->root = g_strdup(optarg);
			break;

		case 'u':
			options->user.name = g_strdup(optarg);
			break;

		case 'V':
			show_version();
			return false;
			break;

		case 'w':
			options->workingdir = g_strdup(optarg);
			break;

		case '?':
		case ':':
			return false;
			break;

		default:
			break;
		}
	}

	if ( options->config == NULL )
		options->config = g_strdup(PREFIX"/etc/dionaea/dionaea.conf");

	return true;
}

bool options_validate(struct options *opt)
{
	if ( opt->user.name != NULL )
	{

		struct passwd *pass;                                

		if (isdigit(*opt->user.name) != 0)
		{
			opt->user.id = atoi(opt->user.name);
			g_debug("User %s has uid %i\n",opt->user.name,opt->user.id);
		}else
		if ( (pass = getpwnam(opt->user.name)) == NULL )
		{
			g_warning("Could not get id for user '%s'\n", opt->user.name);
			return false;
		}else
		{
			g_debug("User %s has uid %i\n",opt->user.name,pass->pw_uid);
			opt->user.id = pass->pw_uid;
		}
	}

	if ( opt->group.name != NULL )
	{
		struct group *grp;
		if (isdigit(*opt->group.name) != 0)
		{
			opt->group.id = atoi(opt->group.name);
			g_debug("Group %s has gid %i\n", opt->group.name, opt->group.id);
		}else
		if ( (grp = getgrnam(opt->group.name)) == NULL )
		{
			g_warning("Could not get id for group '%s'\n",opt->group.name);
			return false;
		}else
		{
			g_debug("Group %s has gid %i\n",opt->group.name, grp->gr_gid);
			opt->group.id = grp->gr_gid;
		}
	}

	return true;
}

void show_version(void)
{

#if defined(__GNUC__)
	#define MY_COMPILER "gcc"
#elif defined(__CYGWIN__)
	#define MY_COMPILER "cygwin"
#else	
	#define MY_COMPILER "unknown Compiler"
#endif


#if defined(__FreeBSD__)
#  define MY_OS "FreeBSD"
#elif defined(linux) || defined (__linux)
#  define MY_OS "Linux"
#elif defined (__MACOSX__) || defined (__APPLE__)
#  define MY_OS "Mac OS X"
#elif defined(__NetBSD__)
#  define MY_OS "NetBSD"
#elif defined(__OpenBSD__)
#  define MY_OS "OpenBSD"
#elif defined(_WIN32) || defined(__WIN32__) || defined(__TOS_WIN__)
#  define MY_OS "Windows"
#elif defined(CYGWIN)
#  define MY_OS "Cygwin\Windows"
#else
#  define MY_OS "Unknown OS"
#endif


#if defined(__alpha__) || defined(__alpha) || defined(_M_ALPHA)
#  define MY_ARCH "Alpha"
#elif defined(__arm__)
#  if defined(__ARMEB__)
#    define MY_ARCH "ARMeb"
#  else 
#    define MY_ARCH "ARM"
#  endif 
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86) || defined(_X86_) || defined(__THW_INTEL)
#  define MY_ARCH "x86"
#elif defined(__x86_64__) || defined(__amd64__)
#  define MY_ARCH "x86_64"
#elif defined(__ia64__) || defined(_IA64) || defined(__IA64__) || defined(_M_IA64)
#  define MY_ARCH "Intel Architecture-64"
#elif defined(__mips__) || defined(__mips) || defined(__MIPS__)
#  if defined(__mips32__) || defined(__mips32)
#    define MY_ARCH "MIPS32"
#  else 
#    define MY_ARCH "MIPS"
#  endif 
#elif defined(__hppa__) || defined(__hppa)
#  define MY_ARCH "PA RISC"
#elif defined(__powerpc) || defined(__powerpc__) || defined(__POWERPC__) || defined(__ppc__) || defined(_M_PPC) || defined(__PPC) || defined(__PPC__)
#  define MY_ARCH "PowerPC"
#elif defined(__THW_RS6000) || defined(_IBMR2) || defined(_POWER) || defined(_ARCH_PWR) || defined(_ARCH_PWR2)
#  define MY_ARCH "RS/6000"
#elif defined(__sparc__) || defined(sparc) || defined(__sparc)
#  define MY_ARCH "SPARC"
#else
#  define MY_ARCH "Unknown Architecture"
#endif

	struct utsname sysinfo;
	int i = uname(&sysinfo);

	printf("\n");
	printf("Dionaea Version %s \n",VERSION);
	printf("Compiled on %s/%s at %s %s with %s %s \n",MY_OS,MY_ARCH,__DATE__, __TIME__,MY_COMPILER,__VERSION__);

	if (i == 0)
	{
		printf("Started on %s running %s/%s release %s\n",
			   sysinfo.nodename,
			   sysinfo.sysname, 
			   sysinfo.machine,
			   sysinfo.release
			   );
	}

	printf("\n");
#undef MY_OS
#undef MY_ARCH
#undef MY_COMPILER
}

void show_help(bool defaults)
{
	typedef struct 
	{
		const char *info;
		const char *verbose;
        const char *description;
		const char *standard;
	} help_info;

	help_info myopts[]=
	{
        {"c",	"config=FILE",		"use FILE as configuration file",				SYSCONFDIR "/nepenthes.conf"	},
		{"D",	"daemonize",		"run as daemon",						0						},
		{"h",	"help",				"display help",							0						},
		{"H",	"large-help",		"display help with default values",		0						},
        {"r",	"chroot=DIR",		"chroot to DIR after startup",				"don't chroot"		},
		{"u",	"user=USER",				"switch to USER after startup",	"keep current opt->user.name"},
		{"g",	"group=GROUP",			"switch to GROUP after startup (use with -u)", "keep current group"},
		{"V",	"version",			"show version",							""						},
		{"w",	"workingdir=DIR",		"set the process' working dir to DIR",			PREFIX		},
	};
	show_version();

	for ( int i=0;i<sizeof(myopts)/sizeof(help_info);i++ )
	{
		printf("  -%s, --%-19s %s\n", myopts[i].info,
			myopts[i].verbose,
			myopts[i].description);
		
		if( defaults == true && myopts[i].standard )
		{
			printf("                              Default value/behaviour: %s\n", myopts[i].standard);
		}
	}
}

void stdout_logger(const gchar *log_domain, 
			GLogLevelFlags log_level,
			const gchar *message,
            gpointer user_data)
{

	char *level = NULL;
	if ( log_level &  G_LOG_LEVEL_ERROR)
		level = "error";
	else
	if ( log_level &  G_LOG_LEVEL_CRITICAL)
		level = "critical";
	else
	if ( log_level &  G_LOG_LEVEL_WARNING)
		level = "warning";
	else
	if ( log_level &  G_LOG_LEVEL_MESSAGE)
		level = "message";
	else
	if ( log_level &  G_LOG_LEVEL_INFO)
		level = "info";
	else
	if ( log_level &  G_LOG_LEVEL_DEBUG)
		level = "debug";


	printf("%s-%s: %s", level, log_domain, message);
}


int main (int argc, char *argv[])
{
	g_log_set_default_handler(stdout_logger, NULL);

	struct options *opt = g_malloc0(sizeof(struct options));

	if ( options_parse(opt, argc, argv) == false)
		return 1;

	if ( opt->workingdir != NULL && chdir(opt->workingdir) != 0)
		g_error("Invalid directory %s (%s)", opt->workingdir, strerror(errno));


	if ( options_validate(opt) == false )
		g_error("Invalid options");

	struct dionaea *d = g_malloc0(sizeof(struct dionaea));

	// config
	if ( (d->config.config = lcfg_new(opt->config)) == NULL)
		g_error("config not found");

	if( lcfg_parse(d->config.config) != lcfg_status_ok )
		g_error("lcfg error: %s\n", lcfg_error_get(d->config.config));

	d->config.root = lcfgx_tree_new(d->config.config);

	// daemon
	if ( opt->daemon &&	
		 daemon(1, 0) != 0)
		g_error("Could not daemonize (%s)", strerror(errno));

	// libev


	// privileged child


	// udns 
	
		
	// glib threadpool


	// modules


	// chroot
	if ( opt->root != NULL && chroot(opt->root) != 0 )
		g_error("Could not chroot(\"%s\") (%s)", opt->root, strerror(errno));

	// drop
	if ( opt->group.name != NULL && 
		 setresgid(opt->group.id, opt->group.id, opt->group.id) < 0)
		g_error("Could not change group");

	if ( opt->user.name != NULL && 
		 setresuid(opt->user.id, opt->user.id, opt->user.id) < 0)
		g_error("Could not change user");


	// signals


	// loop


	// kill privileged child

	return 0;
}


