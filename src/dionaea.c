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

#include <ev.h>
#include <udns.h>
#include <openssl/ssl.h>

#include "config.h"

#ifdef HAVE_LIBGC
	#include <gc.h>
#endif

#include "config.h"
#include "dionaea.h"
#include "dns.h"
#include "modules.h"
#include "log.h"
#include "pchild.h"
#include "signals.h"
#include "incident.h"
#include "threads.h"
#include "processor.h"

void show_version(void);
void show_help(bool defaults);

#define D_LOG_DOMAIN "dionaea"


struct dionaea *g_dionaea = NULL;

extern struct processor proc_filter;
extern struct processor proc_unicode;
extern struct processor proc_emu;
extern struct processor proc_cspm;
extern struct processor proc_streamdumper;



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
	char *garbage;

	struct
	{
		char *levels;
		char *domains;
		struct log_filter *filter;
	}stdout;

	char *pidfile;
};


bool options_parse(struct options* options, int argc, char* argv[])
{
	while( 1 )
	{
		int option_index = 0;
		static struct option long_options[] = {
			{ "config",         1, 0, 'c'},
			{ "daemonize",      1, 0, 'D'},
			{ "group",          1, 0, 'g'},
			{ "garbage",        1, 0, 'G'},
			{ "help",           0, 0, 'h'},
			{ "large-help",     0, 0, 'H'},
			{ "log-levels",     0, 0, 'l'},
			{ "log-domains",    0, 0, 'L'},
			{ "user",           1, 0, 'u'},
			{ "chroot",         1, 0, 'r'},
			{ "pid-file",       1, 0, 'p'},
			{ "version",        0, 0, 'V'},
			{ "workingdir",     0, 0, 'w'},
			{ 0, 0, 0, 0}
		};

		int c = getopt_long(argc, argv, "c:Dg:G:hHl:L:p:r:u:Vw:", long_options, (int *)&option_index);
		if( c == -1 )
			break;

		switch( c )
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

#ifdef HAVE_LIBGC
		case 'G':
			options->garbage = g_strdup(optarg);
			break;
#endif

		case 'h':
			show_help(false);
			exit(0);
			break;

		case 'H':
			show_help(true);
			exit(0);
			break;

		case 'l':
			options->stdout.levels = g_strdup(optarg);
			break;

		case 'L':
			options->stdout.domains = g_strdup(optarg);
			break;


		case 'p':
			options->pidfile = g_strdup(optarg);
			break;

		case 'r':
			options->root = g_strdup(optarg);
			break;

		case 'u':
			options->user.name = g_strdup(optarg);
			break;

		case 'V':
			show_version();
			exit(0);
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

	if( options->config == NULL )
		options->config = strdup(SYSCONFDIR"/dionaea/dionaea.conf");

	if( options->workingdir == NULL )
		options->workingdir = g_strdup(PREFIX);

	return true;
}

bool options_validate(struct options *opt)
{
	if( opt->user.name != NULL )
	{

		struct passwd *pass;                                

		if( isdigit(*opt->user.name) != 0 )
		{
			opt->user.id = atoi(opt->user.name);
			g_debug("User %s has uid %i\n",opt->user.name,opt->user.id);
		} else
			if( (pass = getpwnam(opt->user.name)) == NULL )
		{
			g_warning("Could not get id for user '%s'\n", opt->user.name);
			return false;
		} else
		{
			g_debug("User %s has uid %i\n",opt->user.name,pass->pw_uid);
			opt->user.id = pass->pw_uid;
		}
	}

	if( opt->group.name != NULL )
	{
		struct group *grp;
		if( isdigit(*opt->group.name) != 0 )
		{
			opt->group.id = atoi(opt->group.name);
			g_debug("Group %s has gid %i\n", opt->group.name, opt->group.id);
		} else
			if( (grp = getgrnam(opt->group.name)) == NULL )
		{
			g_warning("Could not get id for group '%s'\n",opt->group.name);
			return false;
		} else
		{
			g_debug("Group %s has gid %i\n",opt->group.name, grp->gr_gid);
			opt->group.id = grp->gr_gid;
		}
	}

	if( opt->garbage != NULL )
	{
		if( strcmp(opt->garbage, "collect" ) != 0 && strcmp(opt->garbage, "debug" ) != 0 )
		{
			g_error("Invalid garbage mode %s\n", opt->garbage);
			return false;
		}
	}

	opt->stdout.filter = log_filter_new(opt->stdout.domains, opt->stdout.levels);
	if( opt->stdout.filter == NULL )
		return false;

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
	#define MY_OS "FreeBSD"
#elif defined(linux) || defined (__linux)
	#define MY_OS "Linux"
#elif defined (__MACOSX__) || defined (__APPLE__)
	#define MY_OS "Mac OS X"
#elif defined(__NetBSD__)
	#define MY_OS "NetBSD"
#elif defined(__OpenBSD__)
	#define MY_OS "OpenBSD"
#elif defined(_WIN32) || defined(__WIN32__) || defined(__TOS_WIN__)
	#define MY_OS "Windows"
#elif defined(CYGWIN)
	#define MY_OS "Cygwin\Windows"
#else
	#define MY_OS "Unknown OS"
#endif


#if defined(__alpha__) || defined(__alpha) || defined(_M_ALPHA)
	#define MY_ARCH "Alpha"
#elif defined(__arm__)
	#if defined(__ARMEB__)
		#define MY_ARCH "ARMeb"
	#else 
		#define MY_ARCH "ARM"
	#endif 
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86) || defined(_X86_) || defined(__THW_INTEL)
	#define MY_ARCH "x86"
#elif defined(__x86_64__) || defined(__amd64__)
	#define MY_ARCH "x86_64"
#elif defined(__ia64__) || defined(_IA64) || defined(__IA64__) || defined(_M_IA64)
	#define MY_ARCH "Intel Architecture-64"
#elif defined(__mips__) || defined(__mips) || defined(__MIPS__)
	#if defined(__mips32__) || defined(__mips32)
		#define MY_ARCH "MIPS32"
	#else 
		#define MY_ARCH "MIPS"
	#endif 
#elif defined(__hppa__) || defined(__hppa)
	#define MY_ARCH "PA RISC"
#elif defined(__powerpc) || defined(__powerpc__) || defined(__POWERPC__) || defined(__ppc__) || defined(_M_PPC) || defined(__PPC) || defined(__PPC__)
	#define MY_ARCH "PowerPC"
#elif defined(__THW_RS6000) || defined(_IBMR2) || defined(_POWER) || defined(_ARCH_PWR) || defined(_ARCH_PWR2)
	#define MY_ARCH "RS/6000"
#elif defined(__sparc__) || defined(sparc) || defined(__sparc)
	#define MY_ARCH "SPARC"
#else
	#define MY_ARCH "Unknown Architecture"
#endif

	struct utsname sysinfo;
	int i = uname(&sysinfo);

	printf("\n");
	printf("Dionaea Version %s \n",VERSION);
	printf("Compiled on %s/%s at %s %s with %s %s \n",MY_OS,MY_ARCH,__DATE__, __TIME__,MY_COMPILER,__VERSION__);

	if( i == 0 )
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
		{"c",   "config=FILE",          "use FILE as configuration file",               SYSCONFDIR "/dionaea.conf"},
		{"D",   "daemonize",            "run as daemon",                        0},
		{"g",   "group=GROUP",          "switch to GROUP after startup (use with -u)", "keep current group"},
#ifdef HAVE_LIBGC
		{"G",   "garbage=[collect|debug]","garbage collect,  usefull to debug memory leaks, does NOT work with valgrind",   0},  
#endif
		{"h",   "help",                 "display help",                         0},
		{"H",   "large-help",           "display help with default values",     0},
		{"l",   "log-levels=WHAT",      "which levels to log, valid values all, debug, info, message, warning, critical, error, combine using ',', exclude with - prefix",  0},
		{"L",   "log-domains=WHAT",     "which domains use * and ? wildcards, combine using ',', exclude using -",  0},
		{"u",   "user=USER",            "switch to USER after startup", "keep current user"},
		{"p",   "pid-file=FILE",        "write pid to file",    0},
		{"r",   "chroot=DIR",           "chroot to DIR after startup, warning: chrooting causes problems with logsql/sqlite",              "don't chroot"},
		{"V",   "version",              "show version",                         ""},
		{"w",   "workingdir=DIR",       "set the process' working dir to DIR",          PREFIX},
	};
	show_version();

	for( int i=0;i<sizeof(myopts)/sizeof(help_info);i++ )
	{
		printf("  -%s, --%-25s %s\n", myopts[i].info,
			   myopts[i].verbose,
			   myopts[i].description);

		if( defaults == true && myopts[i].standard )
		{
			printf("%-35s Default value/behaviour: %s\n", "", myopts[i].standard);
		}
	}
	puts("\n\nexamples:\n"
		 "\t# dionaea -l all,-debug -L '*'\n"
		 "\t# dionaea -l all,-debug -L 'con*,py*'\n"
		 "\t# dionaea -u nobody -g nogroup -w /opt/dionaea -p /opt/dionaea/var/run/dionaea.pid\n");

}

static void log_ev_fatal_error (const char *msg)
{
	g_error("%s",msg);
}


int main (int argc, char *argv[])
{
	show_version();
	g_log_set_default_handler(logger_stdout_log, NULL);

	struct options *opt = malloc(sizeof(struct options));
	memset(opt, 0, sizeof(struct options));

	if( options_parse(opt, argc, argv) == false )
	{
		g_error("Could not parse options!\n");
	}

	if( options_validate(opt) == false )
	{
		g_error("Invalid options");
	}

	g_log_set_default_handler(logger_stdout_log, opt->stdout.filter);
	// gc
	if( opt->garbage != NULL )
	{
#ifdef HAVE_LIBGC
		g_message("gc mode %s", opt->garbage);
		if( g_mem_gc_friendly != TRUE )
		{
			g_error("export G_DEBUG=gc-friendly\nexport G_SLICE=always-malloc\n for gc");
		}


		static GMemVTable memory_vtable =
		{
			.malloc = GC_malloc,
			.realloc = GC_realloc,
			.free   = GC_free,
		};

		g_mem_set_vtable(&memory_vtable);
		if( strcmp(opt->garbage, "debug") == 0 )
			GC_find_leak = 1;

		// set libev allocator
		typedef void *(*moron)(void *ptr, long size);
		ev_set_allocator((moron)GC_realloc);
#endif
	}

	if( opt->workingdir != NULL && chdir(opt->workingdir) != 0 )
	{
		g_error("Invalid directory %s (%s)", opt->workingdir, strerror(errno));
	}

	struct dionaea *d = g_malloc0(sizeof(struct dionaea));
	g_dionaea = d;

	// config
	if( (d->config.config = lcfg_new(opt->config)) == NULL )
	{
		g_error("config not found");
	}

	if( lcfg_parse(d->config.config) != lcfg_status_ok )
	{
		g_error("lcfg error: %s\n", lcfg_error_get(d->config.config));
	}

	d->config.root = lcfgx_tree_new(d->config.config);
	d->config.name = g_strdup(opt->config);

	// logging 
	d->logging = g_malloc0(sizeof(struct logging));


	// no daemon logs to stdout by default
	if( opt->daemon == false )
	{
		struct logger *l = logger_new(logger_stdout_log, NULL, NULL, NULL, NULL, opt->stdout.filter);
		logger_stdout_open(l, NULL);
		d->logging->loggers = g_list_append(d->logging->loggers, l);
	}

	// log to file(s) - if specified in config
	struct lcfgx_tree_node *n;
	if( lcfgx_get_map(g_dionaea->config.root, &n, "logging") == LCFGX_PATH_FOUND_TYPE_OK )
	{
		struct lcfgx_tree_node *it;
		for( it = n->value.elements; it != NULL; it = it->next )
		{
			if( it->type != lcfgx_map )
				continue;

			char *alias = it->key;
			char *file = NULL;
			char *domains = NULL;
			char *levels = NULL;

			struct lcfgx_tree_node *f;

			if( lcfgx_get_string(it, &f, "file") == LCFGX_PATH_FOUND_TYPE_OK )
				file = f->value.string.data;

			if( lcfgx_get_string(it, &f, "domains") == LCFGX_PATH_FOUND_TYPE_OK )
				domains = f->value.string.data;

			if( lcfgx_get_string(it, &f, "levels") == LCFGX_PATH_FOUND_TYPE_OK )
				levels = f->value.string.data;

			g_debug("Logfile (handle %s) %s %s %s", alias, file, domains, levels);

			if( file == NULL )
				continue;

			struct log_filter *lf = log_filter_new(domains, levels);
			if( lf == NULL )
				return -1;

			struct logger_file_data *fd = g_malloc0(sizeof(struct logger_file_data));
			if( *file != '/' )
			{
				fd->file = g_malloc0(PATH_MAX+1);
				g_snprintf(fd->file, PATH_MAX, "%s/%s", LOCALESTATEDIR, file);
			} else
				fd->file = g_strdup(file);

			fd->filter = lf;

			struct logger *l = logger_new(logger_file_log, logger_file_open, logger_file_hup, logger_file_close, logger_file_flush, fd);
			d->logging->loggers = g_list_append(d->logging->loggers, l);
		}
	}

	for( GList *it = d->logging->loggers; it != NULL; it = it->next )
	{
		struct logger *l = it->data;
		if( l->open != NULL )
			l->open(l, l->data);
	}

	// daemon
	if( opt->daemon && daemon(1, 0) != 0 )
	{
		g_error("Could not daemonize (%s)", strerror(errno));
	}

	// pidfile
	if( opt->pidfile != NULL )
	{
		FILE *p = fopen(opt->pidfile,"w+");
		if( p == NULL )
		{
			g_error("Could not write pid file to %s", opt->pidfile);
		}
		char pidstr[16];
		int len = snprintf(pidstr, 15, "%i", getpid());
		fwrite(pidstr, len, 1, p);
		fclose(p);
	}
	g_message("glib version %i.%i.%i", glib_major_version, glib_minor_version, glib_micro_version);

	// libev
	d->loop = ev_default_loop(0);
	g_message("libev api version is %i.%i", ev_version_major(), ev_version_minor());
	{
		int b = ev_backend(d->loop);

		const char *backend[] = 
		{
			"select",
			"poll",
			"epoll",
			"kqueue",
			"devpoll",
			"port"
		};
		for( int i=0; i<sizeof(backend)/sizeof(const char *); i++ )
			if( b == 1 << i )
				g_message("libev backend is %s", backend[i]);
	}
	ev_set_syserr_cb(log_ev_fatal_error);
	g_message("libev default loop %p\n", d->loop);

	// ssl
	SSL_load_error_strings();
	SSL_library_init();
	SSL_COMP_add_compression_method(0xe0, COMP_zlib());
	g_message("%s", SSLeay_version(SSLEAY_VERSION));


	// udns 
	d->dns = g_malloc0(sizeof(struct dns));
	dns_init(NULL , 0);
	d->dns->dns = dns_new(NULL);
	dns_init(d->dns->dns, 0);
	dns_set_tmcbck(d->dns->dns, udns_set_timeout_cb, g_dionaea->loop);
	d->dns->socket = dns_open(g_dionaea->dns->dns);
	ev_io_init(&d->dns->io_in, udns_io_in_cb, d->dns->socket, EV_READ);
	ev_io_start(g_dionaea->loop, &d->dns->io_in);
	ev_timer_init(&d->dns->dns_timeout, udns_timeout_cb, 0., 0.);
	g_message("udns version %s",  UDNS_VERSION);


	// glib thread init
	if( !g_thread_supported () )
		g_thread_init (NULL);

	// logging continued ...
	d->logging->lock = g_mutex_new();

	// incident handlers
	d->ihandlers = g_malloc0(sizeof(struct ihandlers));

	// processors
	d->processors = g_malloc0(sizeof(struct processors));
	d->processors->names = g_hash_table_new(g_str_hash, g_str_equal);



	// modules
	d->modules = g_malloc0(sizeof(struct modules));
//	struct lcfgx_tree_node *n;
	if( lcfgx_get_map(g_dionaea->config.root, &n, "modules") == LCFGX_PATH_FOUND_TYPE_OK )
		modules_load(n);
	else
		g_warning("dionaea is useless without modules");

	modules_config();
	modules_prepare();

	// privileged child
	d->pchild = pchild_new();
	if( pchild_init() == false )
	{
		g_error("Could not init privileged child!");
	}

	// maybe a little late, but want to avoid having dups of the fd in the child
	g_log_set_default_handler(log_multiplexer, NULL);

	// processors continued, create tree
	g_hash_table_insert(d->processors->names, (void *)proc_streamdumper.name, &proc_streamdumper);
//	g_hash_table_insert(d->processors->names, (void *)proc_emu.name, &proc_emu);
	g_hash_table_insert(d->processors->names, (void *)proc_filter.name, &proc_filter);
	g_hash_table_insert(d->processors->names, (void *)proc_unicode.name, &proc_unicode);
//	struct lcfgx_tree_node *n;
	g_debug("Creating processors tree");
	d->processors->tree = g_node_new(NULL);
	if( lcfgx_get_map(d->config.root, &n, "processors") == LCFGX_PATH_FOUND_TYPE_OK )
	{
		lcfgx_tree_dump(n,0);
		for( struct lcfgx_tree_node *it = n->value.elements; it != NULL; it = it->next )
		{
			processors_tree_create(d->processors->tree, it);
		}
	}

	processors_tree_dump(d->processors->tree, 0);


	modules_new();


	// threads ...
	d->threads = g_malloc0(sizeof(struct threads));

	// cmd queue
	d->threads->cmds = g_async_queue_new();
	ev_async_init(&d->threads->trigger, trigger_cb);
	ev_async_start(d->loop, &d->threads->trigger);

	// chroot
	if( opt->root != NULL && chroot(opt->root) != 0 )
	{
		g_error("Could not chroot(\"%s\") (%s)", opt->root, strerror(errno));
	}

	// umask
	mode_t newu = S_IWGRP | S_IWOTH;
	mode_t oldu = umask(newu);

#define print_umask(str, x)\
	g_debug("%s -%s%s%s%s%s%s%s%s%s", str, \
				   x & S_IRUSR ? "r" : "-",\
				   x & S_IWUSR ? "w" : "-",\
				   x & S_IXUSR ? "x" : "-",\
				   x & S_IRGRP ? "r" : "-",\
				   x & S_IWGRP ? "w" : "-",\
				   x & S_IXGRP ? "x" : "-",\
				   x & S_IROTH ? "r" : "-",\
				   x & S_IWOTH ? "w" : "-",\
				   x & S_IXOTH ? "x" : "-")
	   
	print_umask("old umask", oldu);
	print_umask("new umask", newu);
#undef print_umask



	// drop
	if( opt->group.name != NULL && 
		setresgid(opt->group.id, opt->group.id, opt->group.id) < 0 )
	{
		g_error("Could not change group");
	}

	if( opt->user.name != NULL && 
		setresuid(opt->user.id, opt->user.id, opt->user.id) < 0 )
	{
		g_error("Could not change user");
	}

	g_info("Installing signal handlers");
	// signals
	d->signals = g_malloc0(sizeof(struct signals));
	ev_signal_init(&d->signals->sigint,  sigint_cb, SIGINT);
	ev_signal_start(d->loop, &d->signals->sigint);

	ev_signal_init(&d->signals->sighup,  sighup_cb, SIGHUP);
	ev_signal_start(d->loop, &d->signals->sighup);
	signal(SIGSEGV, sigsegv_backtrace_cb);

	/* 
	 * SIGPIPE 
	 *  
	 * Preventing the signal is hard.
	 * From what I know, sigpipe can be raised issued by write/send
	 * read/write, maybe even accept?, I do not know. 
	 *  
	 * Linux provides send(MSG_NOSIGNAL), 
	 * Freebsd requires a setsockopt(SO_NOSIGPIPE) 
	 * some documentation list MSG_NOSIGNAL as flag for recv too 
	 * Therefore, to make things easy, we simply ignore SIGPIPE 
	 * Given the alternatives I consider ignoring the best option
	 */
	signal(SIGPIPE, SIG_IGN);

//	ev_signal_init(&d->signals->sigsegv,  sigsegv_cb, SIGSEGV);
//	ev_signal_start(d->loop, &d->signals->sigsegv);
//	signal(SIGSEGV, (sighandler_t) segv_handler);
//	signal(SIGBUS, (sighandler_t) segv_handler);

	// thread pool
	int threads = sysconf(_SC_NPROCESSORS_ONLN);
	threads = (threads <= 1?2:threads);
	GError *thread_error = NULL;
	g_message("Creating %i threads in pool", threads);
	d->threads->pool = g_thread_pool_new(threadpool_wrapper, NULL, threads, TRUE, &thread_error);

	if( thread_error != NULL )
	{
		g_error("Could not create thread pool (%s)",  thread_error->message);
	}

	// periodic thread pool surveillance
	ev_periodic_init(&d->threads->surveillance, surveillance_cb, 0., 5., NULL);
	ev_periodic_start(d->loop, &d->threads->surveillance);


	// loop	
	g_debug("looping");
	ev_loop(d->loop,0);

	// delete thread pool
	g_debug("Closing thread pool (%i active threads, %i jobs in queue), be patient",
			g_thread_pool_get_num_threads(g_dionaea->threads->pool),
			g_thread_pool_unprocessed(g_dionaea->threads->pool));
	g_thread_pool_free(d->threads->pool, FALSE, TRUE);

	// modules api.free
	g_debug("modules free");
	modules_free();

	// module unload
	g_debug("modules unload");
	modules_unload();

	// kill privileged child
	g_debug("Closing child");
	close(d->pchild->fd);

	// close logs
	g_debug("Closing logs");
	for( GList *it = d->logging->loggers; it != NULL; it = it->next )
	{
		struct logger *l = it->data;
		if( l->close != NULL )
			l->close(l, l->data);
	}

	return 0;
}
