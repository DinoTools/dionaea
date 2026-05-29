/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009-2011 Markus Koetter
 * SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_MODULES_H
#define HAVE_MODULES_H

#include <stdbool.h>
#include <glib.h>
#include <gmodule.h>

struct dionaea;

struct module;



typedef struct module_api *(*module_init_function)(struct dionaea *d);

typedef bool (*module_config_function)(void);
typedef bool (*module_start_function)(void);
typedef bool (*module_new_function)(struct dionaea *d);
typedef bool (*module_free_function)(void);

/**
 * this is the api to interact with modules
 * startup order is
 *  * config
 *  * prepare
 *  * new
 * after prepare privs are dropped
 *
 * hup is meant to support SIGHUP in modules
 *
 * shutdown order
 *  * free
 */
struct module_api
{
	module_config_function config;
	module_start_function start;
	module_start_function prepare;
	module_new_function new;
	module_free_function free;
	module_config_function hup;
};

struct module
{
	char *name;
	GModule *module;
	module_init_function module_init;
	struct module_api api;
};

struct module *module_new(const char *name, const char *path);
void module_free(struct module *module);


struct modules
{
	GList *modules;
};


void modules_load(gchar **);
void modules_unload(void);

/**
 * module bootstrapping order
 *
 * config: ...
 *
 * prepare: initialize shared memory for pchild (if required)
 *
 * ->fork pchild
 *
 * new: bind & do things
 *
 * drop privs & chroot
 *
 * start: run in your chroot, open db handles
 */



void modules_config(void);
void modules_prepare(void);
void modules_new(void);
void modules_start(void);
void modules_free(void);
void modules_hup(void);

#endif
