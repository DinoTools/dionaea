#ifndef HAVE_MODULES_H
#define HAVE_MODULES_H

#include <stdbool.h>
#include <glib.h>
#include <gmodule.h>

#include <lcfg/lcfg.h>
#include <lcfgx/lcfgx_tree.h>

struct dionaea;

struct module;



typedef struct module_api *(*module_init_function)(struct dionaea *d);

typedef bool (*module_config_function)(struct lcfgx_tree_node *node);
typedef bool (*module_prepare_function)(void);
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
	module_config_function hup;
	module_prepare_function prepare;
	module_new_function new;
	module_free_function free;
};

struct module
{
	char *name;
	GModule *module;
	module_init_function module_init;
	struct lcfgx_tree_node *config;
	struct module_api api;
};

struct module *module_new(const char *name, const char *path);
void module_free(struct module *module);


struct modules
{
	GList *modules;
};


void modules_load(struct lcfgx_tree_node *node);
void modules_unload(void);

void modules_config(void);
void modules_prepare(void);
void modules_new(void);
void modules_free(void);
void modules_hup(void);

#endif
