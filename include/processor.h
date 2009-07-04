#ifndef HAVE_STREAMPROCESSOR_H
#define HAVE_STREAMPROCESSOR_H

#include <stdbool.h>

#include "bistream.h"

struct connection;
struct lcfgx_tree_node;

struct processors
{
	GNode *tree;
	GHashTable *names;
};


enum processor_state 
{ 
	processor_done, 
	processor_continue 
};

struct processor_data;


typedef void *(*processor_cfg_new)(struct lcfgx_tree_node *node);
typedef bool (*processor_process)(struct connection *con, void *config);
typedef void *(*processor_ctx_new)(void *cfg);
typedef void (*processor_ctx_free)(void *ctx);
typedef void (*processor_on_close)(struct connection *con, struct processor_data *pd);
typedef void (*processor_on_io)(struct connection *con, struct processor_data *pd);

struct processor
{
	const char *name;
	processor_cfg_new cfg;
	processor_process process;	
	processor_ctx_new new;	
	processor_ctx_free free;
	processor_on_io on_io_in;
	processor_on_io on_io_out;
	void *config;
};


struct processor_data
{
	enum processor_state state;
	GMutex *mutex;
	struct processor *processor;
	void *ctx;
	struct bistream *bistream;

	GList *filters; // of type struct stream_processor_data
};

bool processors_tree_create(GNode *tree, struct lcfgx_tree_node *node);
void processors_tree_dump(GNode *tree, int indent);

void processors_init(struct connection *con);
void processors_clear(struct connection *con);

void processors_io_out(struct connection *con, void *data, int size);
void processors_io_in(struct connection *con, void *data, int size);
struct processor_data *processor_data_new(void);
void processor_data_free(struct processor_data *pd);

#endif
