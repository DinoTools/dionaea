#include <lcfg/lcfg.h>
#include <lcfgx/lcfgx_tree.h>


#include "dionaea.h"
#include "connection.h"
#include "processor.h"
#include "threads.h"


bool processors_tree_create(GNode *tree, struct lcfgx_tree_node *node)
{
	g_debug("%s tree %p node %p key %s", __PRETTY_FUNCTION__, tree, node, node->key);
	struct processor *p = g_hash_table_lookup(g_dionaea->processors->names, node->key);

	if( p == NULL )
	{
		g_critical("Could not find processor %s", node->key);
		return false;
	}

	struct processor *pt = g_malloc0(sizeof(struct processor));
	memcpy(pt, p, sizeof(struct processor));

	struct lcfgx_tree_node *n;
	if( lcfgx_get_map(node, &n, "config") == LCFGX_PATH_FOUND_TYPE_OK )
	{
/*		if( pt->cfg == NULL )
		{
			return false;
		}
		pt->config = pt->cfg(n);
*/
	}

	GNode *me = g_node_new(pt);
	g_node_append(tree, me);

	if( lcfgx_get_map(node, &n, "next") == LCFGX_PATH_FOUND_TYPE_OK )
	{
		struct lcfgx_tree_node *it;
		for( it = n->value.elements; it != NULL; it = it->next )
		{
			if ( processors_tree_create(me, it) != true)
				return false;
		}
	}
	return true;
}

void processors_tree_dump(GNode *tree, int indent)
{
	for(GNode *it = g_node_first_sibling(tree); it != NULL; it = it->next)
	{
		if( it->data )
		{
			struct processor *p = it->data;
			char fmt[256];
			snprintf(fmt, 255, "%%-%is %%s %%i",indent);
			g_debug("%*s %s", indent, " ", p->name);
		}

		if( it->children )
			processors_tree_dump(g_node_first_child(it), indent+1);
	}
}

void processor_data_creation(struct connection *con, struct processor_data *pd, GNode *node)
{
	g_debug("%s con %p pd %p node %p", __PRETTY_FUNCTION__, con, pd, node);
	struct processor *p = node->data;


	if( p->process && !p->process(con, p->config) )
		return;

	g_debug("creating %s", p->name);
	struct processor_data *npd = processor_data_new();
	npd->processor = p;
	npd->ctx = npd->processor->new(p->config);
	pd->filters = g_list_append(pd->filters, npd);

	GNode *it;
	for( it = node->children; it != NULL; it = it->next )
	{
		processor_data_creation(con, npd, it);
	}
}

void processor_data_deletion(struct processor_data *pd)
{
	printf("%s con %p\n", __PRETTY_FUNCTION__, pd);
	GList *it;
	while ( (it = g_list_first(pd->filters)) != NULL)
	{
		struct processor_data *proc_data = it->data;
		processor_data_deletion(proc_data);
		pd->filters = g_list_delete_link(pd->filters, it);
	}
	pd->processor->free(pd->ctx);
	processor_data_free(pd);
}

void processors_init(struct connection *con)
{
	g_debug("%s con %p\n", __PRETTY_FUNCTION__, con);
	con->processor_data = processor_data_new();
	for(GNode *it = g_node_first_sibling(g_dionaea->processors->tree->children); 
		 it != NULL; 
		 it = it->next)
	{
		processor_data_creation(con, con->processor_data, it);
	}
}


void processors_clear(struct connection *con)
{
	printf("%s con %p\n", __PRETTY_FUNCTION__, con);

	GList *it;
	while ( (it = g_list_first(con->processor_data->filters)) != NULL)
	{
		struct processor_data *proc_data = it->data;
		processor_data_deletion(proc_data);
		con->processor_data->filters = g_list_delete_link(con->processor_data->filters, it);
	}
	processor_data_free(con->processor_data);
	con->processor_data = NULL;
		
}

struct processor_data *processor_data_new(void)
{
	struct processor_data *pd = g_malloc0(sizeof(struct processor_data));
	pd->mutex = g_mutex_new();
	pd->state = processor_continue;
	pd->processor = NULL;
	pd->filters = NULL;
	pd->bistream = bistream_new();
	return pd;
}

void processor_data_free(struct processor_data *pd)
{
	bistream_free(pd->bistream);
	g_mutex_free(pd->mutex);
	g_free(pd);
}

void recurse_io(GList *list, struct connection *con, enum bistream_direction dir)
{
	GList *it;
	for ( it = g_list_first(list); it != NULL; it = g_list_next(it) )
	{
		struct processor_data *proc_data = it->data;
		if( dir == bistream_in )
			proc_data->processor->on_io_in(con, proc_data);
		else
			proc_data->processor->on_io_out(con, proc_data);
		recurse_io(proc_data->filters, con, dir);
	}
}

void processors_io_in_thread(void *data, void *userdata)
{
	printf("%s data %p userdata %p\n", __PRETTY_FUNCTION__, data,  userdata);
 	struct connection *con = data;
	g_mutex_lock(con->processor_data->mutex);
	recurse_io(con->processor_data->filters, con, bistream_in);
	g_mutex_unlock(con->processor_data->mutex);
	connection_unref(con);
}

void processors_io_out_thread(void *data, void *userdata)
{
	printf("%s data %p userdata %p\n", __PRETTY_FUNCTION__, data,  userdata);
 	struct connection *con = data;
	g_mutex_lock(con->processor_data->mutex);
	recurse_io(con->processor_data->filters, con, bistream_out);
	g_mutex_unlock(con->processor_data->mutex);
	connection_unref(con);
}



void processors_io_in(struct connection *con, void *data, int size)
{
	printf("%s con %p\n", __PRETTY_FUNCTION__, con);
//	struct bistream *bistream = g_hash_table_lookup(g_evtest->streams.table, con);

	GList *it;
	for ( it = g_list_first(con->processor_data->filters);	it != NULL;	it = g_list_next(it) )
	{
		struct processor_data *proc_data = it->data;
		if ( proc_data->processor->on_io_in == NULL )
			continue;

		struct bistream *bistream = proc_data->bistream;
		bistream_data_add(bistream, bistream_in, data, size);
	}
	
	GError *thread_error;
	struct thread *t = thread_new(con, NULL, processors_io_in_thread);

	connection_ref(con);
	g_thread_pool_push(g_dionaea->threads->pool, t, &thread_error);
}

void processors_io_out(struct connection *con, void *data, int size)
{
	printf("%s con %p\n", __PRETTY_FUNCTION__, con);

	GList *it;
	for ( it = g_list_first(con->processor_data->filters);	it != NULL;	it = g_list_next(it) )
	{
		struct processor_data *proc_data = it->data;
		if ( proc_data->processor->on_io_out == NULL )
			continue;

		struct bistream *bistream = proc_data->bistream;
		bistream_data_add(bistream, bistream_out, data, size);
	}

	GError *thread_error;
	struct thread *t = thread_new(con, NULL, processors_io_out_thread);

	connection_ref(con);
	g_thread_pool_push(g_dionaea->threads->pool, t, &thread_error);
}


void *proc_streamdumper_ctx_new(void *cfg);
void proc_streamdumper_ctx_free(void *ctx);
void proc_streamdumper_on_io_in(struct connection *con, struct processor_data *pd);
void proc_streamdumper_on_io_out(struct connection *con, struct processor_data *pd);

struct processor proc_streamdumper =
{
	.name = "streamdumper",
	.new = proc_streamdumper_ctx_new,  
	.free = proc_streamdumper_ctx_free,
	.on_io_in = proc_streamdumper_on_io_in,
	.on_io_out = proc_streamdumper_on_io_out,
};


struct streamdumper_ctx 
{
	bool in;
	bool out;
};

void *proc_streamdumper_ctx_new(void *cfg)
{
	struct streamdumper_ctx *ctx = g_malloc0(sizeof(struct streamdumper_ctx));
	ctx->in = true;
	ctx->out = true;
	return ctx;
}

void proc_streamdumper_ctx_free(void *ctx)
{
	free(ctx);
}

void proc_streamdumper_on_io(struct connection *con, struct processor_data *pd, enum bistream_direction dir)
{
	printf("%s con %p pd %p dir %i\n", __PRETTY_FUNCTION__, con, pd, dir);
	struct bistream *bs = pd->bistream;
	GList *it;
	g_mutex_lock(bs->mutex);
	for (it = g_list_first(bs->stream_sequence); it != NULL; it = g_list_next(it))
	{
//		if ( (dir == bistream_in && ctx->in) || 
//			 (dir == bistream_out && ctx->out) )
			print_stream_chunk2(it->data);
	}
	g_mutex_unlock(bs->mutex);
}

void proc_streamdumper_on_io_in(struct connection *con, struct processor_data *pd)
{
	proc_streamdumper_on_io(con, pd, bistream_in);
}

void proc_streamdumper_on_io_out(struct connection *con, struct processor_data *pd)
{
	proc_streamdumper_on_io(con, pd, bistream_out);
}


void *proc_unicode_ctx_new(void *data);
void proc_unicode_ctx_free(void *ctx);
void proc_unicode_on_io_in(struct connection *con, struct processor_data *pd);
void proc_unicode_on_io_out(struct connection *con, struct processor_data *pd);

struct processor proc_unicode =
{
	.name = "unicode",
	.new = proc_unicode_ctx_new,  
	.free = proc_unicode_ctx_free,
	.on_io_in = proc_unicode_on_io_in,
	.on_io_out = proc_unicode_on_io_out,
};

struct proc_unicode_ctx 
{
	int io_in_offset;
};

void *proc_unicode_ctx_new(void *cfg)
{
	struct proc_unicode_ctx *ctx = g_malloc0(sizeof(struct proc_unicode_ctx));
	ctx->io_in_offset = 0;
	return ctx;
}

void proc_unicode_ctx_free(void *ctx)
{
	free(ctx);
}

void proc_unicode_on_io_in(struct connection *con, struct processor_data *pd)
{
	printf("%s con %p pd %p\n", __PRETTY_FUNCTION__, con, pd);
	struct proc_unicode_ctx *ctx = pd->ctx;
	void *streamdata = NULL;
	int32_t size = bistream_get_stream(pd->bistream, bistream_in, ctx->io_in_offset, -1, &streamdata);
	ctx->io_in_offset += size;
	for (GList *it = g_list_first(pd->filters); it != NULL; it = g_list_next(it))
	{
		struct processor_data *filter = it->data;
		struct bistream *bs = filter->bistream;
		bistream_data_add(bs, bistream_in, streamdata, size);
	}
	g_free(streamdata);
}

void proc_unicode_on_io_out(struct connection *con, struct processor_data *pd)
{

}


void *proc_filter_cfg(struct lcfgx_tree_node *node);
bool proc_filter_accept(struct connection *con, void *config);
void *proc_filter_ctx_new(void *data);
void proc_filter_ctx_free(void *ctx);
void proc_filter_on_io_in(struct connection *con, struct processor_data *pd);
void proc_filter_on_io_out(struct connection *con, struct processor_data *pd);

struct processor proc_filter =
{
	.name = "filter",
	.cfg = proc_filter_cfg,
	.process = proc_filter_accept,
	.new = proc_filter_ctx_new,  
	.free = proc_filter_ctx_free,
	.on_io_in = proc_filter_on_io_in,
	.on_io_out = proc_filter_on_io_out,
};

struct proc_filter_config
{
	void *bar;
};

struct proc_filter_ctx
{
	struct proc_filter_config *config;
	int io_in_offset;
	int io_out_offset;
};

void *proc_filter_cfg(struct lcfgx_tree_node *node)
{
	return NULL;
}

bool proc_filter_accept(struct connection *con, void *config)
{
	return true;
}

void *proc_filter_ctx_new(void *config)
{
	struct proc_filter_ctx *ctx = g_malloc0(sizeof(struct proc_filter_ctx));
	ctx->config = config;
	return ctx;
}

void proc_filter_ctx_free(void *ctx)
{
	g_free(ctx);
}

void proc_filter_on_io_in(struct connection *con, struct processor_data *pd)
{
	struct proc_filter_ctx *ctx = pd->ctx;
	printf("%s con %p pd %p io_in_offset %i\n", __PRETTY_FUNCTION__, con, pd, ctx->io_in_offset);
		
	void *streamdata = NULL;
	int32_t size = bistream_get_stream(pd->bistream, bistream_in, ctx->io_in_offset, -1, &streamdata);
	ctx->io_in_offset += size;
	for( GList *it = g_list_first(pd->filters); it != NULL; it = g_list_next(it))
	{
		struct processor_data *filter = it->data;
		struct bistream *bs = filter->bistream;
		bistream_data_add(bs, bistream_in, streamdata, size);
	}
	g_free(streamdata);
}

void proc_filter_on_io_out(struct connection *con, struct processor_data *pd)
{
	printf("%s con %p pd %p\n", __PRETTY_FUNCTION__, con, pd);
	struct proc_filter_ctx *ctx = pd->ctx;
	void *streamdata = NULL;
	int32_t size = bistream_get_stream(pd->bistream, bistream_out, ctx->io_out_offset, -1, &streamdata);
	ctx->io_out_offset += size;
	for( GList *it = g_list_first(pd->filters); it != NULL; it = g_list_next(it))
	{
		struct processor_data *filter = it->data;
		struct bistream *bs = filter->bistream;
		bistream_data_add(bs, bistream_out, streamdata, size);
	}
	g_free(streamdata);
}

