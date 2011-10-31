#include <lcfg/lcfg.h>
#include <lcfgx/lcfgx_tree.h>
#include <ctype.h>

#include "dionaea.h"
#include "connection.h"
#include "processor.h"
#include "threads.h"

#include "log.h"
#include "util.h"

#define D_LOG_DOMAIN "processor"

bool processors_tree_create(GNode *tree, struct lcfgx_tree_node *node)
{
	g_debug("%s tree %p node %p key %s", __PRETTY_FUNCTION__, tree, node, node->key);

	char *key = g_strdup(node->key);
	char *x;
	if( (x = strstr(key,"-")) != NULL)
		*x = '\0';

	struct processor *p = g_hash_table_lookup(g_dionaea->processors->names, key);

	if( p == NULL )
	{
		g_error("Could not find processor '%s' (%s)", node->key, key);
	}

	g_free(key);

	struct processor *pt = g_malloc0(sizeof(struct processor));
	memcpy(pt, p, sizeof(struct processor));
	struct lcfgx_tree_node *n;

	if( pt->cfg != NULL )
	{
		if( lcfgx_get_map(node, &n, "config") == LCFGX_PATH_FOUND_TYPE_OK )
		{
			if( (pt->config = pt->cfg(n)) == NULL )
			{
				g_error("processor %s rejected config", node->key);
			}
		} else
		{
			g_error("processor %s expects config", node->key);
		}
	}

	GNode *me = g_node_new(pt);
	g_node_append(tree, me);

	if( lcfgx_get_map(node, &n, "next") == LCFGX_PATH_FOUND_TYPE_OK )
	{
		struct lcfgx_tree_node *it;
		for( it = n->value.elements; it != NULL; it = it->next )
		{
			if( processors_tree_create(me, it) != true )
				return false;
		}
	}
	return true;
}

void processors_tree_dump(GNode *tree, int indent)
{
	for( GNode *it = g_node_first_sibling(tree); it != NULL; it = it->next )
	{
#ifdef DEBUG
		if( it->data )
		{
			struct processor *p = it->data;
			g_debug("%*s %s", indent*4, " ", p->name);
    	}
#endif 

		if( it->children )
			processors_tree_dump(g_node_first_child(it), indent+1);
	}
}

void processor_data_creation(struct connection *con, struct processor_data *pd, GNode *node)
{
	g_debug("%s con %p pd %p node %p", __PRETTY_FUNCTION__, con, pd, node);
	struct processor *p = node->data;

	if( p->process && !p->process(con, p->config) )
	{
		g_debug("skip %s", p->name);
		return;
	}

	g_debug("creating %s", p->name);
	struct processor_data *npd = processor_data_new();
	npd->processor = p;
	if( npd->processor->new )
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
	g_debug("%s pd %p", __PRETTY_FUNCTION__, pd);
	GList *it;
	while( (it = g_list_first(pd->filters)) != NULL )
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
	for( GNode *it = g_node_first_sibling(g_dionaea->processors->tree->children); 
	   it != NULL; 
	   it = it->next )
	{
		processor_data_creation(con, con->processor_data, it);
	}
}


void processors_clear(struct connection *con)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);

	GList *it;
	while( (it = g_list_first(con->processor_data->filters)) != NULL )
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
	refcount_init(&pd->queued);
	pd->state = processor_continue;
	pd->processor = NULL;
	pd->filters = NULL;
	pd->bistream = bistream_new();
	return pd;
}

void processor_data_free(struct processor_data *pd)
{
/*	g_debug("%s pd %p", __PRETTY_FUNCTION__, pd);
	if ( pd == NULL )
		return;
*/
	bistream_free(pd->bistream);
	g_mutex_free(pd->mutex);
	refcount_exit(&pd->queued);
	g_free(pd);
}

void recurse_io(GList *list, struct connection *con, enum bistream_direction dir);
void recurse_io_process(struct processor_data *pd, struct connection *con, enum bistream_direction dir)
{
	if( dir == bistream_in )
	{
		if( pd->processor->thread_io_in != NULL )
		{
			pd->processor->thread_io_in(con, pd);
			recurse_io(pd->filters, con, dir);
		}
	} else
	{
		if( pd->processor->thread_io_out != NULL )
		{
			pd->processor->thread_io_out(con, pd);
			recurse_io(pd->filters, con, dir);
		}
	}
}

void recurse_io(GList *list, struct connection *con, enum bistream_direction dir)
{
	GList *it;
	for( it = g_list_first(list); it != NULL; it = g_list_next(it) )
	{
		struct processor_data *pd = it->data;
		recurse_io_process(pd, con, dir);
	}
}

void processors_io_in_thread(void *data, void *userdata)
{
	g_debug("%s data %p userdata %p", __PRETTY_FUNCTION__, data,  userdata);
	struct connection *con = data;
	struct processor_data *pd = userdata;
	g_mutex_lock(pd->mutex);
	refcount_dec(&pd->queued);
	recurse_io_process(pd, con, bistream_in);
	g_mutex_unlock(pd->mutex);
	connection_unref(con);
}

void processors_io_out_thread(void *data, void *userdata)
{
	g_debug("%s data %p userdata %p", __PRETTY_FUNCTION__, data,  userdata);
	struct connection *con = data;
	struct processor_data *pd = userdata;
	g_mutex_lock(pd->mutex);
	refcount_dec(&pd->queued);
	recurse_io_process(pd, con, bistream_out);
	g_mutex_unlock(pd->mutex);
	connection_unref(con);
}

void processor_io_single(struct connection *con,  struct processor_data *pd, void *data, int size, enum bistream_direction direction)
{
//	g_warning("%s con %p pd %p data %p size %i dir %i", __PRETTY_FUNCTION__, con, pd, data, size, direction);

	processor_io io = NULL;
	GFunc thread_io = NULL;

	if( direction ==  bistream_in )
	{
		if( (io = pd->processor->io_in) == NULL)
			thread_io = processors_io_in_thread;
	}else
	{
		if( (io = pd->processor->io_out) == NULL)
			thread_io = processors_io_out_thread;
	}

//	g_warning("processor %s io %p thread_io %p", pd->processor->name, io, thread_io);

	if( thread_io != NULL )
	{
		struct bistream *bistream = pd->bistream;
		bistream_data_add(bistream, direction, data, size);

		g_mutex_lock(pd->queued.mutex);
		if( pd->queued.refs == 0 )
		{
			pd->queued.refs++;
			GError *thread_error;
			struct thread *t = thread_new(con, pd, thread_io);

			connection_ref(con);
			g_thread_pool_push(g_dionaea->threads->pool, t, &thread_error);
		}
		g_mutex_unlock(pd->queued.mutex);
	}else
	if( io != NULL )
	{
		io(con, pd, data, size);
	}
}


void processors_io_in(struct connection *con, void *data, int size)
{
//	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
	GList *it;
	for( it = g_list_first(con->processor_data->filters);  it != NULL; it = g_list_next(it) )
	{
		struct processor_data *pd = it->data;
//		g_warning("doing %s",  pd->processor->name);
		processor_io_single(con, pd, data, size, bistream_in);
	}
}

void processors_io_out(struct connection *con, void *data, int size)
{
//	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
	GList *it;
	for( it = g_list_first(con->processor_data->filters);  it != NULL; it = g_list_next(it) )
	{
		struct processor_data *pd = it->data;
		processor_io_single(con, pd, data, size, bistream_out);
	}
}

void *proc_streamdumper_cfg_new(struct lcfgx_tree_node *node);
void *proc_streamdumper_ctx_new(void *cfg);
void proc_streamdumper_ctx_free(void *ctx);
void proc_streamdumper_on_io_in(struct connection *con, struct processor_data *pd, void *data, int size);
void proc_streamdumper_on_io_out(struct connection *con, struct processor_data *pd, void *data, int size);

struct streamdumper_config
{
	char *path;
};

struct processor proc_streamdumper =
{
	.name = "streamdumper",
	.cfg = proc_streamdumper_cfg_new,
	.new = proc_streamdumper_ctx_new,  
	.free = proc_streamdumper_ctx_free,
	.io_in = proc_streamdumper_on_io_in,
	.io_out = proc_streamdumper_on_io_out,
};


struct streamdumper_ctx 
{
	struct tempfile *file;
	enum bistream_direction last_was;
};


void *proc_streamdumper_cfg_new(struct lcfgx_tree_node *node)
{
	struct streamdumper_config *cfg = g_malloc0(sizeof(struct streamdumper_config));
	struct lcfgx_tree_node *n;
	if( lcfgx_get_string(node, &n, "path") != LCFGX_PATH_FOUND_TYPE_OK )
	{
		g_error("streamdumper needs a path");
	}

	char *path = n->value.string.data;
	// test the path ...
	char test[256];
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(test, 255, path, timeinfo);
	if( strcmp(test, path) == 0 )
	{
		g_error("streamdumper path does not have time based modifiers, all files end up in a single directory, which is not accepted.");
	}

	g_warning("%s <-> %s", test, path);
	cfg->path = g_strdup(n->value.string.data);
	return cfg;
}

void *proc_streamdumper_ctx_new(void *cfg)
{
	struct streamdumper_ctx *ctx = g_malloc0(sizeof(struct streamdumper_ctx));
	
	return ctx;
}

void proc_streamdumper_ctx_free(void *ctx0)
{
	struct streamdumper_ctx *ctx = ctx0;
	if( ctx->file != NULL )
	{
		const char *close_stream = "')]";
		if( fwrite(close_stream, strlen(close_stream), 1, ctx->file->fh) != 1 )
		{
			g_warning("Could not write close_stream %s",  strerror(errno));
		}
		tempfile_close(ctx->file);
		tempfile_free(ctx->file);
	}
	g_free(ctx);
}

void proc_streamdumper_on_io(struct connection *con, struct processor_data *pd, void *data, int size, enum bistream_direction dir)
{
//	g_warning("%s con %p pd %p data %p size %i dir %i", __PRETTY_FUNCTION__, con, pd, data, size, dir);
	struct streamdumper_ctx *ctx = pd->ctx;

	char *direction_helper[] = 
	{
		"('in', ",
		"('out', ",
	};

	const char * stream_start = "stream = [";
	const char * new_data = "b'";

	if( ctx->file == NULL )
	{
		time_t stamp;
		if( g_dionaea != NULL && g_dionaea->loop != NULL )
			stamp = ev_now(g_dionaea->loop);
		else
			stamp = time(NULL);
		struct tm t;
		localtime_r(&stamp, &t);
		char path[128];
		strftime(path, sizeof(path), ((struct streamdumper_config *)pd->processor->config)->path, &t);
		char prefix[512];
		snprintf(prefix, sizeof(prefix), "%s-%i-%s-",
				 con->protocol.name,
				 ntohs(con->local.port),
				 con->remote.ip_string);

		struct stat s;
		if( stat(path, &s) != 0 &&
			mkdir(path, S_IRWXU|S_IRUSR|S_IWUSR|S_IXUSR|S_IRWXG|S_IRGRP|S_IWGRP|S_IXGRP|S_IRWXO|S_IROTH|S_IWOTH|S_IXOTH) != 0 )
		{
			g_warning("Could not create %s %s",  path, strerror(errno));
		}
		

		if( (ctx->file = tempfile_new(path, prefix)) == NULL )
			return;


		if( fwrite(stream_start, strlen(stream_start), 1, ctx->file->fh) != 1 )
		{
			g_warning("Could not write stream_start %s", strerror(errno));
			return;
		}
		
		if( fwrite(direction_helper[dir], strlen(direction_helper[dir]), 1, ctx->file->fh) != 1 )
		{
			g_warning("Could not write direction %s", strerror(errno));
			return;
		}
		

		if( fwrite(new_data, strlen(new_data), 1, ctx->file->fh) != 1 )
		{
			g_warning("Could not write new_data %s",  strerror(errno));
			return;
		}
		ctx->last_was = dir;
	}
	
	if( ctx->last_was != dir )
	{
		const char *change_stream = "'),\n";
		
		if( fwrite(change_stream, strlen(change_stream), 1, ctx->file->fh) != 1 )
		{
			g_warning("Could not write change_stream %s",  strerror(errno));
			return;
		}

		if( fwrite(direction_helper[dir], strlen(direction_helper[dir]), 1, ctx->file->fh) != 1 )
		{
			g_warning("Could not write direction %s",  strerror(errno));
			return;
		}


		if( fwrite(new_data, strlen(new_data), 1, ctx->file->fh) != 1 )
		{
			g_warning("Could not write new_data %s", strerror(errno));
			return;
		}

		ctx->last_was = dir;
	}

	char *cdata = data;
	char xdata[size*4];
	memset(xdata, 0, size*4);
	char conv[] = "0123456789abcdef";
	int writesize = 0;
	for( int i=0; i<size;i++ )
	{
		if( isprint(cdata[i]) && cdata[i] != '\'' && cdata[i] != '\\' )
		{
			xdata[writesize++] = cdata[i];
		}else
		{
			xdata[writesize++] = '\\';
			xdata[writesize++] = 'x';
			xdata[writesize++] = conv[((cdata[i] & 0xFF) >> 4)];
			xdata[writesize++] = conv[((cdata[i] & 0xff) & 0x0F)];
		}
	}
	if( fwrite(xdata, 1, writesize, ctx->file->fh) != writesize )
	{
		g_warning("Could not write data %s",  strerror(errno));
		return;
	}
}

           


void proc_streamdumper_on_io_in(struct connection *con, struct processor_data *pd, void *data, int size)
{
	proc_streamdumper_on_io(con, pd, data, size, bistream_in);
}

void proc_streamdumper_on_io_out(struct connection *con, struct processor_data *pd, void *data, int size)
{
	proc_streamdumper_on_io(con, pd, data, size, bistream_out);
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
	.thread_io_in = proc_unicode_on_io_in,
	.thread_io_out = proc_unicode_on_io_out,
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
	g_debug("%s con %p pd %p", __PRETTY_FUNCTION__, con, pd);
	struct proc_unicode_ctx *ctx = pd->ctx;
	void *streamdata = NULL;
	int32_t size = bistream_get_stream(pd->bistream, bistream_in, ctx->io_in_offset, -1, &streamdata);
	ctx->io_in_offset += size;
	for( GList *it = g_list_first(pd->filters); it != NULL; it = g_list_next(it) )
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
void proc_filter_on_io_in(struct connection *con, struct processor_data *pd, void *data, int size);
void proc_filter_on_io_out(struct connection *con, struct processor_data *pd, void *data, int size);

struct processor proc_filter =
{
	.name = "filter",
	.cfg = proc_filter_cfg,
	.process = proc_filter_accept,
	.new = proc_filter_ctx_new,  
	.free = proc_filter_ctx_free,
	.io_in = proc_filter_on_io_in,
	.io_out = proc_filter_on_io_out,
};

struct proc_filter_config_rule
{
	GList *types;
	GList *protocols;
};

struct proc_filter_config
{
	GList *allow;
	GList *deny;
};

struct proc_filter_ctx
{
	struct proc_filter_config *config;
};

void proc_filter_dump_rules(struct proc_filter_config *cfg)
{
	struct 
	{
		char *mode;
		int offset;
	} cfg_iter_help[] = 
	{
		{ "allow", offsetof(struct proc_filter_config, allow) },
		{ "deny", offsetof(struct proc_filter_config, deny) },
		{}
	};

	struct
	{
		char *type;
		int offset;
	} rule_iter_help[] =
	{
		{ "protocol", offsetof(struct proc_filter_config_rule, protocols) },
		{ "type", offsetof(struct proc_filter_config_rule, types) },
		{}
	};

	for( int i=0; cfg_iter_help[i].mode != NULL; i++ )
	{
		GList **list = (((void *)cfg) + cfg_iter_help[i].offset);
//		g_warning("mode %s offset %i list %p %p %p",  cfg_iter_help[i].mode, cfg_iter_help[i].offset, cfg, list, cfg->deny);

		if( *list == NULL )
			continue;

		printf("%s\n\t",  cfg_iter_help[i].mode);


		for( GList *it = g_list_first((void *)*list); it != NULL; it = g_list_next(it) )
		{
			for( int j=0; rule_iter_help[j].type != NULL; j++ )
			{
				printf(" # %s  ", rule_iter_help[j].type);

				struct proc_filter_config_rule *rule = it->data;
//				g_warning("################");
				GList **rules = (((void *)rule) + rule_iter_help[j].offset);
				for( GList *jt = g_list_first(*rules); jt != NULL; jt = g_list_next(jt) )
				{
					char *p = jt->data;
//					g_warning("%s %s %s", cfg_iter_help[i].mode, rule_iter_help[j].type, p);
					printf("%s ",  p);
				}
//				g_warning("################");
			}
			if( g_list_next(it) != NULL )
				printf("\n\t");
			else
				printf("\n");
		}
		printf("\n");
	}
//	exit(0);
}

void *proc_filter_cfg(struct lcfgx_tree_node *node)
{
	struct proc_filter_config *cfg = g_malloc0(sizeof(struct proc_filter_config));

//	char *mode = NULL;
//	char *what = NULL;

	for( struct lcfgx_tree_node *n = node->value.elements; n != NULL; n = n->next)
	{
//		g_warning("found %s", mode);
		if( n->type != lcfgx_list )
			continue;

		for( struct lcfgx_tree_node *it = n->value.elements; it != NULL; it = it->next )
		{
//			g_warning("found %s %s",  mode,  it->key);
			if( it->type == lcfgx_map )
			{
				struct proc_filter_config_rule *rule = g_malloc0(sizeof(struct proc_filter_config_rule));

				if( strcmp(n->key,"allow") == 0 )
				{
//					mode = "allow";
					cfg->allow = g_list_append(cfg->allow, rule);
				}else
				if( strcmp(n->key,"deny") == 0 )
				{
//					mode = "deny";
					cfg->deny = g_list_append(cfg->deny, rule);
				}else
				{
					g_free(rule);
					continue;
				}
				for( struct lcfgx_tree_node *jt = it->value.elements; jt != NULL; jt = jt->next )
				{
//					g_warning("found %s %s %s",  mode,  it->key, jt->key);

					GList **l;
					if( strcmp(jt->key, "protocol") == 0 )
					{
//						what = "protocol";
						l = &rule->protocols;
					}else
					if( strcmp(jt->key, "type") == 0 )
					{
//						what = "type";
						l = &rule->types;
					}else
						continue;
		
					for( struct lcfgx_tree_node *kt = jt->value.elements; kt != NULL; kt = kt->next )
					{
						if( kt->type == lcfgx_string )
						{
//							g_warning("%s %s %s", mode, what, (char *)kt->value.string.data);
							*l = g_list_append(*l, g_strdup((char *)kt->value.string.data));
						}
					}
				}
			}
    	}
	}
	proc_filter_dump_rules(cfg);
	return cfg;
}

bool proc_filter_accept_match(struct connection *con, GList *list)
{
	bool match = false;

	for(GList *it = g_list_first(list); it != NULL; it = g_list_next(it) )
	{
		struct proc_filter_config_rule *rule = it->data;
		bool protocol = rule->protocols ? false : true;
		bool type = rule->types ? false : true;
		for( GList *jt = g_list_first(rule->protocols); jt != NULL; jt = g_list_next(jt) )
		{
			char *p = jt->data;
			if( strcmp(p, con->protocol.name) == 0)
			{
				protocol = true;
				break;
			}
		}

		for( GList *jt = g_list_first(rule->types); jt != NULL; jt = g_list_next(jt) )
		{
			char *p = jt->data;
			if( strcmp(p, connection_type_to_string(con->type)) == 0)
			{
				type = true;
				break;
			}
		}

		if( protocol && type )
		{
			match = true;
			break;
		}
	}
	return match;
}


bool proc_filter_accept(struct connection *con, void *config)
{
//	g_debug("%s con %p config %p",  __PRETTY_FUNCTION__, con, config);
	
	struct proc_filter_config *cfg = config;

	bool allow = false;
	bool deny = false;

	allow = proc_filter_accept_match(con, cfg->allow);
	if( allow == false )
		return false;

	deny = proc_filter_accept_match(con, cfg->deny);

	if( deny == true )
		return false;

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

void proc_filter_on_io(struct connection *con, struct processor_data *pd, void *data, int size, enum bistream_direction direction)
{
//	g_debug("%s con %p pd %p data %p size %i direction %i", __PRETTY_FUNCTION__, con, pd, data, size, direction);

	GList *it;
	for( it = pd->filters; it != NULL; it = g_list_next(it) )
	{
		struct processor_data *pd = it->data;
		processor_io_single(con, pd, data, size, direction);
	}
}

void proc_filter_on_io_in(struct connection *con, struct processor_data *pd, void *data, int size)
{
//	g_debug("%s con %p pd %p data %p size %i", __PRETTY_FUNCTION__, con, pd, data, size);
	proc_filter_on_io(con,pd,data,size,bistream_in);
}

void proc_filter_on_io_out(struct connection *con, struct processor_data *pd, void *data, int size)
{
//	g_debug("%s con %p pd %p data %p size %i", __PRETTY_FUNCTION__, con, pd, data, size);
	proc_filter_on_io(con,pd,data,size,bistream_out);
}

