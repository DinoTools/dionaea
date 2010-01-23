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

#include <ev.h>
#include <glib.h>

#include <lcfg/lcfg.h>
#include <lcfgx/lcfgx_tree.h>

#include <emu/emu.h>
#include <emu/emu_shellcode.h>

#include "dionaea.h"
#include "processor.h"
#include "log.h"
#include "incident.h"
#include "threads.h"

#define D_LOG_DOMAIN "emu"

#include "module.h"

struct processor proc_emu =
{
	.name = "emu",
	.new = proc_emu_ctx_new,  
	.free = proc_emu_ctx_free,
	.cfg = proc_emu_ctx_cfg_new,
	.thread_io_in = proc_emu_on_io_in,
};

void *proc_emu_ctx_cfg_new(struct lcfgx_tree_node *node)
{
	g_debug("%s node %p", __PRETTY_FUNCTION__, node);
	lcfgx_tree_dump(node,0);
	struct emu_config *conf = g_malloc0(sizeof(struct emu_config));

	struct lcfgx_tree_node *n;
	if( lcfgx_get_string(node, &n, "emulation.limits.files") == LCFGX_PATH_FOUND_TYPE_OK )
		conf->limits.files = strtol(n->value.string.data, NULL, 10);
	else
		goto err;

	if( lcfgx_get_string(node, &n, "emulation.limits.filesize") == LCFGX_PATH_FOUND_TYPE_OK )
		conf->limits.filesize = strtol(n->value.string.data, NULL, 10);
	else
		goto err;

	if( lcfgx_get_string(node, &n, "emulation.limits.sockets") == LCFGX_PATH_FOUND_TYPE_OK )
		conf->limits.sockets = strtol(n->value.string.data, NULL, 10);
	else
		goto err;

	if( lcfgx_get_string(node, &n, "emulation.limits.steps") == LCFGX_PATH_FOUND_TYPE_OK )
		conf->limits.steps = strtol(n->value.string.data, NULL, 10);
	else
		goto err;

	if( lcfgx_get_string(node, &n, "emulation.limits.idle") == LCFGX_PATH_FOUND_TYPE_OK )
		conf->limits.idle = strtod(n->value.string.data, NULL);
	else
		goto err;

	if( lcfgx_get_string(node, &n, "emulation.limits.sustain") == LCFGX_PATH_FOUND_TYPE_OK )
		conf->limits.sustain = strtod(n->value.string.data, NULL);
	else
		goto err;

	if( lcfgx_get_string(node, &n, "emulation.limits.cpu") == LCFGX_PATH_FOUND_TYPE_OK )
		conf->limits.cpu = strtod(n->value.string.data, NULL);
	else
		goto err;

	g_debug(" files %i filesize %i sockets %i steps %i idle %f sustain %f cpu %f ", conf->limits.files, conf->limits.filesize,
			conf->limits.sockets, conf->limits.steps, conf->limits.idle, conf->limits.sustain, conf->limits.cpu);

//	g_error("STOP");
	return conf;

	err:
	g_warning("configuration incomplete");
	g_free(conf);
	return NULL;
}

void *proc_emu_ctx_new(void *cfg)
{
	if( cfg == NULL )
	{
		g_error("emulation needs configuration");
	}
	struct emu_ctx *ctx = g_malloc0(sizeof(struct emu_ctx));
	ctx->config = cfg;
	return ctx;
}

void proc_emu_ctx_free(void *ctx)
{
	g_free(ctx);
}

#include <emu/emu_log.h>
#include <emu/emu_cpu.h>
#include <emu/emu_cpu_data.h>

void proc_emu_on_io_in(struct connection *con, struct processor_data *pd)
{
	g_debug("%s con %p pd %p", __PRETTY_FUNCTION__, con, pd);
	struct emu_ctx *ctx = pd->ctx;

	int offset = MAX(ctx->offset-300, 0);
	void *streamdata = NULL;
	int32_t size = bistream_get_stream(pd->bistream, bistream_in, offset, -1, &streamdata);
	int ret = 0;
	if( size != -1 )
	{
		struct emu *e = emu_new();
		emu_cpu_debugflag_set(emu_cpu_get(e), instruction_string);
		emu_log_level_set(emu_logging_get(e),EMU_LOG_DEBUG);
		ret = emu_shellcode_test(e, streamdata, size);
		emu_free(e);
		ctx->offset += size;
		if( ret >= 0 )
		{
			struct incident *ix = incident_new("dionaea.shellcode.detected");
			GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
			g_async_queue_push(aq, async_cmd_new(async_incident_report, ix));
			g_async_queue_unref(aq);
			ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);
			g_critical("shellcode found offset %i", ret);
			profile(ctx->config, con, streamdata, size, ret);

			pd->state = processor_done;
		}
		g_free(streamdata);
	}
}
