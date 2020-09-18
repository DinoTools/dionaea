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

#include <emu/emu.h>
#include <emu/emu_shellcode.h>
#include <emu/emu_log.h>
#include <emu/emu_cpu.h>
#include <emu/emu_cpu_data.h>

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

void *proc_emu_ctx_cfg_new(gchar *group_name)
{
	g_debug("%s node", __PRETTY_FUNCTION__);
	struct emu_config *conf = g_malloc0(sizeof(struct emu_config));

	GError *error = NULL;

	conf->limits.files = g_key_file_get_integer(g_dionaea->config, group_name, "config.limits.files", &error);
	if (error != NULL)
		goto err;

	conf->limits.filesize = g_key_file_get_integer(g_dionaea->config, group_name, "config.limits.filesize", &error);
	if (error != NULL)
		goto err;

	conf->limits.sockets = g_key_file_get_integer(g_dionaea->config, group_name, "config.limits.sockets", &error);
	if (error != NULL)
		goto err;

	conf->limits.steps = g_key_file_get_integer(g_dionaea->config, group_name, "config.limits.steps", &error);
	if (error != NULL)
		goto err;

	conf->limits.idle = g_key_file_get_integer(g_dionaea->config, group_name, "config.limits.idle", &error);
	if (error != NULL)
		goto err;

	conf->limits.listen = g_key_file_get_double(g_dionaea->config, group_name, "config.limits.listen", &error);
	if (error != NULL)
		goto err;

	conf->limits.sustain = g_key_file_get_double(g_dionaea->config, group_name, "config.limits.sustain", &error);
	if (error != NULL)
		goto err;

	conf->limits.cpu = g_key_file_get_double(g_dionaea->config, group_name, "config.limits.cpu", &error);
	if (error != NULL)
		goto err;

	g_debug(
		" files %i filesize %i sockets %i steps %i idle %f listen %f sustain %f cpu %f ",
		conf->limits.files,
		conf->limits.filesize,
		conf->limits.sockets,
		conf->limits.steps,
		conf->limits.idle,
		conf->limits.listen,
		conf->limits.sustain,
		conf->limits.cpu
	);

//	g_error("STOP");
	return conf;

	err:
	g_warning("configuration for emulation is incomplete");
	if (error != NULL)
		g_warning("%s", error->message);

	g_clear_error(&error);
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
#if 0
		emu_cpu_debugflag_set(emu_cpu_get(e), instruction_string);
		emu_log_level_set(emu_logging_get(e),EMU_LOG_DEBUG);
#endif
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
			g_debug("shellcode found offset %i", ret);
			profile(ctx->config, con, streamdata, size, ret);

			pd->state = processor_done;
		}
		g_free(streamdata);
	}
}
