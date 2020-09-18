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

#include <errno.h>
#include <ev.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "dionaea.h"
#include "incident.h"
#include "module.h"
#include "processor.h"
#include "threads.h"


#define D_LOG_DOMAIN "xmatch"

typedef struct {
	u_char	*data;
	size_t	len;
} xorkey_t;

struct processor proc_xmatch =
{
	.name = "xmatch",
	.new = proc_xmatch_ctx_new,
	.free = proc_xmatch_ctx_free,
	.cfg = proc_xmatch_ctx_cfg_new,
	.thread_io_in = proc_xmatch_on_io_in,
};


// calculates the period of a string
size_t period(u_char *s, size_t len) {
	int i, j, period = len;
	for (i=1; i<len; ++i) {
		if (s[0] == s[i]) {
			for (j = i; j<len; ++j) {
				if (s[j-i] != s[j]) {
					period = len;
					break;
				}
				period = i;
			}
		}
		if (period < len) break;
	}

	return period;
}

void *proc_xmatch_ctx_cfg_new(void)
{
	g_debug("%s node", __PRETTY_FUNCTION__);
	// xmatch is not used at the moment, so we disable the config parsing
	return NULL;
/*
	struct xmatch_ctx *conf = g_malloc0(sizeof(struct xmatch_ctx));

	struct lcfgx_tree_node *patterns;
	if (lcfgx_get_list(node, &patterns, "patterns") != LCFGX_PATH_FOUND_TYPE_OK )
	{
		g_warning("configuration incomplete");
		g_free(conf);
		return NULL;
	}

	conf->p = NULL;
	conf->pnum = 0;
	conf->maxlen = 0;

	struct lcfgx_tree_node *pattern;
	for (pattern = patterns->value.elements; pattern != NULL; pattern = pattern->next )
	{
		// update maxlen value
		if (conf->maxlen < pattern->value.string.len) conf->maxlen = pattern->value.string.len;

		// for each pattern: calculate matching patterns p' where byte m \in [1:n-1] == p[1] XOR p[m+|keylen|]
		// possible values for keylen are 1..|pattern|/2
		size_t i;
		for (i=1; i <= pattern->value.string.len/2; ++i) {
			if ((conf->p = realloc(conf->p, (conf->pnum + 1) * sizeof(xm_string_t *))) == NULL) {
				g_warning("realloc failed: %s.", strerror(errno));
				return false;
			}
			if ((conf->p[conf->pnum] = xm_convert(pattern->value.string.data, pattern->value.string.len, i)) == NULL) {
				g_warning("xm_convert failed: %s.", strerror(errno));
				return false;
			}
			++conf->pnum;
		}
	}

	if ((conf->fsm = xm_fsm_new(conf->p, conf->pnum)) == NULL) {
		g_warning("could not build fsm from xmatch patterns.");
		return false;
	}

	g_debug("xmatch fsm successfully created, %lu transformed patterns.", conf->pnum);

	return conf;
	*/
}


int xmatch_match_cb(void *pattern_p, int offset, void *input_p) {
	xm_string_t *pattern = pattern_p;
	xm_string_t *input = input_p;
	xorkey_t *key = input->userdata;

	if (!pattern_p || !input_p) return -1;

	g_message("found a match at offset 0x%08x\n", (unsigned int) input->offset + offset);

	if ((key->data = malloc(pattern->len)) == NULL) {
		g_warning("malloc failed: %s.", strerror(errno));
		return -1;
	}
	key->len = pattern->len;

	size_t i, j;
	int nonzero_key = 0;

	for (j=0; j<pattern->len; ++j) {
		key->data[j] = input->data[offset + j] ^ pattern->data[j];
		if (key->data[j] != 0) nonzero_key = 1;
	}

	// if the key consists of zero bytes only, the data is already a plain text
	if (nonzero_key == 0) {
		free(key->data);
		key->data = NULL;
		key->len = 0;
		return 0;
	}

	size_t p = period(key->data, key->len);
	key->len = p;

	for (i=0; i < input->len; i += p)
		for (j=0; j<p; ++j)
			// align key to the match so that we can start decoding from input->data[0]
			input->data[i+j] ^= key->data[j + p - (offset % p)];

	return 0;
}

void *proc_xmatch_ctx_new(void *ctx)
{
	return ctx;
}

void proc_xmatch_ctx_free(void *ctx)
{
	return;
}

void proc_xmatch_on_io_in(struct connection *con, struct processor_data *pd)
{
	g_debug("%s con %p pd %p", __PRETTY_FUNCTION__, con, pd);

	struct xmatch_ctx *ctx = pd->ctx;

	void *streamdata = NULL;
        int32_t size = bistream_get_stream(pd->bistream, bistream_in, 0, -1, &streamdata);

	if (size == -1) return;

	xorkey_t key;
	key.data = NULL;
	key.len = 0;

	// match input against the bfa of transformed patterns, if a match is found, the buffer is automatically decoded with the extracted key
	int matches = xm_match(streamdata, size, ctx->fsm, ctx->maxlen, xmatch_match_cb, &key, BREAK_ON_FIRST_MATCH);

	switch (matches) {
	case -1:
		g_warning("Error during pattern matching.");
		g_free(streamdata);
		return;
	case 0:
		g_debug("did not find any matches.");
		return;
	}

	// match found
	struct incident *ix = incident_new("dionaea.xmatch.detected");
	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	g_async_queue_push(aq, async_cmd_new(async_incident_report, ix));
	g_async_queue_unref(aq);
	ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);

	// deal with match here

	pd->state = processor_done;

	g_free(streamdata);

	return;
}
