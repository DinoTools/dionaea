/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __DIONAEA_XMATCH_H
#define __DIONAEA_XMATCH_H

#include <xmatch.h>

struct processor_data;
struct connection;


struct xmatch_ctx
{
	char *patternfile;
	xm_string_t **p;
	size_t pnum;
	size_t maxlen;
	xm_fsm_t *fsm;
};

void *proc_xmatch_ctx_new(void *cfg);
void proc_xmatch_ctx_free(void *ctx);
void *proc_xmatch_ctx_cfg_new(void);
void proc_xmatch_on_io_in(struct connection *con, struct processor_data *pd);

extern struct processor proc_xmatch;

#endif
