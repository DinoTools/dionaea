/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <stdio.h>

#include "modules.h"
#include "connection.h"
#include "dionaea.h"

#include "module.h"
#include "processor.h"

#define D_LOG_DOMAIN "xmatch"


static bool xmatch_config(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool xmatch_prepare(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	g_hash_table_insert(g_dionaea->processors->names, (void *)proc_xmatch.name, &proc_xmatch);
	return true;
}

static bool xmatch_new(struct dionaea *d)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool xmatch_free(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool xmatch_hup(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

struct module_api *module_init(struct dionaea *d)
{
    g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, d);
	static struct module_api xmatch_api =
	{
		.config = &xmatch_config,
		.prepare = &xmatch_prepare,
		.new = &xmatch_new,
		.free = &xmatch_free,
		.hup = &xmatch_hup
	};

    return &xmatch_api;
}
