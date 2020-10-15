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
#include "log.h"
#include "processor.h"

#define D_LOG_DOMAIN "emu"

/*
static struct
{
} emu_runtime;
*/

static bool emu_config(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool emu_new(struct dionaea *d)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	g_hash_table_insert(g_dionaea->processors->names, (void *)proc_emu.name, &proc_emu);
	return true;
}

static bool emu_free(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}

static bool emu_hup(void)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	return true;
}



struct module_api *module_init(struct dionaea *d)
{
    g_debug("%s:%i %s dionaea %p",__FILE__, __LINE__, __PRETTY_FUNCTION__, d);
	static struct module_api emu_api =
	{
		.config = &emu_config,
		.start = NULL,
		.new = &emu_new,
		.free = &emu_free,
		.hup = &emu_hup
	};

    return &emu_api;
}
