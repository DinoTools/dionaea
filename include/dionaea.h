/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_DIONAEA_H
#define HAVE_DIONAEA_H

#include <glib.h>
struct dns;
struct modules;
struct pchild;
struct logging;
struct ihandlers;
struct threads;

struct version
{
	struct
	{
		char *version;
	} dionaea;
	struct
	{
		char *os;
		char *arch;
		char *date;
		char *time;
		char *name;
		char *version;
	} compiler;
	struct
	{
		char *node;
		char *sys;
		char *machine;
		char *release;
	} info;
};


struct dionaea
{
  GKeyFile *config;

	struct
	{
		int fds;
	} limits;

	struct version *version;

	struct dns *dns;

	struct ev_loop *loop;

	struct modules *modules;

	struct pchild *pchild;

	struct logging *logging;

	struct signals *signals;

	struct ihandlers *ihandlers;

	struct threads *threads;

	struct processors *processors;
};



extern struct dionaea *g_dionaea;



#endif
