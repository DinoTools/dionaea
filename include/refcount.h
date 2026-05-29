/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_REFCOUNT_H
#define HAVE_REFCOUNT_H

#include <stdbool.h>
#include <glib.h>

struct refcount
{
	GMutex mutex;
	int refs;
};

void refcount_init(struct refcount *rc);
void refcount_exit(struct refcount *rc);
void refcount_inc(struct refcount *rc);
void refcount_dec(struct refcount *rc);
bool refcount_is_zero(struct refcount *rc);

#endif
