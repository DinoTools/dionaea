/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "refcount.h"

void refcount_init(struct refcount *rc)
{
	rc->refs = 0;
	g_mutex_init(&rc->mutex);
}

void refcount_exit(struct refcount *rc)
{
	g_mutex_clear(&rc->mutex);
}

void refcount_inc(struct refcount *rc)
{
	g_mutex_lock(&rc->mutex);
	rc->refs++;
	g_mutex_unlock(&rc->mutex);
}

void refcount_dec(struct refcount *rc)
{
	g_mutex_lock(&rc->mutex);
	rc->refs--;
	g_mutex_unlock(&rc->mutex);
}

bool refcount_is_zero(struct refcount *rc)
{
	bool ret = false;

	g_mutex_lock(&rc->mutex);
	if( rc->refs == 0 )
		ret = true;
	g_mutex_unlock(&rc->mutex);
	return ret;
}
