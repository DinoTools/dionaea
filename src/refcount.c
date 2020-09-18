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
