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

#ifndef HAVE_DIONAEA_H
#define HAVE_DIONAEA_H

struct lcfg;
struct lcfgx_tree_node;

struct dns;
struct modules;
struct pchild;
struct logging;
struct ihandlers;
struct threads;

struct dionaea
{
	struct
	{
		struct lcfg *config;
		struct lcfgx_tree_node *root;
		char *name;
	} config;

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
