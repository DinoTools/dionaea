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



struct GMutex;

struct pchild
{
	int fd;
	/**
	 * mutex for the pchild
	 * as threads may use the child for their very own purpose too,
	 * lock the child if it is busy
	 *
	 * locking has to be done 'client' side
	 */
	GMutex mutex;
};


struct pchild *pchild_new(void);
bool pchild_init(void);
int pchild_sent_bind(int sx, struct sockaddr *s, socklen_t size);


/**
 * declaration of a pchild function
 * if you want the pchild do something for you, you send a
 * pointer to a pchild_cmd function the pchild will call the
 * function, and your own function can take care, powered with
 * pchild privileges
 */
typedef void (*pchild_cmd)(int s);
