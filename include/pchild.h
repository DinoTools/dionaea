/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

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
