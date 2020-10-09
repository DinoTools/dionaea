/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ev.h>

struct ev_loop;
struct ev_signal;

struct signals
{
	struct ev_signal sigint;
	struct ev_signal sigterm;
	struct ev_signal sighup;
	struct ev_signal sigsegv;
};


void sigint_cb(struct ev_loop *loop, struct ev_signal *w, int revents);
void sigterm_cb(struct ev_loop *loop, struct ev_signal *w, int revents);
void sighup_cb(struct ev_loop *loop, struct ev_signal *w, int revents);
void sigsegv_cb(struct ev_loop *loop, struct ev_signal *w, int revents);

int segv_handler(int sig);
void sigsegv_backtrace_cb(int sig);
