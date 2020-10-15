/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdbool.h>

struct connection;

void proto_nc_established(struct connection *con);
void proto_nc_established_source(struct connection *con);
bool proto_nc_error(struct connection *con, enum connection_error error);
uint32_t proto_nc_io_in(struct connection *con, void *context, unsigned char *data, uint32_t size);
uint32_t proto_nc_io_in_redir(struct connection *con, void *context, unsigned char *data, uint32_t size);
bool proto_nc_disconnect(struct connection *con, void *context);
bool proto_nc_timeout(struct connection *con, void *context);
void *proto_nc_ctx_new(struct connection *con);
void proto_nc_ctx_free(void *ctx);

void proto_nc_established_http(struct connection *con);
uint32_t proto_nc_io_in_http(struct connection *con, void *context, unsigned char *data, uint32_t size);
void *proto_nc_ctx_new_http(struct connection *con);
void proto_nc_ctx_free_http(void *ctx);

extern struct protocol proto_nc_http;
extern struct protocol proto_nc_source;
extern struct protocol proto_nc_sink;
extern struct protocol proto_nc_redir;
