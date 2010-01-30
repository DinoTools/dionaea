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

extern struct protocol proto_nc_source;
extern struct protocol proto_nc_sink;
extern struct protocol proto_nc_redir;

