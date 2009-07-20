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

struct connection;
struct processor_data;
struct emu;
struct emu_env;

void *proc_emu_ctx_new(void *cfg);
void proc_emu_ctx_free(void *ctx);
void proc_emu_on_io_in(struct connection *con, struct processor_data *pd);
void proc_emu_on_io_out(struct connection *con, struct processor_data *pd);

int run(struct emu *e, struct emu_env *env);
void profile(struct connection *con, void *data, unsigned int size, unsigned int offset);

extern struct processor proc_emu;
