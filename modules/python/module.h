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
#include "connection.h"

#define PY_CLONE(T)  (T)->ob_type->tp_new((T)->ob_type, __pyx_empty_tuple, NULL)
#define PY_NEW(T) (((PyTypeObject*)(T))->tp_new( (PyTypeObject*)(T), __pyx_empty_tuple, NULL))
#define PY_INIT(P, O) (P)->ob_type->tp_init((O), __pyx_empty_tuple, NULL)
#define REFCOUNT(T) printf("obj refcount %i\n", (int)(T)->ob_refcnt)

#define REMOTE(C) (C)->remote
#define LOCAL(C) (C)->local

struct connection;

unsigned int python_handle_io_in_cb(struct connection *con, void *context, unsigned char *data, uint32_t size);

void log_wrap(char *name, int number, char *file, int line, char *msg);
void traceback(void);
PyObject *pygetifaddrs(PyObject *self, PyObject *args);
PyObject *pylcfg(PyObject *self, PyObject *args);
PyObject *pyversion(PyObject *self, PyObject *args);


struct ihandler;
struct incident;
void set_ihandler(struct ihandler *ih);
void traceable_ihandler_cb(struct incident *i, void *ctx);


struct protocol;
void set_protocol(struct protocol *p);
void *traceable_ctx_new_cb(struct connection *con);
void traceable_ctx_free_cb(void *ctx);
void traceable_origin_cb(struct connection *origin, struct connection *con);
void traceable_established_cb(struct connection *con);
uint32_t traceable_io_in_cb(struct connection *con, void *context, unsigned char *data, uint32_t size);
void traceable_io_out_cb(struct connection *con, void *context);
bool traceable_error_cb(struct connection *con, enum connection_error error);
bool traceable_disconnect_cb(struct connection *con, void *context);
bool traceable_idle_timeout_cb(struct connection *con, void *context);
bool traceable_listen_timeout_cb(struct connection *con, void *context);
bool traceable_sustain_timeout_cb(struct connection *con, void *context);

struct processor;
void set_processor(struct processor *);
void python_processor_bistream_create(struct connection *con);

