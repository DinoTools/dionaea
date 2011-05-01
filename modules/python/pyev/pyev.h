/*******************************************************************************
*
* Copyright (c) 2009 - 2011 Malek Hadj-Ali
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
* 3. Neither the name of the copyright holders nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
* BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
* OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
* OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
* IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
* THE POSSIBILITY OF SUCH DAMAGE.
*
*
* Alternatively, the contents of this file may be used under the terms of the
* GNU General Public License (the GNU GPL) version 3 or (at your option) any
* later version, in which case the provisions of the GNU GPL are applicable
* instead of those of the modified BSD license above.
* If you wish to allow use of your version of this file only under the terms
* of the GNU GPL and not to allow others to use your version of this file under
* the modified BSD license above, indicate your decision by deleting
* the provisions above and replace them with the notice and other provisions
* required by the GNU GPL. If you do not delete the provisions above,
* a recipient may use your version of this file under either the modified BSD
* license above or the GNU GPL.
*
*******************************************************************************/


#ifndef _PYEV_H
#define _PYEV_H


/* Python */
#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "structmember.h"
#include "structseq.h"

/* pyev requirements */
#undef EV_STANDALONE
#undef EV_COMPAT3
#undef EV_VERIFY
#undef EV_FEATURES
#undef EV_MULTIPLICITY
#undef EV_PROTOTYPES
#undef EV_COMMON
#undef EV_CB_DECLARE
#undef EV_CB_INVOKE

#undef EV_PERIODIC_ENABLE
#undef EV_SIGNAL_ENABLE
#undef EV_CHILD_ENABLE
#undef EV_STAT_ENABLE
#undef EV_IDLE_ENABLE
#undef EV_PREPARE_ENABLE
#undef EV_CHECK_ENABLE
#undef EV_EMBED_ENABLE
#undef EV_FORK_ENABLE
#undef EV_ASYNC_ENABLE

#define EV_COMPAT3 0

#ifdef Py_DEBUG
#define EV_VERIFY 3
#else
#define EV_VERIFY 0
#endif

#ifdef MS_WINDOWS
#undef EV_FD_TO_WIN32_HANDLE
#undef EV_WIN32_HANDLE_TO_FD
#undef EV_WIN32_CLOSE_FD
#undef FD_SETSIZE
#define FD_SETSIZE 2048
#define PYEV_MAXSTDIO 2048
#define EV_STANDALONE 1
#endif

/* embed libev */
//#include "libev/ev.c"
#include <ev.h>
#define PYEV_VERSION "0.8-0.04"
#define LIBEV_VERSION "4.04"

/*******************************************************************************
* objects
*******************************************************************************/

#ifdef MS_WINDOWS
/* avoid including socketmodule.h (not available anyway) */
typedef struct {
    PyTypeObject *Sock_Type;
    PyObject *error;
#if PY_MAJOR_VERSION >= 3 && PY_MINOR_VERSION >= 2
    PyObject *timeout_error;
#endif
} PySocketModule_APIObject;

static PySocketModule_APIObject PySocketModule;
#endif


/* Error */
static PyObject *Error;


/* Loop */
typedef struct {
    PyObject_HEAD
    ev_loop *loop;
    PyObject *callback;
    PyObject *data;
    char debug;
    double io_interval;
    double timeout_interval;
} Loop;
static PyTypeObject LoopType;

/* the 'default loop' */
static Loop *DefaultLoop = NULL;


/* Watcher - not exposed */
typedef struct {
    PyObject_HEAD
    ev_watcher *watcher;
    int type;
    Loop *loop;
    PyObject *callback;
    PyObject *data;
} Watcher;
static PyTypeObject WatcherType;


/* Io */
typedef struct {
    Watcher watcher;
    ev_io io;
} Io;
static PyTypeObject IoType;


/* Timer */
typedef struct {
    Watcher watcher;
    ev_timer timer;
} Timer;
static PyTypeObject TimerType;


#if EV_PERIODIC_ENABLE
/* PeriodicBase - not exposed */
typedef struct {
    Watcher watcher;
    ev_periodic periodic;
} PeriodicBase;
static PyTypeObject PeriodicBaseType;

/* Periodic */
typedef struct {
    PeriodicBase periodicbase;
} Periodic;
static PyTypeObject PeriodicType;

#if EV_PREPARE_ENABLE
/* Scheduler */
typedef struct {
    PeriodicBase periodicbase;
    ev_prepare prepare;
    PyObject *scheduler;
    PyObject *err_type;
    PyObject *err_value;
    PyObject *err_traceback;
    char err_fatal;
} Scheduler;
static PyTypeObject SchedulerType;
#endif
#endif


#if EV_SIGNAL_ENABLE
/* Signal */
typedef struct {
    Watcher watcher;
    ev_signal signal;
} Signal;
static PyTypeObject SignalType;
#endif


#if EV_CHILD_ENABLE
/* Child */
typedef struct {
    Watcher watcher;
    ev_child child;
} Child;
static PyTypeObject ChildType;
#endif


#if EV_STAT_ENABLE
/* Statdata */
static int StatdataType_initialized = 0;
static PyTypeObject StatdataType;

/* Stat */
typedef struct {
    Watcher watcher;
    ev_stat stat;
    PyObject *current;
    PyObject *previous;
} Stat;
static PyTypeObject StatType;
#endif


#if EV_IDLE_ENABLE
/* Idle */
typedef struct {
    Watcher watcher;
    ev_idle idle;
} Idle;
static PyTypeObject IdleType;
#endif


#if EV_PREPARE_ENABLE
/* Prepare */
typedef struct {
    Watcher watcher;
    ev_prepare prepare;
} Prepare;
static PyTypeObject PrepareType;
#endif


#if EV_CHECK_ENABLE
/* Check */
typedef struct {
    Watcher watcher;
    ev_check check;
} Check;
static PyTypeObject CheckType;
#endif


#if EV_EMBED_ENABLE
/* Embed */
typedef struct {
    Watcher watcher;
    ev_embed embed;
    Loop *other;
} Embed;
static PyTypeObject EmbedType;
#endif


#if EV_FORK_ENABLE
/* Fork */
typedef struct {
    Watcher watcher;
    ev_fork fork;
} Fork;
static PyTypeObject ForkType;
#endif


#if EV_ASYNC_ENABLE
/* Async */
typedef struct {
    Watcher watcher;
    ev_async async;
} Async;
static PyTypeObject AsyncType;
#endif


/*******************************************************************************
* utilities
*******************************************************************************/

#if PY_MAJOR_VERSION >= 3
#define PyInt_FromLong PyLong_FromLong
#define PyInt_FromUnsignedLong PyLong_FromUnsignedLong
#define PyString_FromFormat PyUnicode_FromFormat
#define PyString_FromPath PyUnicode_DecodeFSDefault
char *
PyString_AsPath(PyObject *pypath)
{
    char *path;
    PyObject *bytes;

    if (!PyUnicode_FSConverter(pypath, &bytes)) {
        return NULL;
    }
    path = PyBytes_AsString(bytes);
    Py_DECREF(bytes);
    return path;
}
#else
PyObject *
PyInt_FromUnsignedLong(unsigned long value)
{
    if (value > INT_MAX) {
        return PyLong_FromUnsignedLong(value);
    }
    return PyInt_FromLong((long)value);
}
#define PyString_FromPath PyString_FromString
#define PyString_AsPath PyString_AsString
#endif


#define PYEV_EXIT_LOOP(l) \
    do { \
        ev_break((l), EVBREAK_ALL); \
    } while (0)


#define PYEV_RETURN_BOOL(v) \
    do { \
        if ((v)) { \
            Py_RETURN_TRUE; \
        } \
        Py_RETURN_FALSE; \
    } while (0)


#define PYEV_CALLABLE_VALUE(v) \
    do { \
        if (!PyCallable_Check((v))) { \
            PyErr_SetString(PyExc_TypeError, "a callable is required"); \
            return -1; \
        } \
    } while (0)


#define PYEV_CALLABLE_OR_NONE_VALUE(v) \
    do { \
        if ((v) != Py_None && !PyCallable_Check((v))) { \
            PyErr_SetString(PyExc_TypeError, "a callable or None is required"); \
            return -1; \
        } \
    } while (0)


#define PYEV_NULL_VALUE(v) \
    do { \
        if (!(v)) { \
            PyErr_SetString(PyExc_TypeError, "cannot delete attribute"); \
            return -1; \
        } \
    } while (0)


#define PYEV_NEGATIVE_FLOAT(v) \
    do { \
        if ((v) < 0.0) { \
            PyErr_SetString(PyExc_ValueError, \
                            "a positive float or 0.0 is required"); \
            return -1; \
        } \
    } while (0)


#define PYEV_ACTIVE_WATCHER(W, m, r) \
    do { \
        if (ev_is_active((W)->watcher)) { \
            PyErr_Format(Error, \
                         "you cannot %s a watcher while it is active", (m)); \
            return (r); \
        } \
    } while (0)


#define PYEV_PENDING_WATCHER(W, m, r) \
    do { \
        if (ev_is_pending((W)->watcher)) { \
            PyErr_Format(Error, \
                         "you cannot %s a watcher while it is pending", (m)); \
            return (r); \
        } \
    } while (0)


#define PYEV_SET_ACTIVE_WATCHER(w) \
    PYEV_ACTIVE_WATCHER(((Watcher *)(w)), "set", NULL)


#endif
