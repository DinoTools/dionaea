/*
# Copyright (c) 2009 - 2013 Malek Hadj-Ali
# All rights reserved.
#
# This file is part of pyev.
#
# pyev is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3
# as published by the Free Software Foundation.
#
# pyev is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pyev.  If not, see <http://www.gnu.org/licenses/>.
*/


#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "structmember.h"

#include <ev.h>


/*******************************************************************************
* helpers
*******************************************************************************/

#if PY_MAJOR_VERSION >= 3
#define PyInt_FromLong PyLong_FromLong
#define PyInt_AsLong PyLong_AsLong
#define PyInt_FromUnsignedLong PyLong_FromUnsignedLong
#define PyString_FromFormat PyUnicode_FromFormat
#else
PyObject *
PyInt_FromUnsignedLong(unsigned long value)
{
    if (value > INT_MAX) {
        return PyLong_FromUnsignedLong(value);
    }
    return PyInt_FromLong((long)value);
}
#endif


#define PYEV_CHECK_CALLABLE(cb) \
    do { \
        if (!PyCallable_Check((cb))) { \
            PyErr_SetString(PyExc_TypeError, "a callable is required"); \
            return -1; \
        } \
    } while (0)


#define PYEV_CHECK_CALLABLE_OR_NONE(cb) \
    do { \
        if ((cb) != Py_None && !PyCallable_Check((cb))) { \
            PyErr_SetString(PyExc_TypeError, "a callable or None is required"); \
            return -1; \
        } \
    } while (0)


#define PYEV_CHECK_POSITIVE_OR_ZERO_FLOAT(v) \
    do { \
        if ((v) < 0.0) { \
            PyErr_SetString(PyExc_ValueError, \
                            "a positive float or 0.0 is required"); \
            return -1; \
        } \
    } while (0)


#define PYEV_CHECK_INT_ATTRIBUTE(v) \
    do { \
        if ((v) == -1 && PyErr_Occurred()) { \
            return -1; \
        } \
        else if ((v) > INT_MAX) { \
            PyErr_SetString(PyExc_OverflowError, \
                            "signed integer is greater than maximum"); \
            return -1; \
        } \
        else if ((v) < INT_MIN) { \
            PyErr_SetString(PyExc_OverflowError, \
                            "signed integer is less than minimum"); \
            return -1; \
        } \
    } while (0)


#define PYEV_WATCHER_CHECK_STATE(state, W, m, r) \
    do { \
        if (ev_is_##state((W)->watcher)) { \
            PyErr_Format(Error, \
                         "cannot %s a watcher while it is " #state, (m)); \
            return (r); \
        } \
    } while (0)

#define PYEV_WATCHER_CHECK_ACTIVE(W, m, r) \
    PYEV_WATCHER_CHECK_STATE(active, W, m, r)

#define PYEV_WATCHER_CHECK_PENDING(W, m, r) \
    PYEV_WATCHER_CHECK_STATE(pending, W, m, r)

#define PYEV_WATCHER_SET(W) PYEV_WATCHER_CHECK_ACTIVE(W, "set", NULL)


#define PYEV_WATCHER_START(t, w) t##_start((w)->loop->loop, (t *)(w)->watcher)
#define PYEV_WATCHER_STOP(t, w) t##_stop((w)->loop->loop, (t *)(w)->watcher)


#define PYEV_LOOP_EXIT(l) ev_break((l), EVBREAK_ALL)


#define PYEV_PROTECTED_ATTRIBUTE(v) \
    do { \
        if (!(v)) { \
            PyErr_SetString(PyExc_TypeError, "cannot delete attribute"); \
            return -1; \
        } \
    } while (0)


static int
Readonly_attribute_set(PyObject *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    PyErr_SetString(PyExc_AttributeError, "readonly attribute");
    return -1;
}


int
Boolean_Predicate(PyObject *arg, void *addr)
{
    int res = PyObject_IsTrue(arg);
    if (res < 0) {
        return 0;
    }
    *(int *)addr = res;
    return 1;
}


/*******************************************************************************
* objects
*******************************************************************************/

/* Error */
static PyObject *Error = NULL;


/* Loop */
typedef struct {
    PyObject_HEAD
    struct ev_loop *loop;
    PyObject *callback;
    PyObject *data;
    PyThreadState *tstate;
    double io_interval;
    double timeout_interval;
    int debug;
} Loop;
static PyTypeObject LoopType;

/* the 'default loop' */
static Loop *DefaultLoop = NULL;


/* Watcher base - not exposed */
typedef struct {
    PyObject_HEAD
    ev_watcher *watcher;
    Loop *loop;
    PyObject *callback;
    PyObject *data;
    int type;
} Watcher;
static PyTypeObject WatcherType;


/* Watchers */

static PyTypeObject IoType;

static PyTypeObject TimerType;

#if EV_PERIODIC_ENABLE
static PyTypeObject PeriodicBaseType;
static PyTypeObject PeriodicType;
#if EV_PREPARE_ENABLE
typedef struct {
    Watcher watcher;
    ev_prepare *prepare;
    PyObject *scheduler;
    PyObject *err_type;
    PyObject *err_value;
    PyObject *err_traceback;
    int err_fatal;
} Scheduler;
static PyTypeObject SchedulerType;
#endif
#endif

#if EV_SIGNAL_ENABLE
static PyTypeObject SignalType;
#endif

#if EV_CHILD_ENABLE
static PyTypeObject ChildType;
#endif

#if EV_IDLE_ENABLE
static PyTypeObject IdleType;
#endif

#if EV_PREPARE_ENABLE
static PyTypeObject PrepareType;
#endif

#if EV_CHECK_ENABLE
static PyTypeObject CheckType;
#endif

#if EV_EMBED_ENABLE
typedef struct {
    Watcher watcher;
    Loop *other;
} Embed;
static PyTypeObject EmbedType;
#endif

#if EV_FORK_ENABLE
static PyTypeObject ForkType;
#endif

#if EV_ASYNC_ENABLE
static PyTypeObject AsyncType;
#endif


/*******************************************************************************
* types
*******************************************************************************/

#include "Loop.c"
#include "Watcher.c"
#include "Io.c"
#include "Timer.c"

#if EV_PERIODIC_ENABLE
#include "PeriodicBase.c"
#include "Periodic.c"
#if EV_PREPARE_ENABLE
#include "Scheduler.c"
#endif
#endif

#if EV_SIGNAL_ENABLE
#include "Signal.c"
#endif

#if EV_CHILD_ENABLE
#include "Child.c"
#endif

#if EV_IDLE_ENABLE
#include "Idle.c"
#endif

#if EV_PREPARE_ENABLE
#include "Prepare.c"
#endif

#if EV_CHECK_ENABLE
#include "Check.c"
#endif

#if EV_EMBED_ENABLE
#include "Embed.c"
#endif

#if EV_FORK_ENABLE
#include "Fork.c"
#endif

#if EV_ASYNC_ENABLE
#include "Async.c"
#endif


/*******************************************************************************
 utils
*******************************************************************************/

#undef PyModule_AddIntMacro
#define PyModule_AddIntMacro(m, c) PyModule_AddIntConstant((m), #c, (int)(c))
#define PyModule_AddUnsignedIntMacro(m, c) \
    PyModule_AddIntConstant((m), #c, (unsigned int)(c))


/* allocate memory from the Python heap */
static void *
pyev_allocator(void *ptr, long size)
{
    if (size) {
        return PyMem_Realloc(ptr, size);
    }
    PyMem_Free(ptr);
    return NULL;
}


/* Add a type to a module */
int
_PyModule_AddType(PyObject *module, const char *name, PyTypeObject *type)
{
    Py_INCREF(type);
    if (PyModule_AddObject(module, name, (PyObject *)type)) {
        Py_DECREF(type);
        return -1;
    }
    return 0;
}


int
PyType_ReadyWatcher(PyTypeObject *type, PyTypeObject *base)
{
    type->tp_base = (base) ? base : &WatcherType;
    return PyType_Ready(type);
}


int
PyModule_AddType(PyObject *module, const char *name, PyTypeObject *type)
{
    if (PyType_Ready(type)) {
        return -1;
    }
    return _PyModule_AddType(module, name, type);
}


int
PyModule_AddWatcher(PyObject *module, const char *name, PyTypeObject *type,
                    PyTypeObject *base)
{
    if (PyType_ReadyWatcher(type, base)) {
        return -1;
    }
    return _PyModule_AddType(module, name, type);
}


/*******************************************************************************
 pyev_module
*******************************************************************************/

/* pyev_module.m_doc */
PyDoc_STRVAR(pyev_m_doc,
"Python libev interface.");


/* pyev.default_loop([flags=EVFLAG_AUTO, callback=None, data=None,
                      io_interval=0.0, timeout_interval=0.0, debug=False]) -> 'the default loop' */
PyDoc_STRVAR(pyev_default_loop_doc,
"default_loop([flags=EVFLAG_AUTO, callback=None, data=None,\n\
               io_interval=0.0, timeout_interval=0.0, debug=False]) -> 'the default loop'");

static PyObject *
pyev_default_loop(PyObject *module, PyObject *args, PyObject *kwargs)
{
    if (!DefaultLoop) {
        DefaultLoop = Loop_New(&LoopType, args, kwargs, 1);
    }
    else {
        if (PyErr_WarnEx(PyExc_RuntimeWarning,
                         "returning the 'default loop' created earlier, "
                         "arguments ignored (if provided).", 1)) {
            return NULL;
        }
        Py_INCREF(DefaultLoop);
    }
    return (PyObject *)DefaultLoop;
}


/* pyev.supported_backends() -> int */
PyDoc_STRVAR(pyev_supported_backends_doc,
"supported_backends() -> int");

static PyObject *
pyev_supported_backends(PyObject *module)
{
    return PyInt_FromUnsignedLong(ev_supported_backends());
}


/* pyev.recommended_backends() -> int */
PyDoc_STRVAR(pyev_recommended_backends_doc,
"recommended_backends() -> int");

static PyObject *
pyev_recommended_backends(PyObject *module)
{
    return PyInt_FromUnsignedLong(ev_recommended_backends());
}


/* pyev.embeddable_backends() -> int */
PyDoc_STRVAR(pyev_embeddable_backends_doc,
"embeddable_backends() -> int");

static PyObject *
pyev_embeddable_backends(PyObject *module)
{
    return PyInt_FromUnsignedLong(ev_embeddable_backends());
}


/* pyev.time() -> float */
PyDoc_STRVAR(pyev_time_doc,
"time() -> float");

static PyObject *
pyev_time(PyObject *module)
{
    return PyFloat_FromDouble(ev_time());
}


/* pyev.sleep(interval) */
PyDoc_STRVAR(pyev_sleep_doc,
"sleep(interval)");

static PyObject *
pyev_sleep(PyObject *module, PyObject *args)
{
    double interval;

    if (!PyArg_ParseTuple(args, "d:sleep", &interval)) {
        return NULL;
    }
    if (interval > 86400.0 &&
        PyErr_WarnEx(PyExc_RuntimeWarning,
                     "'interval' bigger than a day (86400), "
                     "this is not garanteed to work", 1)) {
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    ev_sleep(interval);
    Py_END_ALLOW_THREADS
    Py_RETURN_NONE;
}


#if EV_SIGNAL_ENABLE
/* pyev.feed_signal(signum) */
PyDoc_STRVAR(pyev_feed_signal_doc,
"feed_signal(signum)");

static PyObject *
pyev_feed_signal(PyObject *module, PyObject *args)
{
    int signum;

    if (!PyArg_ParseTuple(args, "i:feed_signal", &signum)) {
        return NULL;
    }
    ev_feed_signal(signum);
    Py_RETURN_NONE;
}
#endif


/* pyev.abi_version() -> (int, int) */
PyDoc_STRVAR(pyev_abi_version_doc,
"abi_version() -> (int, int)");

static PyObject *
pyev_abi_version(PyObject *module)
{
    return Py_BuildValue("(ii)", ev_version_major(), ev_version_minor());
}


/* pyev_module.m_methods */
static PyMethodDef pyev_m_methods[] = {
    {"default_loop", (PyCFunction)pyev_default_loop,
     METH_VARARGS | METH_KEYWORDS, pyev_default_loop_doc},
    {"supported_backends", (PyCFunction)pyev_supported_backends,
     METH_NOARGS, pyev_supported_backends_doc},
    {"recommended_backends", (PyCFunction)pyev_recommended_backends,
     METH_NOARGS, pyev_recommended_backends_doc},
    {"embeddable_backends", (PyCFunction)pyev_embeddable_backends,
     METH_NOARGS, pyev_embeddable_backends_doc},
    {"time", (PyCFunction)pyev_time,
     METH_NOARGS, pyev_time_doc},
    {"sleep", (PyCFunction)pyev_sleep,
     METH_VARARGS, pyev_sleep_doc},
#if EV_SIGNAL_ENABLE
    {"feed_signal", (PyCFunction)pyev_feed_signal,
     METH_VARARGS, pyev_feed_signal_doc},
#endif
    {"abi_version", (PyCFunction)pyev_abi_version,
     METH_NOARGS, pyev_abi_version_doc},
    {NULL} /* Sentinel */
};


#if PY_MAJOR_VERSION >= 3
/* pyev_module */
static PyModuleDef pyev_module = {
    PyModuleDef_HEAD_INIT,
    "pyev",                                   /*m_name*/
    pyev_m_doc,                               /*m_doc*/
    -1,                                       /*m_size*/
    pyev_m_methods,                           /*m_methods*/
};
#endif


/* pyev_module initialization */
PyObject *
init_pyev(void)
{
    /* pyev */
    PyObject *pyev = NULL;
#if PY_MAJOR_VERSION >= 3
    pyev = PyModule_Create(&pyev_module);
#else
    pyev = Py_InitModule3("pyev", pyev_m_methods, pyev_m_doc);
#endif
    if (!pyev) {
        return NULL;
    }
    /* pyev.__version__ */
    if (PyModule_AddStringConstant(pyev, "__version__", PYEV_VERSION)) {
        goto fail;
    }
    /* pyev.Error */
    Error = PyErr_NewException("pyev.Error", NULL, NULL);
    if (!Error || PyModule_AddObject(pyev, "Error", Error)) {
        Py_XDECREF(Error);
        goto fail;
    }
    /* types and constants */
    if (
        /* loop */
        PyModule_AddType(pyev, "Loop", &LoopType) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_AUTO) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_NOENV) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_FORKCHECK) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_SIGNALFD) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_NOSIGMASK) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_SELECT) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_POLL) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_EPOLL) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_KQUEUE) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_DEVPOLL) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_PORT) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_ALL) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_MASK) ||
        PyModule_AddIntMacro(pyev, EVRUN_NOWAIT) ||
        PyModule_AddIntMacro(pyev, EVRUN_ONCE) ||
        PyModule_AddIntMacro(pyev, EVBREAK_ONE) ||
        PyModule_AddIntMacro(pyev, EVBREAK_ALL) ||
        /* watchers */
        PyType_Ready(&WatcherType) ||
        PyModule_AddWatcher(pyev, "Io", &IoType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_READ) ||
        PyModule_AddIntMacro(pyev, EV_WRITE) ||
        PyModule_AddIntMacro(pyev, EV_IO) ||
        PyModule_AddWatcher(pyev, "Timer", &TimerType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_TIMER) ||
#if EV_PERIODIC_ENABLE
        PyType_ReadyWatcher(&PeriodicBaseType, NULL) ||
        PyModule_AddWatcher(pyev, "Periodic", &PeriodicType, &PeriodicBaseType) ||
#if EV_PREPARE_ENABLE
        PyModule_AddWatcher(pyev, "Scheduler", &SchedulerType, &PeriodicBaseType) ||
#endif
        PyModule_AddIntMacro(pyev, EV_PERIODIC) ||
#endif
#if EV_SIGNAL_ENABLE
        PyModule_AddWatcher(pyev, "Signal", &SignalType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_SIGNAL) ||
#endif
#if EV_CHILD_ENABLE
        PyModule_AddWatcher(pyev, "Child", &ChildType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_CHILD) ||
#endif
#if EV_IDLE_ENABLE
        PyModule_AddWatcher(pyev, "Idle", &IdleType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_IDLE) ||
#endif
#if EV_PREPARE_ENABLE
        PyModule_AddWatcher(pyev, "Prepare", &PrepareType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_PREPARE) ||
#endif
#if EV_CHECK_ENABLE
        PyModule_AddWatcher(pyev, "Check", &CheckType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_CHECK) ||
#endif
#if EV_EMBED_ENABLE
        PyModule_AddWatcher(pyev, "Embed", &EmbedType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_EMBED) ||
#endif
#if EV_FORK_ENABLE
        PyModule_AddWatcher(pyev, "Fork", &ForkType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_FORK) ||
#endif
#if EV_ASYNC_ENABLE
        PyModule_AddWatcher(pyev, "Async", &AsyncType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_ASYNC) ||
#endif
        /* additional events */
        PyModule_AddIntMacro(pyev, EV_CUSTOM) ||
        PyModule_AddIntMacro(pyev, EV_ERROR) ||
        /* priorities */
        PyModule_AddIntMacro(pyev, EV_MINPRI) ||
        PyModule_AddIntMacro(pyev, EV_MAXPRI)
       ) {
        goto fail;
    }
    /* setup libev */
    ev_set_allocator(pyev_allocator);
    ev_set_syserr_cb(Py_FatalError);
    return pyev;

fail:
#if PY_MAJOR_VERSION >= 3
    Py_DECREF(pyev);
#endif
    return NULL;
}


#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC
PyInit_pyev(void)
{
    return init_pyev();
}
#else
PyMODINIT_FUNC
initpyev(void)
{
    init_pyev();
}
#endif
