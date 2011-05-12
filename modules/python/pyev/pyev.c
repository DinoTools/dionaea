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


#include "pyev.h"


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
#if EV_SIGNAL_ENABLE_
#include "Signal.c"
#endif
#if EV_CHILD_ENABLE
#include "Child.c"
#endif
#if EV_STAT_ENABLE
#include "Stat.c"
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
* utilities
*******************************************************************************/

#undef PyModule_AddIntMacro
#define PyModule_AddIntMacro(m, c) \
    PyModule_AddIntConstant(m, #c, (int)c)
#define PyModule_AddUnsignedIntMacro(m, c) \
    PyModule_AddIntConstant(m, #c, (unsigned int)c)


/* Add a type to a module */
int
PyModule_AddType(PyObject *module, const char *name, PyTypeObject *type)
{
    if (PyType_Ready(type)) {
        return -1;
    }
    Py_INCREF(type);
    if (PyModule_AddObject(module, name, (PyObject *)type)) {
        Py_DECREF(type);
        return -1;
    }
    return 0;
}


/* Add a watcher to a module */
int
PyModule_AddWatcher(PyObject *module, const char *name, PyTypeObject *type,
                 PyTypeObject *base)
{
    if (base) {
        type->tp_base = base;
    }
    else {
        type->tp_base = &WatcherType;
    }
    return PyModule_AddType(module, name, type);
}


/* allocate memory from the Python heap - this is a bit messy */
static void *
pyev_allocator(void *ptr, long size)
{
#ifdef PYMALLOC_DEBUG
    PyGILState_STATE gstate = PyGILState_Ensure();
#endif
    void *result = NULL;

    if (size > 0) {
#if SIZEOF_LONG > SIZEOF_SIZE_T
        if (size <= PY_SIZE_MAX) {
            result = PyMem_Realloc(ptr, (size_t)size);
        }
#else
        result = PyMem_Realloc(ptr, (size_t)size);
#endif
    }
    else if (!size) {
        PyMem_Free(ptr);
    }
#ifdef PYMALLOC_DEBUG
    PyGILState_Release(gstate);
#endif
    return result;
}


/* syscall errors will call Py_FatalError */
static void
pyev_syserr_cb(const char *msg)
{
    PyGILState_Ensure();
    if (PyErr_Occurred()) {
        PyErr_Print();
    }
    Py_FatalError(msg);
}


#ifdef MS_WINDOWS
int
pyev_setmaxstdio(void)
{
    if (_setmaxstdio(PYEV_MAXSTDIO) != PYEV_MAXSTDIO) {
        if (errno) {
            PyErr_SetFromErrno(PyExc_WindowsError);
        }
        else {
            PyErr_SetString(PyExc_WindowsError, "_setmaxstdio failed");
        }
        return -1;
    }
    return 0;
}


int
pyev_import_socket(void)
{
    void *api;

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION < 7
    PyObject *_socket, *_socket_CAPI;
    _socket = PyImport_ImportModule("_socket");
    if (!_socket) {
        return -1;
    }
    _socket_CAPI = PyObject_GetAttrString(_socket, "CAPI");
    if (!_socket_CAPI) {
        Py_DECREF(_socket);
        return -1;
    }
    api = PyCObject_AsVoidPtr(_socket_CAPI);
    Py_DECREF(_socket_CAPI);
    Py_DECREF(_socket);
#else
    api = PyCapsule_Import("_socket.CAPI", 0);
#endif
    if (!api) {
        return -1;
    }
    memcpy(&PySocketModule, api, sizeof(PySocketModule));
    return 0;
}
#endif


/*******************************************************************************
* pyev_module
*******************************************************************************/

/* pyev_module.m_doc */
PyDoc_STRVAR(pyev_m_doc,
"Python libev interface.");


/* pyev.version() -> (str, str) */
PyDoc_STRVAR(pyev_version_doc,
"version() -> (str, str)");

static PyObject *
pyev_version(PyObject *module)
{
    return Py_BuildValue("(ss)", PYEV_VERSION, LIBEV_VERSION);
}


/* pyev.abi_version() -> (int, int) */
PyDoc_STRVAR(pyev_abi_version_doc,
"abi_version() -> (int, int)");

static PyObject *
pyev_abi_version(PyObject *module)
{
    return Py_BuildValue("(ii)", ev_version_major(), ev_version_minor());
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
    Py_BEGIN_ALLOW_THREADS
    ev_sleep(interval);
    Py_END_ALLOW_THREADS
    Py_RETURN_NONE;
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


/* pyev.default_loop([flags=EVFLAG_AUTO, callback=None, data=None, debug=False,
                      io_interval=0.0, timeout_interval=0.0]) -> 'default loop' */
PyDoc_STRVAR(pyev_default_loop_doc,
"default_loop([flags=EVFLAG_AUTO, callback=None, data=None, debug=False,\n\
               io_interval=0.0, timeout_interval=0.0]) -> 'default loop'");

static PyObject *
pyev_default_loop(PyObject *module, PyObject *args, PyObject *kwargs)
{
    if (!DefaultLoop) {
        DefaultLoop = new_Loop(&LoopType, args, kwargs, 1);
    }
    else {
        if (PyErr_WarnEx(PyExc_UserWarning,
                         "returning the 'default loop' created earlier, "
                         "arguments ignored (if provided).",
                         1)) {
            return NULL;
        }
        Py_INCREF(DefaultLoop);
    }
    return (PyObject *)DefaultLoop;
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


/* pyev_module.m_methods */
static PyMethodDef pyev_m_methods[] = {
    {"version", (PyCFunction)pyev_version,
     METH_NOARGS, pyev_version_doc},
    {"abi_version", (PyCFunction)pyev_abi_version,
     METH_NOARGS, pyev_abi_version_doc},
    {"time", (PyCFunction)pyev_time,
     METH_NOARGS, pyev_time_doc},
    {"sleep", (PyCFunction)pyev_sleep,
     METH_VARARGS, pyev_sleep_doc},
    {"supported_backends", (PyCFunction)pyev_supported_backends,
     METH_NOARGS, pyev_supported_backends_doc},
    {"recommended_backends", (PyCFunction)pyev_recommended_backends,
     METH_NOARGS, pyev_recommended_backends_doc},
    {"embeddable_backends", (PyCFunction)pyev_embeddable_backends,
     METH_NOARGS, pyev_embeddable_backends_doc},
    {"default_loop", (PyCFunction)pyev_default_loop,
     METH_VARARGS | METH_KEYWORDS, pyev_default_loop_doc},
#if EV_SIGNAL_ENABLE
    {"feed_signal", (PyCFunction)pyev_feed_signal,
     METH_VARARGS, pyev_feed_signal_doc},
#endif
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
    PyObject *pyev;

#ifdef MS_WINDOWS
    if (pyev_setmaxstdio() || pyev_import_socket()) {
        return NULL;
    }
#endif
    /* fill in deferred data addresses */
    WatcherType.tp_new = PyType_GenericNew;
#if EV_PERIODIC_ENABLE
    PeriodicBaseType.tp_base = &WatcherType;
#endif
#if EV_STAT_ENABLE
    /* init StatdataType */
    if (!StatdataType_initialized) {
        PyStructSequence_InitType(&StatdataType, &Statdata_desc);
        StatdataType_initialized = 1;
    }
#endif
    /* pyev */
#if PY_MAJOR_VERSION >= 3
    pyev = PyModule_Create(&pyev_module);
#else
    pyev = Py_InitModule3("pyev", pyev_m_methods, pyev_m_doc);
#endif
    if (!pyev) {
        return NULL;
    }
    /* pyev.Error */
    Error = PyErr_NewException("pyev.Error", NULL, NULL);
    if (!Error || PyModule_AddObject(pyev, "Error", Error)) {
        Py_XDECREF(Error);
        goto fail;
    }
    /* adding types and constants */
    if (
        /* Loop */
        PyModule_AddType(pyev, "Loop", &LoopType) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_AUTO) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_NOENV) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_FORKCHECK) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_NOINOTIFY) ||
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
        PyModule_AddIntMacro(pyev, EV_IO) ||
        PyModule_AddIntMacro(pyev, EV_READ) ||
        PyModule_AddIntMacro(pyev, EV_WRITE) ||
        PyModule_AddWatcher(pyev, "Timer", &TimerType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_TIMER) ||
#if EV_PERIODIC_ENABLE
        PyType_Ready(&PeriodicBaseType) ||
        PyModule_AddWatcher(pyev, "Periodic", &PeriodicType,
                            &PeriodicBaseType) ||
        PyModule_AddIntMacro(pyev, EV_PERIODIC) ||
#if EV_PREPARE_ENABLE
        PyModule_AddWatcher(pyev, "Scheduler", &SchedulerType,
                            &PeriodicBaseType) ||
#endif
#endif
#if EV_SIGNAL_ENABLE
        PyModule_AddWatcher(pyev, "Signal", &SignalType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_SIGNAL) ||
#endif
#if EV_CHILD_ENABLE
        PyModule_AddWatcher(pyev, "Child", &ChildType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_CHILD) ||
#endif
#if EV_STAT_ENABLE
        PyModule_AddWatcher(pyev, "Stat", &StatType, NULL) ||
        PyModule_AddIntMacro(pyev, EV_STAT) ||
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
    ev_set_syserr_cb(pyev_syserr_cb);
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
