/*******************************************************************************
*
* Copyright (c) 2009, Malek Hadj-Ali
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


#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "structmember.h"

#if 0
#ifdef NDEBUG
#undef NDEBUG
#endif /* NDEBUG */
#ifndef EV_VERIFY
#define EV_VERIFY 3
#endif /* !EV_VERIFY */
#endif

/* set EV_VERIFY for a debug build */
#ifndef EV_VERIFY
#ifdef Py_DEBUG
#ifdef NDEBUG //to be absolutely sure
#undef NDEBUG
#endif /* NDEBUG */
#define EV_VERIFY 3
#endif /* Py_DEBUG */
#endif /* !EV_VERIFY */

/* pyev requirements */
#undef EV_MULTIPLICITY
#undef EV_PERIODIC_ENABLE
#undef EV_STAT_ENABLE
#undef EV_IDLE_ENABLE
#undef EV_EMBED_ENABLE
#undef EV_FORK_ENABLE
#undef EV_ASYNC_ENABLE

#include "libev/ev.c"

#ifdef HAVE_LONG_LONG
#define PYEV_T_DEV_RDEV T_LONGLONG
#else
#define PYEV_T_DEV_RDEV T_LONG
#endif /* HAVE_LONG_LONG */

#ifdef HAVE_LARGEFILE_SUPPORT
#define PYEV_T_INO_SIZE T_LONGLONG
#else
#define PYEV_T_INO_SIZE T_LONG
#endif /* HAVE_LARGEFILE_SUPPORT */


/*******************************************************************************
* objects
*******************************************************************************/

/* Error */
static PyObject *Error;


/* Loop */
typedef struct {
    PyObject_HEAD
    struct ev_loop *loop;
    PyObject *pending_cb;
    PyObject *data;
} Loop;

/* the 'default loop' */
Loop *_DefaultLoop = NULL;


/* _Watcher - not exposed */
typedef struct {
    PyObject_HEAD
    ev_watcher *watcher;
    Loop *loop;
    PyObject *callback;
    PyObject *data;
} _Watcher;


/* Io */
typedef struct {
    _Watcher _watcher;
    ev_io io;
} Io;


/* Timer */
typedef struct {
    _Watcher _watcher;
    ev_timer timer;
} Timer;


/* Periodic */
typedef struct {
    _Watcher _watcher;
    ev_periodic periodic;
    PyObject *reschedule_cb;
} Periodic;


/* Signal */
typedef struct {
    _Watcher _watcher;
    ev_signal signal;
} Signal;


/* Child */
typedef struct {
    _Watcher _watcher;
    ev_child child;
} Child;


/* Statdata */
typedef struct {
    PyObject_HEAD
    ev_statdata statdata;
} Statdata;


/* Stat */
typedef struct {
    _Watcher _watcher;
    ev_stat stat;
    Statdata *attr;
    Statdata *prev;
} Stat;


/* Idle */
typedef struct {
    _Watcher _watcher;
    ev_idle idle;
} Idle;


/* Prepare */
typedef struct {
    _Watcher _watcher;
    ev_prepare prepare;
} Prepare;


/* Check */
typedef struct {
    _Watcher _watcher;
    ev_check check;
} Check;


/* Embed */
typedef struct {
    _Watcher _watcher;
    ev_embed embed;
    Loop *other;
} Embed;


/* Fork */
typedef struct {
    _Watcher _watcher;
    ev_fork fork;
} Fork;


/* Async */
typedef struct {
    _Watcher _watcher;
    ev_async async;
} Async;


/*******************************************************************************
* utilities
*******************************************************************************/

/* Add an unsigned integer constant to a module */
int
PyModule_AddUnsignedIntConstant(PyObject *module, const char *name,
                                unsigned long value)
{
    PyObject *object = PyLong_FromUnsignedLong(value);
    if (!object) {
        return -1;
    }

    if (PyModule_AddObject(module, name, object)) {
        Py_DECREF(object);
        return -1;
    }

    return 0;
}

/* Add an unsigned int constant to a module.
   The name and the value are taken from macro. */
#define PyModule_AddUnsignedIntMacro(module, macro) \
    PyModule_AddUnsignedIntConstant(module, #macro, macro)


/* I need to investigate how the 100 opcodes rule works out exactly for the GIL.
   Until then, better safe than sorry :). */
#define PYEV_GIL_ENSURE \
    { \
        PyGILState_STATE gstate = PyGILState_Ensure(); \
        PyObject *err_type, *err_value, *err_traceback; \
        int have_error = PyErr_Occurred() ? 1 : 0; \
        if (have_error) { \
            PyErr_Fetch(&err_type, &err_value, &err_traceback); \
        }

#define PYEV_GIL_RELEASE \
        if (have_error) { \
            PyErr_Restore(err_type, err_value, err_traceback); \
        } \
        PyGILState_Release(gstate); \
    }


/* syscall errors will call Py_FatalError */
static void
pyev_syserr(const char *msg)
{
    PyGILState_Ensure();

    if (PyErr_Occurred()) {
        PyErr_Print();
    }

    Py_FatalError(msg);
}


/* check for a positive float */
int
check_positive_float(double value)
{
    if (value < 0.0) {
        PyErr_SetString(PyExc_ValueError, "a positive float or 0.0 is required");
        return -1;
    }

    return 0;
}


/* fwd decl */
static int
Loop_pending_cb_set(Loop *self, PyObject *value, void *closure);

int
update_stat(Stat *);

static int
_Watcher_callback_set(_Watcher *self, PyObject *value, void *closure);

static int
Periodic_reschedule_cb_set(Periodic *self, PyObject *value, void *closure);


/*******************************************************************************
* LoopType
*******************************************************************************/

/* LoopType.tp_doc */
PyDoc_STRVAR(Loop_doc,
"Loop([flags, [pending_cb=None, [data=None]]])\n\
\n\
Instanciates a new event loop that is always distinct from the 'default loop'.\n\
Unlike the 'default loop', it cannot handle Child watchers, and attempts to do\n\
so will raise an exception.\n\
The recommended way to use libev with threads is indeed to create one loop per\n\
thread, and using the 'default loop' in the 'main' or 'initial' thread.\n\
The 'flags' argument can be used to specify special behaviour or specific\n\
backends to use, it defaults to EVFLAG_AUTO.\n\
If 'pending_cb' is omitted or None the loop will fall back to its default\n\
behavior of calling ev_invoke_pending() when required. If it is a callable, then\n\
the loop will execute it instead and then it becomes the user's responsibility\n\
to call Loop.pending_invoke() to invoke pending events.\n\
The 'data' argument can be used to specify any python object you might want to\n\
attach to the loop (defaults to None).\n\
\n\
See also:\n\
The documentation for ev_default_loop() in 'FUNCTIONS CONTROLLING THE EVENT\n\
LOOP' at libev documentation for more information about 'flags'.");


/* loop pending callback */
static void
loop_pending_cb(struct ev_loop *loop)
{
    PYEV_GIL_ENSURE

    Loop *_loop = ev_userdata(loop);
    PyObject *result;

    result = PyObject_CallFunctionObjArgs(_loop->pending_cb, _loop, NULL);
    if (!result) {
        ev_unloop(loop, EVUNLOOP_ALL);
    }
    else {
        Py_DECREF(result);
    }

    PYEV_GIL_RELEASE
}


/* new_loop - instanciate a Loop */
Loop *
new_loop(PyTypeObject *type, unsigned int flags, int default_loop,
         PyObject *pending_cb, PyObject *data)
{
    PyObject *tmp;

    Loop *self = (Loop *)type->tp_alloc(type, 0);
    if (!self) {
        return NULL;
    }

    /* self->loop */
    if (default_loop) {
        self->loop = ev_default_loop(flags);
    }
    else {
        self->loop = ev_loop_new(flags);
    }
    if (!self->loop) {
        PyErr_SetString(Error, "could not create Loop, bad 'flags'?");
        Py_DECREF(self);
        return NULL;
    }

    /* self->pending_cb */
    if (Loop_pending_cb_set(self, pending_cb, NULL)) {
        Py_DECREF(self);
        return NULL;
    }

    /* self->data */
    if (data) {
        tmp = self->data;
        Py_INCREF(data);
        self->data = data;
        Py_XDECREF(tmp);
    }

    ev_set_userdata(self->loop, (void *)self);

    return self;
}


/* LoopType.tp_traverse */
static int
Loop_traverse(Loop *self, visitproc visit, void *arg)
{
    Py_VISIT(self->data);
    Py_VISIT(self->pending_cb);

    return 0;
}


/* LoopType.tp_clear */
static int
Loop_clear(Loop *self)
{
    Py_CLEAR(self->data);
    Py_CLEAR(self->pending_cb);

    return 0;
}


/* LoopType.tp_dealloc */
static void
Loop_dealloc(Loop *self)
{
    Loop_clear(self);

    if (self->loop) {
        if (ev_is_default_loop(self->loop)) {
            ev_default_destroy();
            _DefaultLoop = NULL;
        }
        else {
            ev_loop_destroy(self->loop);
        }
    }

    Py_TYPE(self)->tp_free((PyObject *)self);
}


/* LoopType.tp_new */
static PyObject *
Loop_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    unsigned int flags = EVFLAG_AUTO;
    PyObject *pending_cb = Py_None;
    PyObject *data = NULL;

    static char *kwlist[] = {"flags", "pending_cb", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IOO:__new__", kwlist,
                                     &flags, &pending_cb, &data)) {
        return NULL;
    }

    return (PyObject *)new_loop(type, flags, 0, pending_cb, data);
}


/* Loop.fork() */
PyDoc_STRVAR(Loop_fork_doc,
"fork()\n\
\n\
This method sets a flag that causes subsequent loop iterations to reinitialise\n\
the kernel state for backends that have one. Despite the name, you can call it\n\
anytime, but it makes most sense after forking, in the child process (or both\n\
child and parent, but that again makes little sense). You must call it in the\n\
child before using any of the libev functions, and it will only take effect at\n\
the next loop iteration.\n\
On the other hand, you only need to call this method in the child process if and\n\
only if you want to use the event library in the child. If you just fork+exec,\n\
you don't have to call it at all.");

static PyObject *
Loop_fork(Loop *self)
{
    if (ev_is_default_loop(self->loop)) {
        ev_default_fork();
    }
    else {
        ev_loop_fork(self->loop);
    }

    Py_RETURN_NONE;
}


/* Loop.count() -> int/long */
PyDoc_STRVAR(Loop_count_doc,
"count() -> int/long\n\
\n\
Returns the count of loop iterations for the loop, which is identical to the\n\
number of times libev did poll for new events. It starts at 0 and happily wraps\n\
around with enough iterations.\n\
This value can sometimes be useful as a generation counter of sorts (it 'ticks'\n\
the number of loop iterations), as it roughly corresponds with Prepare and Check\n\
calls.");

static PyObject *
Loop_count(Loop *self)
{
    return PyLong_FromUnsignedLong(ev_loop_count(self->loop));
}


/* Loop.depth() -> int/long */
PyDoc_STRVAR(Loop_depth_doc,
"depth() -> int/long\n\
\n\
Returns the number of times Loop.loop() was entered minus the number of times\n\
Loop.loop() was exited, in other words, the recursion depth.\n\
Outside Loop.loop(), this number is zero. In a callback, this number is 1,\n\
unless Loop.loop() was invoked recursively (or from another thread), in which\n\
case it is higher.");

static PyObject *
Loop_depth(Loop *self)
{
    return PyLong_FromUnsignedLong(ev_loop_depth(self->loop));
}


/* Loop.now() -> float */
PyDoc_STRVAR(Loop_now_doc,
"now() -> float\n\
\n\
Returns the current 'event loop time', which is the time the event loop received\n\
events and started processing them. This timestamp does not change as long as\n\
callbacks are being processed, and this is also the base time used for relative\n\
timers. You can treat it as the timestamp of the event occurring (or more\n\
correctly, libev finding out about it).");

static PyObject *
Loop_now(Loop *self)
{
    return PyFloat_FromDouble(ev_now(self->loop));
}


/* Loop.now_update() */
PyDoc_STRVAR(Loop_now_update_doc,
"now_update()\n\
\n\
Establishes the current time by querying the kernel, updating the time returned\n\
by Loop.now() in the progress. This is a costly operation and is usually done\n\
automatically within Loop.loop().\n\
This function is rarely useful, but when some event callback runs for a very\n\
long time without entering the event loop, updating libev's idea of the current\n\
time is a good idea.\n\
\n\
See also:\n\
'The special problem of time updates' in the ev_timer section at libev\n\
documentation.");

static PyObject *
Loop_now_update(Loop *self)
{
    ev_now_update(self->loop);

    Py_RETURN_NONE;
}


/* Loop.suspend()
   Loop.resume() */
PyDoc_STRVAR(Loop_suspend_resume_doc,
"suspend()\n\
resume()\n\
\n\
These two methods suspend and resume a loop, for use when the loop is not used\n\
for a while and timeouts should not be processed.\n\
A typical use case would be an interactive program such as a game: When the user\n\
presses Ctrl+Z to suspend the game and resumes it an hour later it would be best\n\
to handle timeouts as if no time had actually passed while the program was\n\
suspended. This can be achieved by calling Loop.suspend() in your SIGTSTP\n\
handler, sending yourself a SIGSTOP and calling Loop.resume() directly\n\
afterwards to resume timer processing.\n\
Effectively, all Timer watchers will be delayed by the time spend between\n\
Loop.suspend() and Loop.resume(), and all Periodic watchers will be rescheduled\n\
(that is, they will lose any events that would have occured while suspended).\n\
After calling Loop.suspend() you must not call any function on the given loop\n\
other than Loop.resume(), and you must not call Loop.resume() without a previous\n\
call to Loop.suspend().\n\
Calling Loop.suspend()/Loop.resume() has the side effect of updating the event\n\
loop time (see Loop.now_update()).");

static PyObject *
Loop_suspend(Loop *self)
{
    ev_suspend(self->loop);

    Py_RETURN_NONE;
}

static PyObject *
Loop_resume(Loop *self)
{
    ev_resume(self->loop);

    Py_RETURN_NONE;
}


/* Loop.loop([flag]) */
PyDoc_STRVAR(Loop_loop_doc,
"loop([flag])\n\
\n\
This method usually is called after you have initialised all your watchers and\n\
you want to start handling events.\n\
If the 'flag' argument is omitted or specified as 0, it will not return until\n\
either no event watchers are active anymore or Loop.unloop() was called.\n\
A 'flag' value of EVLOOP_NONBLOCK will look for new events, will handle those\n\
events and any already outstanding ones, but will not block your process in case\n\
there are no events and will return after one iteration of the loop.\n\
A 'flag' value of EVLOOP_ONESHOT will look for new events (waiting if necessary)\n\
and will handle those and any already outstanding ones. It will block your\n\
process until at least one new event arrives (which could be an event internal\n\
to libev itself, so there is no guarantee that a user-registered callback will\n\
be called), and will return after one iteration of the loop. This is useful if\n\
you are waiting for some external event in conjunction with something not\n\
expressible using libev watchers. However, a pair of Prepare/Check watchers is\n\
usually a better approach for this kind of thing.\n\
\n\
Note:\n\
An explicit Loop.unloop() is usually better than relying on all watchers to be\n\
stopped when deciding when a program has finished (especially in interactive\n\
programs).");

static PyObject *
Loop_loop(Loop *self, PyObject *args)
{
    int flag = 0;

    if (!PyArg_ParseTuple(args, "|i:loop", &flag)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS

    ev_loop(self->loop, flag);

    Py_END_ALLOW_THREADS

    if (PyErr_Occurred()) {
        return NULL;
    }

    Py_RETURN_NONE;
}


/* Loop.unloop([how]) */
PyDoc_STRVAR(Loop_unloop_doc,
"unloop([how])\n\
\n\
Can be used to make a call to Loop.loop() return early (but only after it has\n\
processed all outstanding events).\n\
If the 'how' argument is omitted or specified as EVUNLOOP_ALL, it will make all\n\
nested Loop.loop() calls return.\n\
A 'how' value of EVUNLOOP_ONE will make the innermost Loop.loop() call return.\n\
This 'unloop state' will be cleared when entering Loop.loop() again.\n\
It is safe to call Loop.unloop() from otuside any Loop.loop() calls.");

static PyObject *
Loop_unloop(Loop *self, PyObject *args)
{
    int how = EVUNLOOP_ALL;

    if (!PyArg_ParseTuple(args, "|i:unloop", &how)) {
        return NULL;
    }

    ev_unloop(self->loop, how);

    Py_RETURN_NONE;
}


/* Loop.ref()
   Loop.unref() */
PyDoc_STRVAR(Loop_ref_unref_doc,
"ref()\n\
unref()\n\
\n\
ref()/unref() can be used to add or remove a reference count on the event loop:\n\
every watcher keeps one reference, and as long as the reference count is\n\
nonzero, Loop.loop() will not return on its own.\n\
If you have a watcher you never unregister that should not keep Loop.loop() from\n\
returning, call Loop.unref() after starting, and Loop.ref() before stopping it.\n\
As an example, libev itself uses this for its internal signal pipe: it is not\n\
visible to the libev user and should not keep Loop.loop() from exiting if no\n\
event watchers registered by it are active. It is also an excellent way to do\n\
this for generic recurring timers or from within third-party libraries. Just\n\
remember to Loop.unref() after start() and Loop.ref() before stop() (but only if\n\
the watcher wasn't active before, or was active before, respectively. Note also\n\
that libev might stop watchers itself (e.g. non-repeating timers) in which case\n\
you have to Loop.ref() in the callback).\n\
\n\
Note:\n\
These two methods have nothing to do with python reference counting.");

static PyObject *
Loop_ref(Loop *self)
{
    ev_ref(self->loop);

    Py_RETURN_NONE;
}

static PyObject *
Loop_unref(Loop *self)
{
    ev_unref(self->loop);

    Py_RETURN_NONE;
}


/* Loop.set_io_collect_interval(interval)
   Loop.set_timeout_collect_interval(interval) */
PyDoc_STRVAR(Loop_set_collect_interval_doc,
"set_io_collect_interval(interval)\n\
set_timeout_collect_interval(interval)\n\
\n\
These advanced methods influence the time that libev will spend waiting for\n\
events. Both time intervals are by default 0, meaning that libev will try to\n\
invoke Timer/Periodic callbacks and Io callbacks with minimum latency.\n\
Setting these to a higher value (the interval must be >= 0) allows libev to\n\
delay invocation of Io and Timer/Periodic callbacks to increase efficiency of\n\
loop iterations (or to increase power-saving opportunities).\n\
The idea is that sometimes your program runs just fast enough to handle one (or\n\
very few) event(s) per loop iteration. While this makes the program responsive,\n\
it also wastes a lot of CPU time to poll for new events, especially with\n\
backends like select which have a high overhead for the actual polling but can\n\
deliver many events at once.\n\
By setting a higher io collect interval you allow libev to spend more time\n\
collecting I/O events, so you can handle more events per iteration, at the cost\n\
of increasing latency. Timeouts (both Periodic and Timer) will be not affected.\n\
Setting this to a non-null value will introduce an additional sleep() call into\n\
most loop iterations. The sleep time ensures that libev will not poll for Io\n\
events more often then once per this interval, on average.\n\
Likewise, by setting a higher timeout collect interval you allow libev to spend\n\
more time collecting timeouts, at the expense of increased latency/jitter/\n\
inexactness (the watcher callback will be called later). Io watchers will not be\n\
affected. Setting this to a non-null value will not introduce any overhead in\n\
libev.\n\
Many (busy) programs can usually benefit by setting the io collect interval to a\n\
value near 0.1 or so, which is often enough for interactive servers (of course\n\
not for games), likewise for timeouts. It usually doesn't make much sense to set\n\
it to a lower value than 0.01, as this approaches the timing granularity of most\n\
systems. Note that if you do transactions with the outside world and you can't\n\
increase the parallelity, then this setting will limit your transaction rate (if\n\
you need to poll once per transaction and the io collect interval is 0.01, then\n\
you can't do more than 100 transations per second).\n\
Setting the timeout collect interval can improve the opportunity for saving\n\
power, as the program will 'bundle' timer callback invocations that are 'near'\n\
in time together, by delaying some, thus reducing the number of times the\n\
process sleeps and wakes up again. Another useful technique to reduce\n\
iterations/wake-ups is to use Periodic watchers and make sure they fire on, say,\n\
one-second boundaries only.");

static PyObject *
Loop_set_io_collect_interval(Loop *self, PyObject *args)
{
    double interval;

    if (!PyArg_ParseTuple(args, "d:set_io_collect_interval", &interval)) {
        return NULL;
    }

    if (check_positive_float(interval)) {
        return NULL;
    }

    ev_set_io_collect_interval(self->loop, interval);

    Py_RETURN_NONE;
}

static PyObject *
Loop_set_timeout_collect_interval(Loop *self, PyObject *args)
{
    double interval;

    if (!PyArg_ParseTuple(args, "d:set_timeout_collect_interval", &interval)) {
        return NULL;
    }

    if (check_positive_float(interval)) {
        return NULL;
    }

    ev_set_timeout_collect_interval(self->loop, interval);

    Py_RETURN_NONE;
}


/* Loop.pending_invoke() */
PyDoc_STRVAR(Loop_pending_invoke_doc,
"pending_invoke()\n\
\n\
This method will simply invoke all pending watchers while resetting their\n\
pending state. Normally, Loop.loop() does this automatically when required, but\n\
when setting the 'pending_cb' attribute this call comes in handy.");

static PyObject *
Loop_pending_invoke(Loop *self)
{
    ev_invoke_pending(self->loop);

    Py_RETURN_NONE;
}


/* Loop.pending_count() -> int/long */
PyDoc_STRVAR(Loop_pending_count_doc,
"pending_count() -> int/long\n\
\n\
Returns the number of pending watchers - zero indicates that no watchers are\n\
pending.");

static PyObject *
Loop_pending_count(Loop *self)
{
    return PyLong_FromUnsignedLong(ev_pending_count(self->loop));
}


/* Loop.verify() */
PyDoc_STRVAR(Loop_verify_doc,
"verify()\n\
\n\
This method only does something with a debug build of pyev (which needs a debug\n\
build of Python). It tries to go through all internal structures and checks them\n\
for validity. If anything is found to be inconsistent, it will print an error\n\
message to standard error and call abort().\n\
This can be used to catch bugs inside libev itself: under normal circumstances,\n\
this function should never abort.");

static PyObject *
Loop_verify(Loop *self)
{
    ev_loop_verify(self->loop);

    Py_RETURN_NONE;
}


/* LoopType.tp_methods */
static PyMethodDef Loop_methods[] = {
    {"fork", (PyCFunction)Loop_fork,
     METH_NOARGS, Loop_fork_doc},
    {"count", (PyCFunction)Loop_count,
     METH_NOARGS, Loop_count_doc},
    {"depth", (PyCFunction)Loop_depth,
     METH_NOARGS, Loop_depth_doc},
    {"now", (PyCFunction)Loop_now,
     METH_NOARGS, Loop_now_doc},
    {"now_update", (PyCFunction)Loop_now_update,
     METH_NOARGS, Loop_now_update_doc},
    {"suspend", (PyCFunction)Loop_suspend,
     METH_NOARGS, Loop_suspend_resume_doc},
    {"resume", (PyCFunction)Loop_resume,
     METH_NOARGS, Loop_suspend_resume_doc},
    {"loop", (PyCFunction)Loop_loop,
     METH_VARARGS, Loop_loop_doc},
    {"unloop", (PyCFunction)Loop_unloop,
     METH_VARARGS, Loop_unloop_doc},
    {"ref", (PyCFunction)Loop_ref,
     METH_NOARGS, Loop_ref_unref_doc},
    {"unref", (PyCFunction)Loop_unref,
     METH_NOARGS, Loop_ref_unref_doc},
    {"set_io_collect_interval", (PyCFunction)Loop_set_io_collect_interval,
     METH_VARARGS, Loop_set_collect_interval_doc},
    {"set_timeout_collect_interval",
     (PyCFunction)Loop_set_timeout_collect_interval,
     METH_VARARGS, Loop_set_collect_interval_doc},
    {"pending_invoke", (PyCFunction)Loop_pending_invoke,
     METH_NOARGS, Loop_pending_invoke_doc},
    {"pending_count", (PyCFunction)Loop_pending_count,
     METH_NOARGS, Loop_pending_count_doc},
    {"verify", (PyCFunction)Loop_verify,
     METH_NOARGS, Loop_verify_doc},
    {NULL}  /* Sentinel */
};


/* LoopType.tp_members */
static PyMemberDef Loop_members[] = {
    {"data", T_OBJECT, offsetof(Loop, data), 0,
     "loop data"},
    {NULL}  /* Sentinel */
};


/* Loop.default_loop */
PyDoc_STRVAR(Loop_default_loop_doc,
"True if this Loop is the 'default loop', False otherwise.");

static PyObject *
Loop_default_loop_get(Loop *self, void *closure)
{
    if (ev_is_default_loop(self->loop)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}


/* Loop.backend */
PyDoc_STRVAR(Loop_backend_doc,
"One of the EVBACKEND_* flags indicating the event backend in use.");

static PyObject *
Loop_backend_get(Loop *self, void *closure)
{
    return PyLong_FromUnsignedLong(ev_backend(self->loop));
}


/* Loop.pending_cb */
PyDoc_STRVAR(Loop_pending_cb_doc,
"The current invoke pending callback, its signature must be: pending_cb(loop).\n\
'loop' will be the Loop object that needs invoking pending events.\n\
If pending_cb raises an error, pyev will stop the loop.\n\
This overrides the invoke pending functionality of the loop: instead of\n\
invoking all pending watchers when there are any, Loop.loop() will call this\n\
callback instead. This is useful, for example, when you want to invoke the\n\
actual watchers inside another context (another thread etc.).\n\
If you want to reset the callback, set it to None.");

static PyObject *
Loop_pending_cb_get(Loop *self, void *closure)
{
    Py_INCREF(self->pending_cb);
    return self->pending_cb;
}

static int
Loop_pending_cb_set(Loop *self, PyObject *value, void *closure)
{
    PyObject *tmp;

    if (!value) {
        PyErr_SetString(PyExc_TypeError, "cannot delete attribute");
        return -1;
    }

    if (value != Py_None && !PyCallable_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "a callable or None is required");
        return -1;
    }

    if (value == Py_None) {
        ev_set_invoke_pending_cb(self->loop, ev_invoke_pending);
    }
    else {
        ev_set_invoke_pending_cb(self->loop, loop_pending_cb);
    }

    tmp = self->pending_cb;
    Py_INCREF(value);
    self->pending_cb = value;
    Py_XDECREF(tmp);

    return 0;
}


/* LoopType.tp_getsets */
static PyGetSetDef Loop_getsets[] = {
    {"default_loop", (getter)Loop_default_loop_get, NULL,
     Loop_default_loop_doc, NULL},
    {"backend", (getter)Loop_backend_get, NULL,
     Loop_backend_doc, NULL},
    {"pending_cb", (getter)Loop_pending_cb_get, (setter)Loop_pending_cb_set,
     Loop_pending_cb_doc, NULL},
    {NULL}  /* Sentinel */
};


/* LoopType */
static PyTypeObject LoopType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Loop",                              /*tp_name*/
    sizeof(Loop),                             /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Loop_dealloc,                 /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC, /*tp_flags*/
    Loop_doc,                                 /*tp_doc*/
    (traverseproc)Loop_traverse,              /*tp_traverse*/
    (inquiry)Loop_clear,                      /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Loop_methods,                             /*tp_methods*/
    Loop_members,                             /*tp_members*/
    Loop_getsets,                             /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    0,                                        /*tp_init*/
    0,                                        /*tp_alloc*/
    Loop_new,                                 /*tp_new*/
};


/*******************************************************************************
* _WatcherType
*******************************************************************************/

/* watcher callback */
static void
_watcher_cb(struct ev_loop *loop, ev_watcher *watcher, int events)
{
    PYEV_GIL_ENSURE

    _Watcher *_watcher = watcher->data;
    PyObject *py_result, *py_events;

    if (events & EV_ERROR) {
        if (errno) {
            // there's a high probability it is related
            PyErr_SetFromErrno(PyExc_OSError);
        }
        else {
            PyErr_SetString(Error, "unspecified libev error");
        }
        ev_unloop(loop, EVUNLOOP_ALL);
    }
    else if ((events & EV_STAT) && update_stat((Stat *)_watcher)) {
        ev_unloop(loop, EVUNLOOP_ALL);
    }
    else if (_watcher->callback != Py_None) {
        py_events = PyLong_FromUnsignedLong(events);
        if (!py_events) {
            pyev_syserr("Cannot convert int to PyLong");
        }
        else {
            py_result = PyObject_CallFunctionObjArgs(_watcher->callback,
                                                     _watcher, py_events, NULL);
            if (!py_result) {
                PyErr_WriteUnraisable(_watcher->callback);
            }
            else {
                Py_DECREF(py_result);
            }
            Py_DECREF(py_events);
        }
    }
    else if (events & EV_EMBED) {
        ev_embed_sweep(loop, (ev_embed *)watcher);
    }

    PYEV_GIL_RELEASE
}


/* set - called by subtypes before calling ev_TYPE_set */
int
set_watcher(_Watcher *self)
{
    if (ev_is_active(self->watcher)) {
        PyErr_SetString(Error, "you cannot set a watcher while it is active");
        return -1;
    }

    return 0;
}


/* _WatcherType.tp_traverse */
static int
_Watcher_traverse(_Watcher *self, visitproc visit, void *arg)
{
    Py_VISIT(self->data);
    Py_VISIT(self->callback);
    Py_VISIT(self->loop);

    return 0;
}


/* _WatcherType.tp_clear */
static int
_Watcher_clear(_Watcher *self)
{
    Py_CLEAR(self->data);
    Py_CLEAR(self->callback);
    Py_CLEAR(self->loop);

    return 0;
}


/* _WatcherType.tp_dealloc */
static void
_Watcher_dealloc(_Watcher *self)
{
    _Watcher_clear(self);

    Py_TYPE(self)->tp_free((PyObject *)self);
}


/* instanciate (sort of) the _Watcher - called by subtypes tp_new */
void
_Watcher_new(_Watcher *self, ev_watcher *watcher)
{
    /* our ev_watcher */
    self->watcher = watcher;

    /* self->watcher->data */
    self->watcher->data = (void *)self;

    /* init the watcher*/
    ev_init(self->watcher, _watcher_cb);
}


/* init the _Watcher - called by subtypes tp_init */
int
_Watcher_init(_Watcher *self, Loop *loop, PyObject *callback, PyObject *data,
              int default_loop, void *cb_closure)
{
    PyObject *tmp;

    if (set_watcher(self)) {
        return -1;
    }

    /* self->loop */
    if (!PyObject_TypeCheck(loop, &LoopType)) {
        PyErr_SetString(PyExc_TypeError, "a pyev.Loop is required");
        return -1;
    }
    else if (default_loop && !ev_is_default_loop(loop->loop)) {
        PyErr_SetString(Error, "loop must be the 'default loop'");
        return -1;
    }
    tmp = (PyObject *)self->loop;
    Py_INCREF(loop);
    self->loop = loop;
    Py_XDECREF(tmp);

    /* self->callback */
    if (_Watcher_callback_set(self, callback, cb_closure)) {
        return -1;
    }

    /* self->data */
    if (data) {
        tmp = self->data;
        Py_INCREF(data);
        self->data = data;
        Py_XDECREF(tmp);
    }

    return 0;
}


/* _Watcher.invoke(events) */
PyDoc_STRVAR(_Watcher_invoke_doc,
"invoke(events)\n\
\n\
Invoke the watcher with the given 'events'.\n\
'events' doesn't need to be valid as long as the watcher callback can deal with\n\
that fact.");

static PyObject *
_Watcher_invoke(_Watcher *self, PyObject *args)
{
    unsigned long events;

    if (!PyArg_ParseTuple(args, "k:invoke", &events)) {
        return NULL;
    }

    ev_invoke(self->loop->loop, self->watcher, events);

    Py_RETURN_NONE;
}


/* _Watcher.clear_pending() -> int/long */
PyDoc_STRVAR(_Watcher_clear_pending_doc,
"clear_pending() -> int/long\n\
\n\
If the watcher is pending, this method clears its pending status and returns its\n\
events bitset (as if its callback was invoked). If the watcher isn't pending it\n\
does nothing and returns 0.\n\
Sometimes it can be useful to 'poll' a watcher instead of waiting for its\n\
callback to be invoked, which can be accomplished with this method.");

static PyObject *
_Watcher_clear_pending(_Watcher *self)
{
    return PyLong_FromUnsignedLong(ev_clear_pending(self->loop->loop,
                                                    self->watcher));
}


/* _Watcher.start() - doc only */
PyDoc_STRVAR(_Watcher_start_doc,
"start()\n\
\n\
Starts (activates) the watcher. Only active watchers will receive events.\n\
If the watcher is already active nothing will happen.");


/* _Watcher.stop() - doc only */
PyDoc_STRVAR(_Watcher_stop_doc,
"stop()\n\
\n\
Stops the watcher if active, and clears the pending status (whether the watcher\n\
was active or not).\n\
It is possible that stopped watchers are pending - for example, non-repeating\n\
timers are being stopped when they become pending - but calling stop() ensures\n\
that the watcher is neither active nor pending.\n\
\n\
Note:\n\
Watchers are automatically stopped when they are garbage-collected.");


/* _WatcherType.tp_methods */
static PyMethodDef _Watcher_methods[] = {
    {"invoke", (PyCFunction)_Watcher_invoke,
     METH_VARARGS, _Watcher_invoke_doc},
    {"clear_pending", (PyCFunction)_Watcher_clear_pending,
     METH_NOARGS, _Watcher_clear_pending_doc},
    {NULL}  /* Sentinel */
};


/* _WatcherType.tp_members */
static PyMemberDef _Watcher_members[] = {
    {"loop", T_OBJECT_EX, offsetof(_Watcher, loop), READONLY,
     "pyev.Loop object to which this watcher is attached"},
    {"data", T_OBJECT, offsetof(_Watcher, data), 0,
     "watcher data"},
    {NULL}  /* Sentinel */
};


/* _Watcher.callback */
PyDoc_STRVAR(_Watcher_callback_doc,
"This watcher's callback. The callback is a callable whose signature must be:\n\
callback(watcher, events).\n\
The 'watcher' argument will be the python watcher object receiving the events.\n\
The 'events' argument  will be a python int/long representing ored EV_* flags\n\
corresponding to the received events.\n\
As a rule you should not let the callback return with unhandled exceptions. The\n\
loop 'does not know' what to do with an exception happening in your callback\n\
(might change in future versions, if there is a general consensus), so it will\n\
just print a warning and suppress it. If you want to act on an exception, do it\n\
in the callback (where you are allowed to do anything needed, like logging,\n\
stopping/restarting the loop, ...).");

static PyObject *
_Watcher_callback_get(_Watcher *self, void *closure)
{
    Py_INCREF(self->callback);
    return self->callback;
}

static int
_Watcher_callback_set(_Watcher *self, PyObject *value, void *closure)
{
    PyObject *tmp;

    if (!value) {
        PyErr_SetString(PyExc_TypeError, "cannot delete attribute");
        return -1;
    }

    if (closure) {
        if (value != Py_None && !PyCallable_Check(value)) {
            PyErr_SetString(PyExc_TypeError, "a callable or None is required");
            return -1;
        }
    }
    else {
        if (!PyCallable_Check(value)) {
            PyErr_SetString(PyExc_TypeError, "a callable is required");
            return -1;
        }
    }

    tmp = self->callback;
    Py_INCREF(value);
    self->callback = value;
    Py_XDECREF(tmp);

    return 0;
}


/* _Watcher.active */
PyDoc_STRVAR(_Watcher_active_doc,
"True if the watcher is active (i.e. it has been started and not yet been\n\
stopped), False otherwise.\n\
As long as a watcher is active you must not modify it.");

static PyObject *
_Watcher_active_get(_Watcher *self, void *closure)
{
    if (ev_is_active(self->watcher)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}


/* _Watcher.pending */
PyDoc_STRVAR(_Watcher_pending_doc,
"True if the watcher is pending, (i.e. it has outstanding events but its\n\
callback has not yet been invoked), False otherwise.\n\
As long as a watcher is pending (but not active) you must not change its\n\
priority.");

static PyObject *
_Watcher_pending_get(_Watcher *self, void *closure)
{
    if (ev_is_pending(self->watcher)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}


/* _Watcher.priority */
PyDoc_STRVAR(_Watcher_priority_doc,
"Set and query the priority of the watcher. The priority is a small integer\n\
between EV_MAXPRI (default: 2) and EV_MINPRI (default: -2). Pending watchers\n\
with higher priority will be invoked before watchers with lower priority, but\n\
priority will not keep watchers from being executed (except for Idle watchers).\n\
If you need to suppress invocation when higher priority events are pending you\n\
need to look at Idle watchers, which provide this functionality.\n\
You must not change the priority of a watcher as long as it is active or pending.\n\
Setting a priority outside the range of EV_MINPRI to EV_MAXPRI is fine, as long\n\
as you do not mind that the priority value you query might or might not have\n\
been clamped to the valid range.\n\
The default priority used by watchers when no priority has been set is always 0,\n\
which is supposed to not be too high and not be too low :).\n\
\n\
Note:\n\
If you want to redefine EV_MINPRI/EV_MAXPRI, you need to rebuild pyev (have a\n\
look at setup.py).\n\
\n\
See also:\n\
'WATCHER PRIORITY MODELS' at libev documentation for a more thorough treatment\n\
of priorities.");

static PyObject *
_Watcher_priority_get(_Watcher *self, void *closure)
{
    return PyLong_FromLong(ev_priority(self->watcher));
}

static int
_Watcher_priority_set(_Watcher *self, PyObject *value, void *closure)
{
    long priority;

    if (ev_is_active(self->watcher) || ev_is_pending(self->watcher)) {
        PyErr_SetString(Error, "you cannot change the 'priority' of a watcher "
                        "while it is active or pending.");
        return -1;
    }

    if (!value) {
        PyErr_SetString(PyExc_TypeError, "cannot delete attribute");
        return -1;
    }

#if PY_MAJOR_VERSION >= 3
    if (!PyLong_Check(value)) {
#else
    if (!PyInt_Check(value)) {
#endif
        PyErr_SetString(PyExc_TypeError, "an integer is required");
        return -1;
    }

    priority = PyLong_AsLong(value);
    if (priority == -1 && PyErr_Occurred()) {
        return -1;
    }

    ev_set_priority(self->watcher, priority);

    return 0;
}


/* _WatcherType.tp_getsets */
static PyGetSetDef _Watcher_getsets[] = {
    {"callback", (getter)_Watcher_callback_get, (setter)_Watcher_callback_set,
     _Watcher_callback_doc, NULL},
    {"active", (getter)_Watcher_active_get, NULL,
     _Watcher_active_doc, NULL},
    {"pending", (getter)_Watcher_pending_get, NULL,
     _Watcher_pending_doc, NULL},
    {"priority", (getter)_Watcher_priority_get, (setter)_Watcher_priority_set,
     _Watcher_priority_doc, NULL},
    {NULL}  /* Sentinel */
};


/* _WatcherType */
static PyTypeObject _WatcherType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev._Watcher",                          /*tp_name*/
    sizeof(_Watcher),                         /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)_Watcher_dealloc,             /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,  /*tp_flags*/
    0,                                        /*tp_doc*/
    (traverseproc)_Watcher_traverse,          /*tp_traverse*/
    (inquiry)_Watcher_clear,                  /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    _Watcher_methods,                         /*tp_methods*/
    _Watcher_members,                         /*tp_members*/
    _Watcher_getsets,                         /*tp_getsets*/
};


/*******************************************************************************
* IoType
*******************************************************************************/

/* IoType.tp_doc */
PyDoc_STRVAR(Io_doc,
"Io(fd, events, loop, callback, [data=None])\n\
\n\
Io watchers check whether a file descriptor is readable or writable in each\n\
iteration of the event loop, or, more precisely, when reading would not block\n\
the process and writing would at least be able to write some data. This\n\
behaviour is called level-triggering because you keep receiving events as long\n\
as the condition persists. Remember you can stop the watcher if you don't want\n\
to act on the event and neither want to receive future events.\n\
In general you can register as many read and/or write event watchers per fd as\n\
you want. Setting all file descriptors to non-blocking mode is also usually a\n\
good idea (but not required).\n\
'fd': the file descriptor to be monitored (accept socket or file objects as well\n\
int).\n\
'events': either EV_READ, EV_WRITE or EV_READ | EV_WRITE.\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_io - is this file descriptor readable or writable?' at libev documentation\n\
for more information.");


/* set the ev_io */
int
set_io(Io *self, PyObject *fd, unsigned long events)
{
    /* fd --> fdnum */
    int fdnum = PyObject_AsFileDescriptor(fd);
    if (fdnum == -1) {
        return -1;
    }

    if (events & ~(EV_READ | EV_WRITE)) {
        PyErr_SetString(Error, "illegal event mask");
        return -1;
    }

    ev_io_set(&self->io, fdnum, events);

    return 0;
}


/* IoType.tp_dealloc */
static void
Io_dealloc(Io *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    if (_watcher->loop && &self->io) {
        ev_io_stop(_watcher->loop->loop, &self->io);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* IoType.tp_new */
static PyObject *
Io_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Io *self = (Io *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->io);

    return (PyObject *)self;
}


/* IoType.tp_init */
static int
Io_init(Io *self, PyObject *args, PyObject *kwargs)
{
    PyObject *fd;
    unsigned long events;

    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"fd", "events",
                             "loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OkOO|O:__init__", kwlist,
                                     &fd, &events,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, NULL)) {
        return -1;
    }

    if (set_io(self, fd, events)) {
        return -1;
    }

    return 0;
}


/* Io.set(fd, events) */
PyDoc_STRVAR(Io_set_doc,
"set(fd, events)\n\
\n\
'fd': the file descriptor to be monitored (accept socket or file objects as well\n\
int).\n\
'events': either EV_READ, EV_WRITE or EV_READ | EV_WRITE.");

static PyObject *
Io_set(Io *self, PyObject *args)
{
    PyObject *fd;
    unsigned long events;

    if (!PyArg_ParseTuple(args, "Ok:set", &fd, &events)) {
        return NULL;
    }

    if (set_watcher((_Watcher *)self)) {
        return NULL;
    }

    if (set_io(self, fd, events)) {
        return NULL;
    }

    Py_RETURN_NONE;
}


/* Io.start() */
static PyObject *
Io_start(Io *self)
{
    ev_io_start(((_Watcher *)self)->loop->loop, &self->io);

    Py_RETURN_NONE;
}


/* Io.stop() */
static PyObject *
Io_stop(Io *self)
{
    ev_io_stop(((_Watcher *)self)->loop->loop, &self->io);

    Py_RETURN_NONE;
}


/* IoType.tp_methods */
static PyMethodDef Io_methods[] = {
    {"set", (PyCFunction)Io_set,
     METH_VARARGS, Io_set_doc},
    {"start", (PyCFunction)Io_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Io_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {NULL}  /* Sentinel */
};


/* IoType.tp_members */
static PyMemberDef Io_members[] = {
    {"fd", T_INT, offsetof(Io, io.fd), READONLY,
     "The file descriptor being watched."},
    {"events", T_ULONG, offsetof(Io, io.events), READONLY,
     "The events being watched."},
    {NULL}  /* Sentinel */
};


/* IoType */
static PyTypeObject IoType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Io",                                /*tp_name*/
    sizeof(Io),                               /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Io_dealloc,                   /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Io_doc,                                   /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Io_methods,                               /*tp_methods*/
    Io_members,                               /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Io_init,                        /*tp_init*/
    0,                                        /*tp_alloc*/
    Io_new,                                   /*tp_new*/
};


/*******************************************************************************
* TimerType
*******************************************************************************/

/* TimerType.tp_doc */
PyDoc_STRVAR(Timer_doc,
"Timer(after, repeat, loop, callback, [data=None])\n\
\n\
Timer watchers are simple relative timers that generate an event after a given\n\
time, and optionally repeating in regular intervals after that.\n\
The timers are based on real time, that is, if you register an event that times\n\
out after an hour and you reset your system clock to January last year, it will\n\
still time out after (roughly) one hour. 'Roughly' because detecting time jumps\n\
is hard, and some inaccuracies are unavoidable.\n\
The callback is guaranteed to be invoked only after its timeout has passed (not\n\
at, so on systems with very low-resolution clocks this might introduce a small\n\
delay). If multiple timers become ready during the same loop iteration then the\n\
ones with earlier time-out values are invoked before ones of the same priority\n\
with later time-out values (but this is no longer true when a callback calls\n\
Loop.loop() recursively).\n\
'after': configure the timer to trigger after after seconds.\n\
If 'repeat' is 0.0, then it will automatically be stopped once the timeout is\n\
reached. If it is positive, then the timer will automatically be configured to\n\
trigger again 'repeat' seconds later, again, and again, until stopped manually.\n\
The timer itself will do a best-effort at avoiding drift, that is, if you\n\
configure a timer to trigger every 10 seconds, then it will normally trigger at\n\
exactly 10 second intervals. If, however, your program cannot keep up with the\n\
timer (because it takes longer than those 10 seconds to do stuff) the timer will\n\
not fire more than once per event loop iteration.\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_timer - relative and optionally repeating timeouts' at libev documentation\n\
for more information, particularly the section titled 'Be smart about timeouts',\n\
for usage examples.");


/* set the ev_timer */
int
set_timer(Timer *self, double after, double repeat)
{
    if (check_positive_float(repeat)) {
        return -1;
    }

    ev_timer_set(&self->timer, after, repeat);

    return 0;
}


/* TimerType.tp_dealloc */
static void
Timer_dealloc(Timer *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    if (_watcher->loop && &self->timer) {
        ev_timer_stop(_watcher->loop->loop, &self->timer);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* TimerType.tp_new */
static PyObject *
Timer_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Timer *self = (Timer *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->timer);

    return (PyObject *)self;
}


/* TimerType.tp_init */
static int
Timer_init(Timer *self, PyObject *args, PyObject *kwargs)
{
    double after, repeat;

    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"after", "repeat",
                             "loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ddOO|O:__init__", kwlist,
                                     &after, &repeat,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, NULL)) {
        return -1;
    }

    if (set_timer(self, after, repeat)) {
        return -1;
    }

    return 0;
}


/* Timer.set(after, repeat) */
PyDoc_STRVAR(Timer_set_doc,
"set(after, repeat)\n\
\n\
'after': configure the timer to trigger after after seconds.\n\
If 'repeat' is 0.0, then it will automatically be stopped once the timeout is\n\
reached. If it is positive, then the timer will automatically be configured to\n\
trigger again 'repeat' seconds later, again, and again, until stopped manually.\n\
The timer itself will do a best-effort at avoiding drift, that is, if you\n\
configure a timer to trigger every 10 seconds, then it will normally trigger at\n\
exactly 10 second intervals. If, however, your program cannot keep up with the\n\
timer (because it takes longer than those 10 seconds to do stuff) the timer will\n\
not fire more than once per event loop iteration.");

static PyObject *
Timer_set(Timer *self, PyObject *args)
{
    double after, repeat;

    if (!PyArg_ParseTuple(args, "dd:set", &after, &repeat)) {
        return NULL;
    }

    if (set_watcher((_Watcher *)self)) {
        return NULL;
    }

    if (set_timer(self, after, repeat)) {
        return NULL;
    }

    Py_RETURN_NONE;
}


/* Timer.start() */
static PyObject *
Timer_start(Timer *self)
{
    ev_timer_start(((_Watcher *)self)->loop->loop, &self->timer);

    Py_RETURN_NONE;
}


/* Timer.stop() */
static PyObject *
Timer_stop(Timer *self)
{
    ev_timer_stop(((_Watcher *)self)->loop->loop, &self->timer);

    Py_RETURN_NONE;
}


/* Timer.again() */
PyDoc_STRVAR(Timer_again_doc,
"again()\n\
\n\
This will act as if the timer timed out and restart it again if it is repeating.\n\
The exact semantics are:\n\
If the timer is pending, its pending status is cleared.\n\
If the timer is started but non-repeating, stop it (as if it timed out).\n\
If the timer is repeating, either start it if necessary (with the repeat value),\n\
or reset the running timer to the repeat value.\n\
\n\
See also:\n\
'Be smart about timeouts' at libev documentation for a usage example.");

static PyObject *
Timer_again(Timer *self)
{
    ev_timer_again(((_Watcher *)self)->loop->loop, &self->timer);

    Py_RETURN_NONE;
}


/* Timer.remaining() -> float */
PyDoc_STRVAR(Timer_remaining_doc,
"remaining() -> float\n\
\n\
Returns the remaining time until a timer fires. If the timer is active, then\n\
this time is relative to the current event loop time, otherwise it's the timeout\n\
value currently configured.\n\
That is, after an Timer.set(5, 7), Timer.remaining() returns 5. When the timer\n\
is started and one second passes, Timer.remaining() will return 4. When the\n\
timer expires and is restarted, it will return roughly 7 (likely slightly less\n\
as callback invocation takes some time, too), and so on.");

static PyObject *
Timer_remaining(Timer *self)
{
    return PyFloat_FromDouble(ev_timer_remaining(((_Watcher *)self)->loop->loop,
                                                 &self->timer));
}


/* TimerType.tp_methods */
static PyMethodDef Timer_methods[] = {
    {"set", (PyCFunction)Timer_set,
     METH_VARARGS, Timer_set_doc},
    {"start", (PyCFunction)Timer_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Timer_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {"again", (PyCFunction)Timer_again,
     METH_NOARGS, Timer_again_doc},
    {"remaining", (PyCFunction)Timer_remaining,
     METH_NOARGS, Timer_remaining_doc},
    {NULL}  /* Sentinel */
};


/* Timer.repeat */
PyDoc_STRVAR(Timer_repeat_doc,
"The current repeat value. Will be used each time the watcher times out or\n\
Timer.again() is called, and determines the next timeout (if any), which is also\n\
when any modifications are taken into account.");

static PyObject *
Timer_repeat_get(Timer *self, void *closure)
{
    return PyFloat_FromDouble(self->timer.repeat);
}

static int
Timer_repeat_set(Timer *self, PyObject *value, void *closure)
{
    double repeat;

    if (!value) {
        PyErr_SetString(PyExc_TypeError, "cannot delete attribute");
        return -1;
    }

    if (!PyFloat_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "a float is required");
        return -1;
    }

    repeat = PyFloat_AS_DOUBLE(value);

    if (check_positive_float(repeat)) {
        return -1;
    }

    self->timer.repeat = repeat;

    return 0;
}


/* TimerType.tp_getsets */
static PyGetSetDef Timer_getsets[] = {
    {"repeat", (getter)Timer_repeat_get, (setter)Timer_repeat_set,
     Timer_repeat_doc, NULL},
    {NULL}  /* Sentinel */
};


/* TimerType */
static PyTypeObject TimerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Timer",                             /*tp_name*/
    sizeof(Timer),                            /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Timer_dealloc,                /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Timer_doc,                                /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Timer_methods,                            /*tp_methods*/
    0,                                        /*tp_members*/
    Timer_getsets,                            /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Timer_init,                     /*tp_init*/
    0,                                        /*tp_alloc*/
    Timer_new,                                /*tp_new*/
};


/*******************************************************************************
* PeriodicType
*******************************************************************************/

/* PeriodicType.tp_doc */
PyDoc_STRVAR(Periodic_doc,
"Periodic(offset, interval, reschedule_cb, loop, callback, [data=None])\n\
\n\
Periodic watchers are also timers of a kind, but they are very versatile (and\n\
unfortunately a bit complex).\n\
Unlike Timer, periodic watchers are not based on real time (or relative time,\n\
the physical time that passes) but on wall clock time (absolute time, the thing\n\
you can read on your calender or clock). The difference is that wall clock time\n\
can run faster or slower than real time, and time jumps are not uncommon (e.g.\n\
when you adjust your wrist-watch).\n\
You can tell a periodic watcher to trigger after some specific point in time:\n\
for example, if you tell a periodic watcher to trigger 'in 10 seconds' (by\n\
specifying e.g. Loop.now() + 10.0, that is, an absolute time not a delay) and\n\
then reset your system clock to January of the previous year, then it will take\n\
a year or more to trigger the event (unlike an Timer, which would still trigger\n\
roughly 10 seconds after starting it, as it uses a relative timeout).\n\
Periodic watchers can also be used to implement vastly more complex timers, such\n\
as triggering an event on each 'midnight, local time', or other complicated\n\
rules. This cannot be done with Timer watchers, as those cannot react to time\n\
jumps.\n\
As with Timers, the callback is guaranteed to be invoked only when the point in\n\
time where it is supposed to trigger has passed. If multiple timers become ready\n\
during the same loop iteration then the ones with earlier time-out values are\n\
invoked before ones with later time-out values (but this is no longer true when\n\
a callback calls Loop.loop() recursively).\n\
'offset': float.\n\
'interval': positive float or 0.0.\n\
'reschedule_cb': callable returning the next time to trigger, based on the\n\
passed time value. If 'reschedule_cb' is not needed you must set it to None.\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_periodic - to cron or not to cron?' at libev documentation for a more\n\
detailed description, you need to read it to understand the different modes of\n\
operation triggered by the arguments.");


/* periodic reschedule stop callback */
static void
periodic_reschedule_stop(struct ev_loop *loop, ev_prepare *prepare, int events)
{
    ev_periodic_stop(loop, (ev_periodic *)prepare->data);
    ev_prepare_stop(loop, prepare);

    free(prepare);
}


/* periodic reschedule callback */
static double
periodic_reschedule_cb(ev_periodic *watcher, double now)
{
    double result;

    PYEV_GIL_ENSURE

    Periodic *periodic = watcher->data;
    PyObject *py_result, *py_now;
    ev_prepare *prepare;

    py_now = PyFloat_FromDouble(now);
    if (!py_now) {
        pyev_syserr("Cannot convert double to PyFloat");
    }
    py_result = PyObject_CallFunctionObjArgs(periodic->reschedule_cb, periodic,
                                             py_now, NULL);
    if (!py_result) {
        goto error;
    }
    if (!PyFloat_Check(py_result)) {
        PyErr_SetString(PyExc_TypeError, "reschedule_cb must return a float");
        goto error;
    }
    result = PyFloat_AS_DOUBLE(py_result);
    if (result < now) {
        PyErr_SetString(Error, "returned value must be >= 'now' param");
        goto error;
    }
    goto finish;

error:
    /* inform the user we're going to stop this periodic */
    PyErr_WriteUnraisable(periodic->reschedule_cb);
    PyErr_Format(Error, "due to previous error, <pyev.Periodic object at %p> "
                 "will be stopped", periodic);
    PyErr_WriteUnraisable(periodic->reschedule_cb);

    /* start an ev_prepare watcher that will stop this periodic */
    prepare = malloc(sizeof(ev_prepare));
    if (!prepare) {
        Py_FatalError("Memory could not be allocated.");
    }
    prepare->data = (void *)watcher;
    ev_prepare_init(prepare, periodic_reschedule_stop);
    ev_prepare_start(((_Watcher *)periodic)->loop->loop, prepare);

    result = now + 1e30;

finish:
    Py_XDECREF(py_result);
    Py_XDECREF(py_now);

    PYEV_GIL_RELEASE

    return result;
}


/* set up the periodic */
int
set_periodic(Periodic *self, double offset, double interval,
             PyObject *reschedule_cb)
{
    if (check_positive_float(interval)) {
        return -1;
    }

    /* self->reschedule_cb */
    if (Periodic_reschedule_cb_set(self, reschedule_cb, (void *)1)) {
        return -1;
    }

    if (reschedule_cb != Py_None) {
        ev_periodic_set(&self->periodic, offset, interval,
                        periodic_reschedule_cb);
    }
    else{
        ev_periodic_set(&self->periodic, offset, interval, 0);
    }

    return 0;
}


/* PeriodicType.tp_traverse */
static int
Periodic_traverse(Periodic *self, visitproc visit, void *arg)
{
    Py_VISIT(self->reschedule_cb);

    return 0;
}


/* PeriodicType.tp_clear */
static int
Periodic_clear(Periodic *self)
{
    Py_CLEAR(self->reschedule_cb);

    return 0;
}


/* PeriodicType.tp_dealloc */
static void
Periodic_dealloc(Periodic *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    Periodic_clear(self);

    if (_watcher->loop && &self->periodic) {
        ev_periodic_stop(_watcher->loop->loop, &self->periodic);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* PeriodicType.tp_new */
static PyObject *
Periodic_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Periodic *self = (Periodic *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->periodic);

    return (PyObject *)self;
}


/* PeriodicType.tp_init */
static int
Periodic_init(Periodic *self, PyObject *args, PyObject *kwargs)
{
    double offset, interval;
    PyObject *reschedule_cb;

    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"offset", "interval", "reschedule_cb",
                             "loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ddOOO|O:__init__", kwlist,
                                     &offset, &interval, &reschedule_cb,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, NULL)) {
        return -1;
    }

    if (set_periodic(self, offset, interval, reschedule_cb)) {
        return -1;
    }

    return 0;
}


/* Periodic.set(offset, interval, reschedule_cb) */
PyDoc_STRVAR(Periodic_set_doc,
"set(offset, interval, reschedule_cb)\n\
\n\
'offset': float.\n\
'interval': positive float or 0.0.\n\
'reschedule_cb': callable returning the next time to trigger, based on the\n\
passed time value. If 'reschedule_cb' is not needed you must set it to None.\n\
\n\
See also:\n\
'ev_periodic - to cron or not to cron?' at libev documentation for a more\n\
detailed description, you need to read it to understand the different modes of\n\
operation triggered by the arguments.");

static PyObject *
Periodic_set(Periodic *self, PyObject *args)
{
    double offset, interval;
    PyObject *reschedule_cb;

    if (!PyArg_ParseTuple(args, "ddO:set", &offset, &interval, &reschedule_cb)) {
        return NULL;
    }

    if (set_watcher((_Watcher *)self)) {
        return NULL;
    }

    if (set_periodic(self, offset, interval, reschedule_cb)) {
        return NULL;
    }

    Py_RETURN_NONE;
}


/* Periodic.start() */
static PyObject *
Periodic_start(Periodic *self)
{
    ev_periodic_start(((_Watcher *)self)->loop->loop, &self->periodic);

    Py_RETURN_NONE;
}


/* Periodic.stop() */
static PyObject *
Periodic_stop(Periodic *self)
{
    ev_periodic_stop(((_Watcher *)self)->loop->loop, &self->periodic);

    Py_RETURN_NONE;
}


/* Periodic.again() */
PyDoc_STRVAR(Periodic_again_doc,
"again()\n\
\n\
Simply stops and restarts the Periodic watcher again. This is only useful when\n\
you changed some parameters or the reschedule callback would return a different\n\
time than the last time it was called (e.g. in a crond like program when the\n\
crontabs have changed).");

static PyObject *
Periodic_again(Periodic *self)
{
    ev_periodic_again(((_Watcher *)self)->loop->loop, &self->periodic);

    Py_RETURN_NONE;
}


/* Periodic.at() -> float */
PyDoc_STRVAR(Periodic_at_doc,
"at() -> float\n\
\n\
When active, returns the absolute time that the watcher is supposed to trigger\n\
next. This is not the same as the offset argument to Periodic.set(), but indeed\n\
works even in interval and manual rescheduling modes.");

static PyObject *
Periodic_at(Periodic *self)
{
    return PyFloat_FromDouble(ev_periodic_at(&self->periodic));
}


/* PeriodicType.tp_methods */
static PyMethodDef Periodic_methods[] = {
    {"set", (PyCFunction)Periodic_set,
     METH_VARARGS, Periodic_set_doc},
    {"start", (PyCFunction)Periodic_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Periodic_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {"again", (PyCFunction)Periodic_again,
     METH_VARARGS, Periodic_again_doc},
    {"at", (PyCFunction)Periodic_at,
     METH_VARARGS, Periodic_at_doc},
    {NULL}  /* Sentinel */
};


/* Periodic.offset - doc only */
PyDoc_STRVAR(Periodic_offset_doc,
"When repeating, this contains the offset value, otherwise this is the absolute\n\
point in time (the offset value passed to Periodic.set(), although libev might\n\
modify this value for better numerical stability). Can be modified any time, but\n\
changes only take effect when the periodic timer fires or Periodic.again() is\n\
being called.");


/* PeriodicType.tp_members */
static PyMemberDef Periodic_members[] = {
    {"offset", T_DOUBLE, offsetof(Periodic, periodic.offset), 0,
     Periodic_offset_doc},
    {NULL}  /* Sentinel */
};


/* Periodic.interval */
PyDoc_STRVAR(Periodic_interval_doc,
"The current interval value. Can be modified any time, but changes only take\n\
effect when the periodic timer fires or Periodic.again() is being called.");

static PyObject *
Periodic_interval_get(Periodic *self, void *closure)
{
    return PyFloat_FromDouble(self->periodic.interval);
}

static int
Periodic_interval_set(Periodic *self, PyObject *value, void *closure)
{
    double interval;

    if (!value) {
        PyErr_SetString(PyExc_TypeError, "cannot delete attribute");
        return -1;
    }

    if (!PyFloat_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "a float is required");
        return -1;
    }

    interval = PyFloat_AS_DOUBLE(value);

    if (check_positive_float(interval)) {
        return -1;
    }

    self->periodic.interval = interval;

    return 0;
}


/* Periodic.reschedule_cb */
PyDoc_STRVAR(Periodic_reschedule_cb_doc,
"The current reschedule callback, or None if this functionality is switched off.\n\
If given, its signature must be: reschedule_cb(periodic, now).\n\
'periodic' will be the Periodic watcher receiving the event, while 'now' will be\n\
a float indicating the time the callback has been invoked.\n\
It must return a float greater than or equal to the 'now' argument to indicate\n\
the next time the watcher callback should be scheduled.\n\
If reschedule_cb raises an error, pyev will try and stop this watcher, printing\n\
a warning in the process (this behaviour might change in future release).\n\
Can be changed any time, but changes only take effect when the periodic timer\n\
fires or Periodic.again() is being called.");

static PyObject *
Periodic_reschedule_cb_get(Periodic *self, void *closure)
{
    Py_INCREF(self->reschedule_cb);
    return self->reschedule_cb;
}

static int
Periodic_reschedule_cb_set(Periodic *self, PyObject *value, void *closure)
{
    PyObject *tmp;

    if (!value) {
        PyErr_SetString(PyExc_TypeError, "cannot delete attribute");
        return -1;
    }

    if (value != Py_None && !PyCallable_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "a callable or None is required");
        return -1;
    }

    if (!closure) {
        if (value != Py_None) {
            self->periodic.reschedule_cb = periodic_reschedule_cb;
        }
        else {
            self->periodic.reschedule_cb = 0;
        }
    }

    tmp = self->reschedule_cb;
    Py_INCREF(value);
    self->reschedule_cb = value;
    Py_XDECREF(tmp);

    return 0;
}


/* PeriodicType.tp_getsets */
static PyGetSetDef Periodic_getsets[] = {
    {"interval", (getter)Periodic_interval_get, (setter)Periodic_interval_set,
     Periodic_interval_doc, NULL},
    {"reschedule_cb", (getter)Periodic_reschedule_cb_get,
     (setter)Periodic_reschedule_cb_set,
     Periodic_reschedule_cb_doc, NULL},
    {NULL}  /* Sentinel */
};


/* PeriodicType */
static PyTypeObject PeriodicType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Periodic",                          /*tp_name*/
    sizeof(Periodic),                         /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Periodic_dealloc,             /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC, /*tp_flags*/
    Periodic_doc,                             /*tp_doc*/
    (traverseproc)Periodic_traverse,          /*tp_traverse*/
    (inquiry)Periodic_clear,                  /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Periodic_methods,                         /*tp_methods*/
    Periodic_members,                         /*tp_members*/
    Periodic_getsets,                         /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Periodic_init,                  /*tp_init*/
    0,                                        /*tp_alloc*/
    Periodic_new,                             /*tp_new*/
};


/*******************************************************************************
* SignalType
*******************************************************************************/

/* SignalType.tp_doc */
PyDoc_STRVAR(Signal_doc,
"Signal(signum, loop, callback, [data=None])\n\
\n\
Signal watchers will trigger an event when the process receives a specific\n\
signal one or more times. Even though signals are very asynchronous, libev will\n\
try it's best to deliver signals synchronously, i.e. as part of the normal event\n\
processing, like any other event.\n\
If you want signals to be delivered truly asynchronously, just use sigaction as\n\
you would do without libev and forget about sharing the signal. You can even use\n\
an Async watcher from a signal handler to synchronously wake up an event loop.\n\
You can configure as many watchers as you like for the same signal, but only\n\
within the same loop, i.e. you can watch for SIGINT in your 'default loop' and\n\
for SIGIO in another loop, but you cannot watch for SIGINT in both the 'default\n\
loop' and another loop at the same time. At the moment, SIGCHLD is permanently\n\
tied to the 'default loop'.\n\
When the first watcher gets started will libev actually register something with\n\
the kernel (thus it coexists with your own signal handlers as long as you don't\n\
register any with libev for the same signal).\n\
If possible and supported, libev will install its handlers with SA_RESTART (or\n\
equivalent) behaviour enabled, so system calls should not be unduly interrupted.\n\
If you have a problem with system calls getting interrupted by signals you can\n\
block all signals in a Check watcher and unblock them in a Prepare watcher.\n\
'signum': the signal number to be monitored (usually one of the SIG* constants).\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_signal - signal me when a signal gets signalled!' at libev documentation\n\
for more information.");


/* set the ev_signal */
int
set_signal(Signal *self, int signum)
{
    struct ev_loop *loop = ((_Watcher *)self)->loop->loop;

    if (signum <= 0 || signum >= EV_NSIG) {
        PyErr_SetString(Error, "illegal signal number");
        return -1;
    }

    if (signals[signum - 1].loop && signals[signum - 1].loop != loop) {
        PyErr_SetString(Error, "the same signal must not be attached to two "
                        "different loops");
        return -1;
    }
    signals[signum - 1].loop = loop;

    ev_signal_set(&self->signal, signum);

    return 0;
}


/* SignalType.tp_dealloc */
static void
Signal_dealloc(Signal *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    if (_watcher->loop && &self->signal) {
        ev_signal_stop(_watcher->loop->loop, &self->signal);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* SignalType.tp_new */
static PyObject *
Signal_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Signal *self = (Signal *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->signal);

    return (PyObject *)self;
}


/* SignalType.tp_init */
static int
Signal_init(Signal *self, PyObject *args, PyObject *kwargs)
{
    int signum;

    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"signum",
                             "loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iOO|O:__init__", kwlist,
                                     &signum,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, NULL)) {
        return -1;
    }

    if (set_signal(self, signum)) {
        return -1;
    }

    return 0;
}


/* Signal.set(signum) */
PyDoc_STRVAR(Signal_set_doc,
"set(signum)\n\
\n\
'signum': the signal number to be monitored (usually one of the SIG* constants).");

static PyObject *
Signal_set(Signal *self, PyObject *args)
{
    int signum;

    if (!PyArg_ParseTuple(args, "i:set", &signum)) {
        return NULL;
    }

    if (set_watcher((_Watcher *)self)) {
        return NULL;
    }

    if (set_signal(self, signum)) {
        return NULL;
    }

    Py_RETURN_NONE;
}


/* Signal.start() */
static PyObject *
Signal_start(Signal *self)
{
    ev_signal_start(((_Watcher *)self)->loop->loop, &self->signal);

    Py_RETURN_NONE;
}


/* Signal.stop() */
static PyObject *
Signal_stop(Signal *self)
{
    ev_signal_stop(((_Watcher *)self)->loop->loop, &self->signal);

    Py_RETURN_NONE;
}


/* SignalType.tp_methods */
static PyMethodDef Signal_methods[] = {
    {"set", (PyCFunction)Signal_set,
     METH_VARARGS, Signal_set_doc},
    {"start", (PyCFunction)Signal_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Signal_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {NULL}  /* Sentinel */
};


/* SignalType.tp_members */
static PyMemberDef Signal_members[] = {
    {"signum", T_INT, offsetof(Signal, signal.signum), READONLY,
     "The signal the watcher watches out for."},
    {NULL}  /* Sentinel */
};


/* SignalType */
static PyTypeObject SignalType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Signal",                            /*tp_name*/
    sizeof(Signal),                           /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Signal_dealloc,               /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Signal_doc,                               /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Signal_methods,                           /*tp_methods*/
    Signal_members,                           /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Signal_init,                    /*tp_init*/
    0,                                        /*tp_alloc*/
    Signal_new,                               /*tp_new*/
};


/*******************************************************************************
* ChildType
*******************************************************************************/

/* ChildType.tp_doc */
PyDoc_STRVAR(Child_doc,
"Child(pid, trace, loop, callback, [data=None])\n\
\n\
Child watchers trigger when your process receives a SIGCHLD in response to some\n\
child status changes (most typically when a child of yours dies or exits). It is\n\
permissible to install a child watcher after the child has been forked (which\n\
implies it might have already exited), as long as the event loop isn't entered\n\
(or is continued from a watcher), i.e., forking and then immediately registering\n\
a watcher for the child is fine, but forking and registering a watcher a few\n\
event loop iterations later or in the next callback invocation is not.\n\
You can only register Child watchers in the 'default loop'.\n\
'pid': wait for status changes of process 'pid' (or any process if 'pid' is\n\
specified as 0).\n\
'trace': if False only activate the watcher when the process terminates, if True\n\
additionally activate the watcher when the process is stopped or continued.\n\
'loop': the 'default loop'.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_child - watch out for process status changes' at libev documentation for\n\
more information.");


/* set the ev_child */
int
set_child(Child *self, int pid, PyObject *trace)
{
    if (!PyBool_Check(trace)) {
        PyErr_SetString(PyExc_TypeError, "a boolean is required");
        return -1;
    }

    ev_child_set(&self->child, pid, (trace == Py_True) ? 1 : 0);

    return 0;
}


/* ChildType.tp_dealloc */
static void
Child_dealloc(Child *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    if (_watcher->loop && &self->child) {
        ev_child_stop(_watcher->loop->loop, &self->child);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* ChildType.tp_new */
static PyObject *
Child_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Child *self = (Child *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->child);

    return (PyObject *)self;
}


/* ChildType.tp_init */
static int
Child_init(Child *self, PyObject *args, PyObject *kwargs)
{
    int pid;
    PyObject *trace;

    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"pid", "trace",
                             "loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iOOO|O:__init__", kwlist,
                                     &pid, &trace,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 1, NULL)) {
        return -1;
    }

    if (set_child(self, pid, trace)) {
        return -1;
    }

    return 0;
}


/* Child.set(pid, trace) */
PyDoc_STRVAR(Child_set_doc,
"set(pid, trace)\n\
\n\
'pid': wait for status changes of process 'pid' (or any process if 'pid' is\n\
specified as 0).\n\
'trace': if False only activate the watcher when the process terminates, if True\n\
additionally activate the watcher when the process is stopped or continued.");

static PyObject *
Child_set(Child *self, PyObject *args)
{
    int pid;
    PyObject *trace;

    if (!PyArg_ParseTuple(args, "iO:set", &pid, &trace)) {
        return NULL;
    }

    if (set_watcher((_Watcher *)self)) {
        return NULL;
    }

    if (set_child(self, pid, trace)) {
        return NULL;
    }

    Py_RETURN_NONE;
}


/* Child.start() */
static PyObject *
Child_start(Child *self)
{
    ev_child_start(((_Watcher *)self)->loop->loop, &self->child);

    Py_RETURN_NONE;
}


/* Child.stop() */
static PyObject *
Child_stop(Child *self)
{
    ev_child_stop(((_Watcher *)self)->loop->loop, &self->child);

    Py_RETURN_NONE;
}


/* ChildType.tp_methods */
static PyMethodDef Child_methods[] = {
    {"set", (PyCFunction)Child_set,
     METH_VARARGS, Child_set_doc},
    {"start", (PyCFunction)Child_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Child_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {NULL}  /* Sentinel */
};


/* ChildType.tp_members */
static PyMemberDef Child_members[] = {
    {"pid", T_INT, offsetof(Child, child.pid), READONLY,
     "The process id this watcher watches out for, or 0, meaning any process id."},
    {"rpid", T_INT, offsetof(Child, child.rpid), 0,
     "The process id that detected a status change."},
    {"rstatus", T_INT, offsetof(Child, child.rstatus), 0,
     "The process exit/trace status caused by rpid."},
    {NULL}  /* Sentinel */
};


/* ChildType */
static PyTypeObject ChildType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Child",                             /*tp_name*/
    sizeof(Child),                            /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Child_dealloc,                /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Child_doc,                                /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Child_methods,                            /*tp_methods*/
    Child_members,                            /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Child_init,                     /*tp_init*/
    0,                                        /*tp_alloc*/
    Child_new,                                /*tp_new*/
};


/*******************************************************************************
* StatdataType
*******************************************************************************/

/* new_statdata - instanciate a Statdata */
Statdata *
new_statdata(PyTypeObject *type, ev_statdata *statdata)
{
    Statdata *self;

    self = (Statdata *)type->tp_alloc(type, 0);
    if (!self) {
        return NULL;
    }

    self->statdata = *statdata;

    return self;
}


/* StatdataType.tp_dealloc */
static void
Statdata_dealloc(Statdata *self)
{
    Py_TYPE(self)->tp_free((PyObject *)self);
}


/* StatdataType.tp_members */
static PyMemberDef Statdata_members[] = {
    {"nlink", T_LONG, offsetof(Statdata, statdata.st_nlink), READONLY,
     "number of hard links"},
    {"mode", T_LONG, offsetof(Statdata, statdata.st_mode), READONLY,
     "protection bits"},
    {"uid", T_LONG, offsetof(Statdata, statdata.st_uid), READONLY,
     "user ID of owner"},
    {"gid", T_LONG, offsetof(Statdata, statdata.st_gid), READONLY,
     "group ID of owner"},
    {"atime", T_LONG, offsetof(Statdata, statdata.st_atime), READONLY,
     "time of last access"},
    {"mtime", T_LONG, offsetof(Statdata, statdata.st_mtime), READONLY,
     "time of last modification"},
    {"ctime", T_LONG, offsetof(Statdata, statdata.st_ctime), READONLY,
     "time of last status change"},
    {"dev", PYEV_T_DEV_RDEV, offsetof(Statdata, statdata.st_dev), READONLY,
     "device"},
    {"rdev", PYEV_T_DEV_RDEV, offsetof(Statdata, statdata.st_rdev), READONLY,
     "device type"},
    {"ino", PYEV_T_INO_SIZE, offsetof(Statdata, statdata.st_ino), READONLY,
     "inode"},
    {"size", PYEV_T_INO_SIZE, offsetof(Statdata, statdata.st_size), READONLY,
     "total size, in bytes"},
    {NULL}  /* Sentinel */
};


/* StatdataType */
static PyTypeObject StatdataType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Statdata",                          /*tp_name*/
    sizeof(Statdata),                         /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Statdata_dealloc,             /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,                       /*tp_flags*/
    "Statdata object",                        /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    0,                                        /*tp_methods*/
    Statdata_members,                         /*tp_members*/
};


/*******************************************************************************
* StatType
*******************************************************************************/

/* StatType.tp_doc */
PyDoc_STRVAR(Stat_doc,
"Stat(path, interval, loop, callback, [data=None])\n\
\n\
This watches a file system path for attribute changes. That is, it calls stat()\n\
on that path in regular intervals (or when the OS says it changed) and sees if\n\
it changed compared to the last time, invoking the callback if it did.\n\
The path does not need to exist: changing from 'path exists' to 'path does not\n\
exist' is a status change like any other. The condition 'path does not exist'\n\
(or more correctly 'path cannot be stated') is signified by the nlink field\n\
being zero (which is otherwise always forced to be at least one) and all the\n\
other fields of the Statdata object having unspecified contents.\n\
The path must not end in a slash or contain special components such as '.' or\n\
'..'. The path should be absolute: if it is relative and your working directory\n\
changes, then the behaviour is undefined.\n\
Since there is no portable change notification interface available, the portable\n\
implementation simply calls stat(2) regularly on the path to see if it changed\n\
somehow. You can specify a recommended polling interval for this case. If you\n\
specify a polling interval of 0 (highly recommended!) then a suitable,\n\
unspecified default value will be used (which you can expect to be around five\n\
seconds, although this might change dynamically). libev will also impose a\n\
minimum interval which is currently around 0.1, but that's usually overkill.\n\
This watcher type is not meant for massive numbers of stat watchers, as even\n\
with OS-supported change notifications, this can be resource-intensive.\n\
At the time of this writing, the only OS-specific interface implemented is the\n\
Linux inotify interface.\n\
'path': configures the watcher to wait for status changes of the given path.\n\
'interval': hint (in seconds) on how quickly a change is expected to be detected\n\
and should normally be specified as 0 to let libev choose a suitable value.\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_stat - did the file attributes just change?' at libev documentation for more\n\
information.");


/* update Stat attr and prev member */
int
update_stat(Stat *self)
{
    Statdata *attr, *tmp;

    attr = new_statdata(&StatdataType, &self->stat.attr);
    if (!attr) {
        return -1;
    }
    tmp = self->prev;
    self->prev = self->attr;
    self->attr = attr;
    Py_XDECREF(tmp);

    return 0;
}


/* StatType.tp_dealloc */
static void
Stat_dealloc(Stat *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    Py_XDECREF(self->prev);
    Py_XDECREF(self->attr);

    if (_watcher->loop && &self->stat) {
        ev_stat_stop(_watcher->loop->loop, &self->stat);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* StatType.tp_new */
static PyObject *
Stat_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Stat *self = (Stat *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->stat);

    return (PyObject *)self;
}


/* StatType.tp_init */
static int
Stat_init(Stat *self, PyObject *args, PyObject *kwargs)
{
    const char *path;
    double interval;

    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"path", "interval",
                             "loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sdOO|O:__init__", kwlist,
                                     &path, &interval,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, NULL)) {
        return -1;
    }

    ev_stat_set(&self->stat, path, interval);

    return 0;
}


/* Stat.set(path, interval) */
PyDoc_STRVAR(Stat_set_doc,
"set(path, interval)\n\
\n\
'path': configures the watcher to wait for status changes of the given path.\n\
'interval': hint (in seconds) on how quickly a change is expected to be detected\n\
and should normally be specified as 0 to let libev choose a suitable value.");

static PyObject *
Stat_set(Stat *self, PyObject *args)
{
    const char *path;
    double interval;

    if (!PyArg_ParseTuple(args, "sd:set", &path, &interval)) {
        return NULL;
    }

    if (set_watcher((_Watcher *)self)) {
        return NULL;
    }

    ev_stat_set(&self->stat, path, interval);

    Py_RETURN_NONE;
}


/* Stat.start() */
static PyObject *
Stat_start(Stat *self)
{
    ev_stat_start(((_Watcher *)self)->loop->loop, &self->stat);

    if (update_stat(self)) {
        return NULL;
    }

    Py_RETURN_NONE;
}


/* Stat.stop() */
static PyObject *
Stat_stop(Stat *self)
{
    ev_stat_stop(((_Watcher *)self)->loop->loop, &self->stat);

    Py_RETURN_NONE;
}


/* Stat.stat() */
PyDoc_STRVAR(Stat_stat_doc,
"stat()\n\
\n\
Updates Stat.attr immediately with new values. If you change the watched path in\n\
your callback, you could call this function to avoid detecting this change\n\
(while introducing a race condition if you are not the only one changing the\n\
path). Can also be useful simply to find out the new values.");

static PyObject *
Stat_stat(Stat *self)
{
    ev_stat_stat(((_Watcher *)self)->loop->loop, &self->stat);

    if (update_stat(self)) {
        return NULL;
    }

    if (self->stat.attr.st_nlink == 0) {
        return PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                                              (char *)self->stat.path);
    }

    Py_RETURN_NONE;
}


/* StatType.tp_methods */
static PyMethodDef Stat_methods[] = {
    {"set", (PyCFunction)Stat_set,
     METH_VARARGS, Stat_set_doc},
    {"start", (PyCFunction)Stat_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Stat_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {"stat", (PyCFunction)Stat_stat,
     METH_NOARGS, Stat_stat_doc},
    {NULL}  /* Sentinel */
};


/* Stat.attr - doc only */
PyDoc_STRVAR(Stat_attr_doc,
"The most-recently detected attributes of the file.\n\
If the nlink attribute is 0, then there was some error while stating the file.");


/* Stat.prev - doc only */
PyDoc_STRVAR(Stat_prev_doc,
"The previous attributes of the file.\n\
The callback gets invoked whenever Stat.prev != Stat.attr, or, more precisely,\n\
one or more of these attributes differ: dev, ino, mode, nlink, uid, gid, rdev,\n\
size, atime, mtime, ctime.");


/* StatType.tp_members */
static PyMemberDef Stat_members[] = {
    {"attr", T_OBJECT, offsetof(Stat, attr), READONLY,
     Stat_attr_doc},
    {"prev", T_OBJECT, offsetof(Stat, prev), READONLY,
     Stat_prev_doc},
    {"interval", T_DOUBLE, offsetof(Stat, stat.interval), READONLY,
     "The specified interval."},
    {"path", T_STRING, offsetof(Stat, stat.path), READONLY,
     "The file system path that is being watched."},
    {NULL}  /* Sentinel */
};


/* StatType */
static PyTypeObject StatType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Stat",                              /*tp_name*/
    sizeof(Stat),                             /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Stat_dealloc,                 /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Stat_doc,                                 /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Stat_methods,                             /*tp_methods*/
    Stat_members,                             /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Stat_init,                      /*tp_init*/
    0,                                        /*tp_alloc*/
    Stat_new,                                 /*tp_new*/
};


/*******************************************************************************
* IdleType
*******************************************************************************/

/* IdleType.tp_doc */
PyDoc_STRVAR(Idle_doc,
"Idle(loop, callback, [data=None])\n\
\n\
Idle watchers trigger events when no other events of the same or higher priority\n\
are pending (Prepare, Check and other Idle watchers do not count as receiving\n\
'events'). That is, as long as your process is busy handling sockets or timeouts\n\
(or even signals, imagine) of the same or higher priority it will not be\n\
triggered. But when your process is idle (or only lower-priority watchers are\n\
pending), the idle watchers are being called once per event loop iteration -\n\
until stopped, that is, or your process receives more events and becomes busy\n\
again with higher priority stuff.\n\
The most noteworthy effect is that as long as any idle watchers are active, the\n\
process will not block when waiting for new events. Apart from keeping your\n\
process non-blocking (which is a useful effect on its own sometimes), Idle\n\
watchers are a good place to do 'pseudo-background processing', or delay\n\
processing stuff to after the event loop has handled all outstanding events.\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_idle - when you've got nothing better to do...' at libev documentation for\n\
more information.");


/* IdleType.tp_dealloc */
static void
Idle_dealloc(Idle *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    if (_watcher->loop && &self->idle) {
        ev_idle_stop(_watcher->loop->loop, &self->idle);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* IdleType.tp_new */
static PyObject *
Idle_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Idle *self = (Idle *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->idle);

    return (PyObject *)self;
}


/* IdleType.tp_init */
static int
Idle_init(Idle *self, PyObject *args, PyObject *kwargs)
{
    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|O:__init__", kwlist,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, NULL)) {
        return -1;
    }

    return 0;
}


/* Idle.start() */
static PyObject *
Idle_start(Idle *self)
{
    ev_idle_start(((_Watcher *)self)->loop->loop, &self->idle);

    Py_RETURN_NONE;
}


/* Idle.stop() */
static PyObject *
Idle_stop(Idle *self)
{
    ev_idle_stop(((_Watcher *)self)->loop->loop, &self->idle);

    Py_RETURN_NONE;
}


/* IdleType.tp_methods */
static PyMethodDef Idle_methods[] = {
    {"start", (PyCFunction)Idle_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Idle_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {NULL}  /* Sentinel */
};


/* IdleType */
static PyTypeObject IdleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Idle",                              /*tp_name*/
    sizeof(Idle),                             /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Idle_dealloc,                 /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Idle_doc,                                 /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Idle_methods,                             /*tp_methods*/
    0,                                        /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Idle_init,                      /*tp_init*/
    0,                                        /*tp_alloc*/
    Idle_new,                                 /*tp_new*/
};


/*******************************************************************************
* PrepareType
*******************************************************************************/

/* PrepareType.tp_doc */
PyDoc_STRVAR(Prepare_doc,
"Prepare(loop, callback, [data=None])\n\
\n\
Prepare and Check watchers are usually (but not always) used in pairs: Prepare\n\
watchers get invoked before the process blocks and check watchers afterwards.\n\
You must not call Loop.loop() or similar functions that enter the current event\n\
loop from either Prepare or Check watchers callback. Other loops than the\n\
current one are fine, however. The rationale behind this is that you do not need\n\
to check for recursion in those watchers, i.e. the sequence will always be:\n\
Prepare --> blocking --> Check, so if you have one watcher of each kind they\n\
will always be called in pairs bracketing the blocking call.\n\
Their main purpose is to integrate other event mechanisms into libev and their\n\
use is somewhat advanced. They could be used, for example, to track variable\n\
changes, implement your own watchers, integrate net-snmp or a coroutine library\n\
and lots more. They are also occasionally useful if you cache some data and want\n\
to flush it before blocking.\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_prepare and ev_check - customise your event loop!' at libev documentation\n\
for more information.");


/* PrepareType.tp_dealloc */
static void
Prepare_dealloc(Prepare *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    if (_watcher->loop && &self->prepare) {
        ev_prepare_stop(_watcher->loop->loop, &self->prepare);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* PrepareType.tp_new */
static PyObject *
Prepare_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Prepare *self = (Prepare *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->prepare);

    return (PyObject *)self;
}


/* PrepareType.tp_init */
static int
Prepare_init(Prepare *self, PyObject *args, PyObject *kwargs)
{
    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|O:__init__", kwlist,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, NULL)) {
        return -1;
    }

    return 0;
}


/* Prepare.start() */
static PyObject *
Prepare_start(Prepare *self)
{
    ev_prepare_start(((_Watcher *)self)->loop->loop, &self->prepare);

    Py_RETURN_NONE;
}


/* Prepare.stop() */
static PyObject *
Prepare_stop(Prepare *self)
{
    ev_prepare_stop(((_Watcher *)self)->loop->loop, &self->prepare);

    Py_RETURN_NONE;
}


/* PrepareType.tp_methods */
static PyMethodDef Prepare_methods[] = {
    {"start", (PyCFunction)Prepare_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Prepare_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {NULL}  /* Sentinel */
};


/* PrepareType */
static PyTypeObject PrepareType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Prepare",                           /*tp_name*/
    sizeof(Prepare),                          /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Prepare_dealloc,              /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Prepare_doc,                              /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Prepare_methods,                          /*tp_methods*/
    0,                                        /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Prepare_init,                   /*tp_init*/
    0,                                        /*tp_alloc*/
    Prepare_new,                              /*tp_new*/
};


/*******************************************************************************
* CheckType
*******************************************************************************/

/* CheckType.tp_doc */
PyDoc_STRVAR(Check_doc,
"Check(loop, callback, [data=None])\n\
\n\
Prepare and Check watchers are usually (but not always) used in pairs: Prepare\n\
watchers get invoked before the process blocks and check watchers afterwards.\n\
You must not call Loop.loop() or similar functions that enter the current event\n\
loop from either Prepare or Check watchers callback. Other loops than the\n\
current one are fine, however. The rationale behind this is that you do not need\n\
to check for recursion in those watchers, i.e. the sequence will always be:\n\
Prepare --> blocking --> Check, so if you have one watcher of each kind they\n\
will always be called in pairs bracketing the blocking call.\n\
Their main purpose is to integrate other event mechanisms into libev and their\n\
use is somewhat advanced. They could be used, for example, to track variable\n\
changes, implement your own watchers, integrate net-snmp or a coroutine library\n\
and lots more. They are also occasionally useful if you cache some data and want\n\
to flush it before blocking.\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_prepare and ev_check - customise your event loop!' at libev documentation\n\
for more information.");


/* CheckType.tp_dealloc */
static void
Check_dealloc(Check *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    if (_watcher->loop && &self->check) {
        ev_check_stop(_watcher->loop->loop, &self->check);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* CheckType.tp_new */
static PyObject *
Check_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Check *self = (Check *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->check);

    return (PyObject *)self;
}


/* CheckType.tp_init */
static int
Check_init(Check *self, PyObject *args, PyObject *kwargs)
{
    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|O:__init__", kwlist,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, NULL)) {
        return -1;
    }

    return 0;
}


/* Check.start() */
static PyObject *
Check_start(Check *self)
{
    ev_check_start(((_Watcher *)self)->loop->loop, &self->check);

    Py_RETURN_NONE;
}


/* Check.stop() */
static PyObject *
Check_stop(Check *self)
{
    ev_check_stop(((_Watcher *)self)->loop->loop, &self->check);

    Py_RETURN_NONE;
}


/* CheckType.tp_methods */
static PyMethodDef Check_methods[] = {
    {"start", (PyCFunction)Check_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Check_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {NULL}  /* Sentinel */
};


/* CheckType */
static PyTypeObject CheckType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Check",                             /*tp_name*/
    sizeof(Check),                            /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Check_dealloc,                /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Check_doc,                                /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Check_methods,                            /*tp_methods*/
    0,                                        /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Check_init,                     /*tp_init*/
    0,                                        /*tp_alloc*/
    Check_new,                                /*tp_new*/
};


/*******************************************************************************
* EmbedType
*******************************************************************************/

/* EmbedType.tp_doc */
PyDoc_STRVAR(Embed_doc,
"Embed(other, loop, callback, [data=None])\n\
\n\
This is a rather advanced watcher type that lets you embed one event loop into\n\
another (currently only Io events are supported in the embedded loop, other\n\
types of watchers might be handled in a delayed or incorrect fashion and must\n\
not be used).\n\
There are primarily two reasons you would want that: work around bugs and\n\
prioritise I/O.\n\
As an example for a bug workaround, the kqueue backend might only support\n\
sockets on some platform, so it is unusable as generic backend, but you still\n\
want to make use of it because you have many sockets and it scales so nicely. In\n\
this case, you would create a kqueue-based loop and embed it into your default\n\
loop (which might use e.g. poll). Overall operation will be a bit slower because\n\
first libev has to call poll and then kevent, but at least you can use both\n\
mechanisms for what they are best: kqueue for scalable sockets and poll if you\n\
want it to work :)\n\
As for prioritising I/O: under rare circumstances you have the case where some\n\
fds have to be watched and handled very quickly (with low latency), and even\n\
priorities and Idle watchers might have too much overhead. In this case you\n\
would put all the high priority stuff in one loop and all the rest in a second\n\
one, and embed the second one in the first.\n\
'other': the pyev.Loop to embed, this loop must be embeddable (i.e. its backend\n\
must be in the set of embeddable backends).\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered. If the\n\
callback is None, then Embed.sweep() will be invoked automatically, otherwise it\n\
is the responsibility of the callback to invoke it (it will continue to be\n\
called until the sweep has been done, if you do not want that, you need to\n\
temporarily stop the Embed watcher).\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_embed - when one backend isn't enough...' at libev documentation for more\n\
information.");


/* set the ev_embed */
int
set_embed(Embed *self, Loop *other)
{
    PyObject *tmp;

    if (!PyObject_TypeCheck(other, &LoopType)) {
        PyErr_SetString(PyExc_TypeError, "a pyev.Loop is required");
        return -1;
    }

    if (!(ev_backend(other->loop) & ev_embeddable_backends())) {
        PyErr_SetString(Error, "'other' must be embeddable");
        return -1;
    }

    tmp = (PyObject *)self->other;
    Py_INCREF(other);
    self->other = other;
    Py_XDECREF(tmp);

    ev_embed_set(&self->embed, other->loop);

    return 0;
}


/* EmbedType.tp_traverse */
static int
Embed_traverse(Embed *self, visitproc visit, void *arg)
{
    Py_VISIT(self->other);

    return 0;
}


/* EmbedType.tp_clear */
static int
Embed_clear(Embed *self)
{
    Py_CLEAR(self->other);

    return 0;
}


/* EmbedType.tp_dealloc */
static void
Embed_dealloc(Embed *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    Embed_clear(self);

    if (_watcher->loop && &self->embed) {
        ev_embed_stop(_watcher->loop->loop, &self->embed);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* EmbedType.tp_new */
static PyObject *
Embed_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Embed *self = (Embed *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->embed);

    return (PyObject *)self;
}


/* EmbedType.tp_init */
static int
Embed_init(Embed *self, PyObject *args, PyObject *kwargs)
{
    Loop *other, *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"other",
                             "loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOO|O:__init__", kwlist,
                                     &other,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, (void *)1)) {
        return -1;
    }

    if (set_embed(self, other)) {
        return -1;
    }

    return 0;
}


/* Embed.set(other) */
PyDoc_STRVAR(Embed_set_doc,
"set(other)\n\
\n\
'other': the pyev.Loop to embed, this loop must be embeddable (i.e. its backend\n\
must be in the set of embeddable backends).");

static PyObject *
Embed_set(Embed *self, PyObject *args)
{
    Loop *other;

    if (!PyArg_ParseTuple(args, "O:set", &other)) {
        return NULL;
    }

    if (set_watcher((_Watcher *)self)) {
        return NULL;
    }

    if (set_embed(self, other)) {
        return NULL;
    }

    Py_RETURN_NONE;
}


/* Embed.start() */
static PyObject *
Embed_start(Embed *self)
{
    ev_embed_start(((_Watcher *)self)->loop->loop, &self->embed);

    Py_RETURN_NONE;
}


/* Embed.stop() */
static PyObject *
Embed_stop(Embed *self)
{
    ev_embed_stop(((_Watcher *)self)->loop->loop, &self->embed);

    Py_RETURN_NONE;
}


/* Embed.sweep() */
PyDoc_STRVAR(Embed_sweep_doc,
"sweep()\n\
\n\
Make a single, non-blocking sweep over the embedded loop. This works similarly\n\
to Embed.other.loop(EVLOOP_NONBLOCK), but in the most appropriate way for\n\
embedded loops.");

static PyObject *
Embed_sweep(Embed *self)
{
    ev_embed_sweep(((_Watcher *)self)->loop->loop, &self->embed);

    Py_RETURN_NONE;
}


/* EmbedType.tp_methods */
static PyMethodDef Embed_methods[] = {
    {"set", (PyCFunction)Embed_set,
     METH_VARARGS, Embed_set_doc},
    {"start", (PyCFunction)Embed_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Embed_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {"sweep", (PyCFunction)Embed_sweep,
     METH_NOARGS, Embed_sweep_doc},
    {NULL}  /* Sentinel */
};


/* EmbedType.tp_members */
static PyMemberDef Embed_members[] = {
    {"other", T_OBJECT_EX, offsetof(Embed, other), READONLY,
     "The embedded event loop."},
    {NULL}  /* Sentinel */
};


/* Embed.callback */
PyDoc_STRVAR(Embed_callback_doc,
"This watcher's callback. The callback is a callable whose signature must be:\n\
callback(watcher, events).\n\
The 'watcher' argument will be the python watcher object receiving the events.\n\
The 'events' argument  will be a python int/long representing ored EV_* flags\n\
corresponding to the received events.\n\
As a rule you should not let the callback return with unhandled exceptions. The\n\
loop 'does not know' what to do with an exception happening in your callback\n\
(might change in future versions, if there is a general consensus), so it will\n\
just print a warning and suppress it. If you want to act on an exception, do it\n\
in the callback (where you are allowed to do anything needed, like logging,\n\
stopping/restarting the loop, ...).\n\
If the callback is None, then Embed.sweep() will be invoked automatically,\n\
otherwise it is the responsibility of the callback to invoke it (it will\n\
continue to be called until the sweep has been done, if you do not want that,\n\
you need to temporarily stop the Embed watcher).");


/* EmbedType.tp_getsets */
static PyGetSetDef Embed_getsets[] = {
    {"callback", (getter)_Watcher_callback_get, (setter)_Watcher_callback_set,
     Embed_callback_doc, (void *)1},
    {NULL}  /* Sentinel */
};


/* EmbedType */
static PyTypeObject EmbedType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Embed",                             /*tp_name*/
    sizeof(Embed),                            /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Embed_dealloc,                /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC, /*tp_flags*/
    Embed_doc,                                /*tp_doc*/
    (traverseproc)Embed_traverse,             /*tp_traverse*/
    (inquiry)Embed_clear,                     /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Embed_methods,                            /*tp_methods*/
    Embed_members,                            /*tp_members*/
    Embed_getsets,                            /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Embed_init,                     /*tp_init*/
    0,                                        /*tp_alloc*/
    Embed_new,                                /*tp_new*/
};


/*******************************************************************************
* ForkType
*******************************************************************************/

/* ForkType.tp_doc */
PyDoc_STRVAR(Fork_doc,
"Fork(loop, callback, [data=None])\n\
\n\
Fork watchers are called when a fork () was detected (usually because whoever is\n\
a good citizen cared to tell libev about it by calling Loop.fork()). The\n\
invocation is done before the event loop blocks next and before Check watchers\n\
are being called, and only in the child after the fork. If whoever good citizen\n\
calling Loop.fork() cheats and calls it in the wrong process, the fork handlers\n\
will be invoked, too, of course.\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_fork - the audacity to resume the event loop after a fork' at libev\n\
documentation for more information.");


/* ForkType.tp_dealloc */
static void
Fork_dealloc(Fork *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    if (_watcher->loop && &self->fork) {
        ev_fork_stop(_watcher->loop->loop, &self->fork);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* ForkType.tp_new */
static PyObject *
Fork_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Fork *self = (Fork *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->fork);

    return (PyObject *)self;
}


/* ForkType.tp_init */
static int
Fork_init(Fork *self, PyObject *args, PyObject *kwargs)
{
    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|O:__init__", kwlist,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, NULL)) {
        return -1;
    }

    return 0;
}


/* Fork.start() */
static PyObject *
Fork_start(Fork *self)
{
    ev_fork_start(((_Watcher *)self)->loop->loop, &self->fork);

    Py_RETURN_NONE;
}


/* Fork.stop() */
static PyObject *
Fork_stop(Fork *self)
{
    ev_fork_stop(((_Watcher *)self)->loop->loop, &self->fork);

    Py_RETURN_NONE;
}


/* ForkType.tp_methods */
static PyMethodDef Fork_methods[] = {
    {"start", (PyCFunction)Fork_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Fork_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {NULL}  /* Sentinel */
};


/* ForkType */
static PyTypeObject ForkType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Fork",                              /*tp_name*/
    sizeof(Fork),                             /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Fork_dealloc,                 /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Fork_doc,                                 /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Fork_methods,                             /*tp_methods*/
    0,                                        /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Fork_init,                      /*tp_init*/
    0,                                        /*tp_alloc*/
    Fork_new,                                 /*tp_new*/
};


/*******************************************************************************
* AsyncType
*******************************************************************************/

/* AsyncType.tp_doc */
PyDoc_STRVAR(Async_doc,
"Async(loop, callback, [data=None])\n\
\n\
In general, you cannot use a Loop from multiple threads or other asynchronous\n\
sources such as signal handlers (as opposed to multiple event loops - those are\n\
of course safe to use in different threads).\n\
Sometimes, however, you need to wake up another event loop you do not control,\n\
for example because it belongs to another thread. This is what Async watchers\n\
do: as long as the Async watcher is active, you can signal it by calling\n\
Async.send(), which is thread- and signal safe.\n\
This functionality is very similar to Signal watchers, as signals, too, are\n\
asynchronous in nature, and signals, too, will be compressed (i.e. the number of\n\
callback invocations may be less than the number of Async.send() calls).\n\
'loop': a pyev.Loop object to which the watcher will be attached.\n\
'callback': a callable that will be invoked when the event is triggered.\n\
'data': any python object you might want to attach to the watcher (defaults to\n\
None).\n\
\n\
See also:\n\
'ev_async - how to wake up another event loop' at libev documentation for more\n\
information.");


/* AsyncType.tp_dealloc */
static void
Async_dealloc(Async *self)
{
    _Watcher *_watcher = (_Watcher *)self;

    if (_watcher->loop && &self->async) {
        ev_async_stop(_watcher->loop->loop, &self->async);
    }

    _WatcherType.tp_dealloc((PyObject *)self);
}


/* AsyncType.tp_new */
static PyObject *
Async_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Async *self = (Async *)_WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }

    _Watcher_new((_Watcher *)self, (ev_watcher *)&self->async);

    return (PyObject *)self;
}


/* AsyncType.tp_init */
static int
Async_init(Async *self, PyObject *args, PyObject *kwargs)
{
    Loop *loop;
    PyObject *callback;
    PyObject *data = NULL;

    static char *kwlist[] = {"loop", "callback", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|O:__init__", kwlist,
                                     &loop, &callback, &data)) {
        return -1;
    }

    if (_Watcher_init((_Watcher *)self, loop, callback, data, 0, NULL)) {
        return -1;
    }

    ev_async_set(&self->async);

    return 0;
}


/* Async.start() */
static PyObject *
Async_start(Async *self)
{
    ev_async_start(((_Watcher *)self)->loop->loop, &self->async);

    Py_RETURN_NONE;
}


/* Async.stop() */
static PyObject *
Async_stop(Async *self)
{
    ev_async_stop(((_Watcher *)self)->loop->loop, &self->async);

    Py_RETURN_NONE;
}


/* Async.send() */
PyDoc_STRVAR(Async_send_doc,
"send()\n\
\n\
Sends/signals/activates the given Async watcher, that is, feeds an EV_ASYNC\n\
event on the watcher into the event loop. This call is safe to do from other\n\
threads, signal or similar contexts.\n\
This call incurs the overhead of a system call only once per event loop\n\
iteration, so while the overhead might be noticeable, it doesn't apply to\n\
repeated calls to Async.send() for the same event loop.\n\
\n\
Note:\n\
As with other watchers in libev, multiple events might get compressed into a\n\
single callback invocation.");

static PyObject *
Async_send(Async *self)
{
    ev_async_send(((_Watcher *)self)->loop->loop, &self->async);

    Py_RETURN_NONE;
}


/* AsyncType.tp_methods */
static PyMethodDef Async_methods[] = {
    {"start", (PyCFunction)Async_start,
     METH_NOARGS, _Watcher_start_doc},
    {"stop", (PyCFunction)Async_stop,
     METH_NOARGS, _Watcher_stop_doc},
    {"send", (PyCFunction)Async_send,
     METH_NOARGS, Async_send_doc},
    {NULL}  /* Sentinel */
};


/* Async.sent */
PyDoc_STRVAR(Async_sent_doc,
"True if send() has been called on the watcher but the event has not yet been\n\
processed (or even noted) by the event loop, False otherwise.\n\
\n\
Note:\n\
This does not check whether the watcher itself is pending, only whether it has\n\
been requested to make this watcher pending.");

static PyObject *
Async_sent_get(Async *self, void *closure)
{
    if (ev_async_pending(&self->async)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}


/* AsyncType.tp_getsets */
static PyGetSetDef Async_getsets[] = {
    {"sent", (getter)Async_sent_get, NULL,
     Async_sent_doc, NULL},
    {NULL}  /* Sentinel */
};


/* AsyncType */
static PyTypeObject AsyncType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Async",                             /*tp_name*/
    sizeof(Async),                            /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Async_dealloc,                /*tp_dealloc*/
    0,                                        /*tp_print*/
    0,                                        /*tp_getattr*/
    0,                                        /*tp_setattr*/
    0,                                        /*tp_compare*/
    0,                                        /*tp_repr*/
    0,                                        /*tp_as_number*/
    0,                                        /*tp_as_sequence*/
    0,                                        /*tp_as_mapping*/
    0,                                        /*tp_hash */
    0,                                        /*tp_call*/
    0,                                        /*tp_str*/
    0,                                        /*tp_getattro*/
    0,                                        /*tp_setattro*/
    0,                                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    Async_doc,                                /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Async_methods,                            /*tp_methods*/
    0,                                        /*tp_members*/
    Async_getsets,                            /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Async_init,                     /*tp_init*/
    0,                                        /*tp_alloc*/
    Async_new,                                /*tp_new*/
};


/*******************************************************************************
* pyev_module
*******************************************************************************/

/* pyev_module.m_doc */
PyDoc_STRVAR(pyev_doc,
"Python libev interface.\n\
\n\
libev is an event loop: you register interest in certain events (such as a file\n\
descriptor being readable or a timeout occurring), and it will manage these\n\
event sources and provide your program with events.\n\
To do this, it must take more or less complete control over your process (or\n\
thread) by executing the event loop handler, and will then communicate events\n\
via a callback mechanism.\n\
You register interest in certain events by registering so-called event watchers,\n\
which you initialise with the details of the event, and then hand it over to\n\
libev by starting the watcher.\n\
libev supports select, poll, the Linux-specific epoll, the BSD-specific kqueue\n\
and the Solaris-specific event port mechanisms for file descriptor events (Io),\n\
the Linux inotify interface (for Stat), Linux eventfd/signalfd (for faster and\n\
cleaner inter-thread wakeup (Async)/signal handling (Signal)) relative timers\n\
(Timer), absolute timers with customised rescheduling (Periodic), synchronous\n\
signals (Signal), process status change events (Child), and event watchers\n\
dealing with the event loop mechanism itself (Idle, Embed, Prepare and Check\n\
watchers) as well as file watchers (Stat) and even limited support for fork\n\
events (Fork).\n\
Liveb is written and maintained by Marc Lehmann.\n\
\n\
See also:\n\
libev documentation at http://pod.tst.eu/http://cvs.schmorp.de/libev/ev.pod");


/* pyev.version() -> (str, str) */
PyDoc_STRVAR(pyev_version_doc,
"version() -> (str, str)\n\
\n\
Returns a tuple of version strings.\n\
The former is pyev version, while the latter is the underlying libev version.");

static PyObject *
pyev_version(PyObject *module)
{
    return Py_BuildValue("(ss)", PYEV_VERSION, LIBEV_VERSION);
}


/* pyev.abi_version() -> (int, int) */
PyDoc_STRVAR(pyev_abi_version_doc,
"abi_version() -> (int, int)\n\
\n\
Returns a tuple of major, minor version numbers.\n\
These numbers represent the libev ABI version that this module is running.\n\
\n\
Note:\n\
This is not the same as libev version (although it might coincide).");

static PyObject *
pyev_abi_version(PyObject *module)
{
    return Py_BuildValue("(ii)", ev_version_major(), ev_version_minor());
}


/* pyev.time() -> float */
PyDoc_STRVAR(pyev_time_doc,
"time() -> float\n\
\n\
Returns the current time as libev would use it.\n\
\n\
Note:\n\
The Loop.now() method is usually faster and also often returns the timestamp you\n\
actually want to know.");

static PyObject *
pyev_time(PyObject *module)
{
    return PyFloat_FromDouble(ev_time());
}


/* pyev.sleep(interval) */
PyDoc_STRVAR(pyev_sleep_doc,
"sleep(interval)\n\
\n\
Sleep for the given interval (in seconds).\n\
The current thread will be blocked until either it is interrupted or the given\n\
time interval has passed.");

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


/* pyev.supported_backends() -> int/long */
PyDoc_STRVAR(pyev_supported_backends_doc,
"supported_backends() -> int/long\n\
\n\
Returns the set of all backends (i.e. their corresponding EVBACKEND_* value)\n\
compiled into this binary of libev (independent of their availability on the\n\
system you are running on).\n\
\n\
See also:\n\
The documentation for ev_default_loop() in 'FUNCTIONS CONTROLLING THE EVENT\n\
LOOP' at libev documentation for a description of the set values.");

static PyObject *
pyev_supported_backends(PyObject *module)
{
    return PyLong_FromUnsignedLong(ev_supported_backends());
}


/* pyev.recommended_backends() -> int/long */
PyDoc_STRVAR(pyev_recommended_backends_doc,
"recommended_backends() -> int/long\n\
\n\
Returns the set of all backends compiled into this binary of libev and also\n\
recommended for this platform. This set is often smaller than the one returned\n\
by supported_backends(), as for example kqueue is broken on most BSDs and will\n\
not be auto-detected unless you explicitly request it. This is the set of\n\
backends that libev will probe for if you specify no backends explicitly.\n\
\n\
See also:\n\
The documentation for ev_default_loop() in 'FUNCTIONS CONTROLLING THE EVENT\n\
LOOP' at libev documentation for a description of the set values.");

static PyObject *
pyev_recommended_backends(PyObject *module)
{
    return PyLong_FromUnsignedLong(ev_recommended_backends());
}


/* pyev.embeddable_backends() -> int/long */
PyDoc_STRVAR(pyev_embeddable_backends_doc,
"embeddable_backends() -> int/long\n\
\n\
Returns the set of backends that are embeddable in other event loops. This is\n\
the theoretical, all-platform, value. To find which backends might be supported\n\
on the current system, you would need to look at\n\
embeddable_backends() & supported_backends(), likewise for recommended ones.\n\
See the description of Embed watchers for more info.\n\
\n\
See also:\n\
The documentation for ev_default_loop() in 'FUNCTIONS CONTROLLING THE EVENT\n\
LOOP' at libev documentation for a description of the set values.");

static PyObject *
pyev_embeddable_backends(PyObject *module)
{
    return PyLong_FromUnsignedLong(ev_embeddable_backends());
}


/* pyev.default_loop([flags]) -> 'default loop' */
PyDoc_STRVAR(pyev_default_loop_doc,
"default_loop([flags, [pending_cb=None, [data=None]]]) -> 'default loop'\n\
\n\
This will initialise the 'default loop' if it hasn't been initialised yet and\n\
return it. If it already was initialised it simply returns it (and ignores the\n\
arguments).\n\
The 'default loop' is the only loop that can handle Child watchers, and to do\n\
this, it always registers a handler for SIGCHLD. If this is a problem for your\n\
application you can either instanciate a Loop that doesn't do that, or you can\n\
simply overwrite the SIGCHLD signal handler.\n\
If you don't know what loop to use, use the one returned from this function.\n\
The 'flags' argument can be used to specify special behaviour or specific\n\
backends to use, it defaults to EVFLAG_AUTO.\n\
If 'pending_cb' is omitted or None the loop will fall back to its default\n\
behavior of calling ev_invoke_pending() when required. If it is a callable, then\n\
the loop will execute it instead and then it becomes the user's responsibility\n\
to call Loop.pending_invoke() to invoke pending events.\n\
The 'data' argument can be used to specify any python object you might want to\n\
attach to the loop (defaults to None).\n\
\n\
See also:\n\
The documentation for ev_default_loop() in 'FUNCTIONS CONTROLLING THE EVENT\n\
LOOP' at libev documentation for more information about 'flags'.");

static PyObject *
pyev_default_loop(PyObject *module, PyObject *args, PyObject *kwargs)
{
    unsigned int flags = EVFLAG_AUTO;
    PyObject *pending_cb = Py_None;
    PyObject *data = NULL;

    static char *kwlist[] = {"flags", "pending_cb", "data", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IOO:default_loop", kwlist,
                                     &flags, &pending_cb, &data)) {
        return NULL;
    }

    if (!_DefaultLoop) {
        _DefaultLoop = new_loop(&LoopType, flags, 1, pending_cb, data);
        if (!_DefaultLoop) {
            return NULL;
        }
    }
    else {
        if (PyErr_WarnEx(PyExc_UserWarning,
                         "returning the 'default_loop' created earlier, "
                         "arguments ignored (if provided).", 1)) {
            return NULL;
        }
        Py_INCREF(_DefaultLoop);
    }

    return (PyObject *)_DefaultLoop;
}


/* pyev_module.m_methods */
static PyMethodDef pyev_methods[] = {
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
    {NULL} /* Sentinel */
};


#if PY_MAJOR_VERSION >= 3
/* pyev_module */
static PyModuleDef pyev_module = {
    PyModuleDef_HEAD_INIT,
    "pyev",                                   /*m_name*/
    pyev_doc,                                 /*m_doc*/
    -1,                                       /*m_size*/
    pyev_methods,                             /*m_methods*/
};
#endif


/* pyev_module initialization */
PyObject *
init_pyev(void)
{
    PyObject *pyev, *__version__;

    /* fill in deferred data addresses */
    _WatcherType.tp_new = PyType_GenericNew;
    IoType.tp_base = &_WatcherType;
    TimerType.tp_base = &_WatcherType;
    PeriodicType.tp_base = &_WatcherType;
    SignalType.tp_base = &_WatcherType;
    ChildType.tp_base = &_WatcherType;
    StatType.tp_base = &_WatcherType;
    IdleType.tp_base = &_WatcherType;
    PrepareType.tp_base = &_WatcherType;
    CheckType.tp_base = &_WatcherType;
    EmbedType.tp_base = &_WatcherType;
    ForkType.tp_base = &_WatcherType;
    AsyncType.tp_base = &_WatcherType;

    /* checking types */
    if (
        PyType_Ready(&LoopType) ||
        PyType_Ready(&_WatcherType) ||
        PyType_Ready(&IoType) ||
        PyType_Ready(&TimerType) ||
        PyType_Ready(&PeriodicType) ||
        PyType_Ready(&SignalType) ||
        PyType_Ready(&ChildType) ||
        PyType_Ready(&StatdataType) ||
        PyType_Ready(&StatType) ||
        PyType_Ready(&IdleType) ||
        PyType_Ready(&PrepareType) ||
        PyType_Ready(&CheckType) ||
        PyType_Ready(&EmbedType) ||
        PyType_Ready(&ForkType) ||
        PyType_Ready(&AsyncType)
       ) {
        return NULL;
    }

    /* pyev.__version__ */
#if PY_MAJOR_VERSION >= 3
    __version__ = PyUnicode_FromFormat("%s-%s", PYEV_VERSION, LIBEV_VERSION);
#else
    __version__ = PyString_FromFormat("%s-%s", PYEV_VERSION, LIBEV_VERSION);
#endif
    if (!__version__) {
        return NULL;
    }

    /* pyev.Error object */
    Error = PyErr_NewException("pyev.Error", NULL, NULL);
    if (!Error) {
        Py_DECREF(__version__);
        return NULL;
    }

    /* pyev */
#if PY_MAJOR_VERSION >= 3
    pyev = PyModule_Create(&pyev_module);
#else
    pyev = Py_InitModule3("pyev", pyev_methods, pyev_doc);
#endif
    if (!pyev) {
        Py_DECREF(__version__);
        Py_DECREF(Error);
        return NULL;
    }

    /* adding objects and constants */
    if (
        PyModule_AddObject(pyev, "__version__", __version__) ||
        PyModule_AddObject(pyev, "Error", Error) ||

        /* types */
        PyModule_AddObject(pyev, "Loop", (PyObject *)&LoopType) ||
        PyModule_AddObject(pyev, "Io", (PyObject *)&IoType) ||
        PyModule_AddObject(pyev, "Timer", (PyObject *)&TimerType) ||
        PyModule_AddObject(pyev, "Periodic", (PyObject *)&PeriodicType) ||
        PyModule_AddObject(pyev, "Signal", (PyObject *)&SignalType) ||
        PyModule_AddObject(pyev, "Child", (PyObject *)&ChildType) ||
        PyModule_AddObject(pyev, "Stat", (PyObject *)&StatType) ||
        PyModule_AddObject(pyev, "Idle", (PyObject *)&IdleType) ||
        PyModule_AddObject(pyev, "Prepare", (PyObject *)&PrepareType) ||
        PyModule_AddObject(pyev, "Check", (PyObject *)&CheckType) ||
        PyModule_AddObject(pyev, "Embed", (PyObject *)&EmbedType) ||
        PyModule_AddObject(pyev, "Fork", (PyObject *)&ForkType) ||
        PyModule_AddObject(pyev, "Async", (PyObject *)&AsyncType) ||

        /* Loop() and default_loop() flags */
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_AUTO) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_NOENV) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_FORKCHECK) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_NOINOTIFY) ||
        PyModule_AddUnsignedIntMacro(pyev, EVFLAG_NOSIGFD) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_SELECT) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_POLL) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_EPOLL) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_KQUEUE) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_DEVPOLL) ||
        PyModule_AddUnsignedIntMacro(pyev, EVBACKEND_PORT) ||

        /* Loop.loop() flag */
        PyModule_AddIntMacro(pyev, EVLOOP_NONBLOCK) ||
        PyModule_AddIntMacro(pyev, EVLOOP_ONESHOT) ||

        /* Loop.unloop() how */
        PyModule_AddIntMacro(pyev, EVUNLOOP_ONE) ||
        PyModule_AddIntMacro(pyev, EVUNLOOP_ALL) ||

        /* priorities */
        PyModule_AddIntMacro(pyev, EV_MINPRI) ||
        PyModule_AddIntMacro(pyev, EV_MAXPRI) ||

        /* events */
        PyModule_AddUnsignedIntMacro(pyev, EV_READ) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_WRITE) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_IO) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_TIMEOUT) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_TIMER) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_PERIODIC) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_SIGNAL) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_CHILD) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_STAT) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_IDLE) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_PREPARE) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_CHECK) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_EMBED) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_FORK) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_ASYNC) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_CUSTOM) ||
        PyModule_AddUnsignedIntMacro(pyev, EV_ERROR)
       ) {
        Py_DECREF(__version__);
        Py_DECREF(Error);
        Py_DECREF(pyev);
        return NULL;
    }

    /* setup libev */
    ev_set_syserr_cb(pyev_syserr);

    return pyev;
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
