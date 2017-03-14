/*******************************************************************************
* utils
*******************************************************************************/

/* report errors or bail out if needed */
void
Loop_WarnOrStop(Loop *self, PyObject *context)
{
    if (self->debug) {
        PYEV_LOOP_EXIT(self->loop);
    }
    else {
        PyErr_WriteUnraisable(context);
    }
}


/* loop pending callback */
static void
Loop_InvokePending(struct ev_loop *loop)
{
    Loop *self = ev_userdata(loop);
    if (self->callback && self->callback != Py_None) {
        PyObject *result =
            PyObject_CallFunctionObjArgs(self->callback, self, NULL);
        if (!result) {
            PYEV_LOOP_EXIT(loop);
        }
        else {
            Py_DECREF(result);
        }
    }
    else {
        ev_invoke_pending(loop);
    }
}


static void
Loop_Release(struct ev_loop *loop)
{
    Loop *self = ev_userdata(loop);
    self->tstate = PyEval_SaveThread();
}

static void
Loop_Acquire(struct ev_loop *loop)
{
    Loop *self = ev_userdata(loop);
    PyEval_RestoreThread(self->tstate);
}


/* set invoke pending callback */
int
Loop_SetCallback(Loop *self, PyObject *callback)
{
    PYEV_CHECK_CALLABLE_OR_NONE(callback);
    PyObject *tmp = self->callback;
    Py_INCREF(callback);
    self->callback = callback;
    Py_XDECREF(tmp);
    return 0;
}


/* set collect interval */
int
Loop_SetInterval(Loop *self, double interval, int io)
{
    PYEV_CHECK_POSITIVE_OR_ZERO_FLOAT(interval);
    if (io) {
        ev_set_io_collect_interval(self->loop, interval);
        self->io_interval = interval;
    }
    else {
        ev_set_timeout_collect_interval(self->loop, interval);
        self->timeout_interval = interval;
    }
    return 0;
}


/* instanciate a Loop */
Loop *
Loop_New(PyTypeObject *type, PyObject *args, PyObject *kwargs, int default_loop)
{
    unsigned int flags = EVFLAG_AUTO;
    PyObject *callback = NULL, *data = NULL;
    double io_interval = 0.0, timeout_interval = 0.0;
    int debug = 0;

    static char *kwlist[] = {"flags",
                             "callback", "data",
                             "io_interval", "timeout_interval",
                             "debug",
                             NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IOOddO&:__new__", kwlist,
                                     &flags,
                                     &callback, &data,
                                     &io_interval, &timeout_interval,
                                     Boolean_Predicate, &debug)) {
        return NULL;
    }

    /* self */
    Loop *self = (Loop *)type->tp_alloc(type, 0);
    if (!self) {
        return NULL;
    }
    /* self->loop */
    self->loop = default_loop ? ev_default_loop(flags) : ev_loop_new(flags);
    if (!self->loop) {
        PyErr_SetString(Error, "could not create Loop, bad 'flags'?");
        Py_DECREF(self);
        return NULL;
    }
    /* self->callback */
    if (callback && Loop_SetCallback(self, callback)) {
        Py_DECREF(self);
        return NULL;
    }
    /* self->data */
    Py_XINCREF(data);
    self->data = data;
    /* self->tstate */
    self->tstate = NULL;
    /* self->io_interval and self->timeout_interval */
    if (Loop_SetInterval(self, io_interval, 1) ||
        Loop_SetInterval(self, timeout_interval, 0)) {
        Py_DECREF(self);
        return NULL;
    }
    /* self->debug */
    self->debug = debug;
    /* done */
    ev_set_userdata(self->loop, self);
    ev_set_invoke_pending_cb(self->loop, Loop_InvokePending);
    ev_set_loop_release_cb (self->loop, Loop_Release, Loop_Acquire);
    return self;
}


/*******************************************************************************
* LoopType
*******************************************************************************/

/* LoopType.tp_doc */
PyDoc_STRVAR(Loop_tp_doc,
"Loop([flags=EVFLAG_AUTO, callback=None, data=None,\n\
       io_interval=0.0, timeout_interval=0.0, debug=False])");


/* LoopType.tp_traverse */
static int
Loop_tp_traverse(Loop *self, visitproc visit, void *arg)
{
    Py_VISIT(self->data);
    Py_VISIT(self->callback);
    return 0;
}


/* LoopType.tp_clear */
static int
Loop_tp_clear(Loop *self)
{
    Py_CLEAR(self->data);
    Py_CLEAR(self->callback);
    return 0;
}


/* LoopType.tp_dealloc */
static void
Loop_tp_dealloc(Loop *self)
{
    Loop_tp_clear(self);
    if (self->loop) {
        PYEV_LOOP_EXIT(self->loop);
        if (ev_is_default_loop(self->loop)) {
            DefaultLoop = NULL;
        }
        ev_loop_destroy(self->loop);
        self->loop = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
}


/* Loop.start([flags]) -> bool */
PyDoc_STRVAR(Loop_start_doc,
"start([flags]) -> bool");

static PyObject *
Loop_start(Loop *self, PyObject *args)
{
    int flags = 0;

    if (!PyArg_ParseTuple(args, "|i:start", &flags)) {
        return NULL;
    }
    int result = ev_run(self->loop, flags);
    if (PyErr_Occurred()) {
        return NULL;
    }
    return PyBool_FromLong(result);
}


/* Loop.stop([how]) */
PyDoc_STRVAR(Loop_stop_doc,
"stop([how])");

static PyObject *
Loop_stop(Loop *self, PyObject *args)
{
    int how = EVBREAK_ONE;

    if (!PyArg_ParseTuple(args, "|i:stop", &how)) {
        return NULL;
    }
    ev_break(self->loop, how);
    Py_RETURN_NONE;
}


/* Loop.invoke() */
PyDoc_STRVAR(Loop_invoke_doc,
"invoke()");

static PyObject *
Loop_invoke(Loop *self)
{
    ev_invoke_pending(self->loop);
    Py_RETURN_NONE;
}


/* Loop.reset() */
PyDoc_STRVAR(Loop_reset_doc,
"reset()");

static PyObject *
Loop_reset(Loop *self)
{
    ev_loop_fork(self->loop);
    Py_RETURN_NONE;
}


/* Loop.now() -> float */
PyDoc_STRVAR(Loop_now_doc,
"now() -> float");

static PyObject *
Loop_now(Loop *self)
{
    return PyFloat_FromDouble(ev_now(self->loop));
}


/* Loop.update() */
PyDoc_STRVAR(Loop_update_doc,
"update()");

static PyObject *
Loop_update(Loop *self)
{
    ev_now_update(self->loop);
    Py_RETURN_NONE;
}


/* Loop.suspend()/Loop.resume() */
PyDoc_STRVAR(Loop_suspend_resume_doc,
"suspend()/resume()");

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


/* Loop.unref()/Loop.ref() */
PyDoc_STRVAR(Loop_ref_unref_doc,
"unref()/ref()");

static PyObject *
Loop_unref(Loop *self)
{
    ev_unref(self->loop);
    Py_RETURN_NONE;
}

static PyObject *
Loop_ref(Loop *self)
{
    ev_ref(self->loop);
    Py_RETURN_NONE;
}


/* Loop.verify() */
PyDoc_STRVAR(Loop_verify_doc,
"verify()");

static PyObject *
Loop_verify(Loop *self)
{
    ev_verify(self->loop);
    Py_RETURN_NONE;
}


/* watcher methods */

PyObject *
Loop_watcher(Loop *self, PyObject *args, const char *name,
                    PyTypeObject *type)
{
    PyObject *callback, *data = Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, name, 1, 3,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)type,
                                        self, callback, data, priority, NULL);
}


/* Loop.io(fd, events, callback[, data, priority]) -> pyev.Io */
PyDoc_STRVAR(Loop_io_doc,
"io(fd, events, callback[, data, priority]) -> pyev.Io");

static PyObject *
Loop_io(Loop *self, PyObject *args)
{
    PyObject *fd, *events;
    PyObject *callback, *data = Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, "io", 3, 5,
                           &fd, &events,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)&IoType,
                                        fd, events,
                                        self, callback, data, priority, NULL);
}


/* Loop.timer(after, repeat, callback[, data, priority]) -> pyev.Timer */
PyDoc_STRVAR(Loop_timer_doc,
"timer(after, repeat, callback[, data, priority]) -> pyev.Timer");

static PyObject *
Loop_timer(Loop *self, PyObject *args)
{
    PyObject *after, *repeat;
    PyObject *callback, *data = Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, "timer", 3, 5,
                           &after, &repeat,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)&TimerType,
                                        after, repeat,
                                        self, callback, data, priority, NULL);
}


#if EV_PERIODIC_ENABLE
/* Loop.periodic(offset, interval, callback[, data, priority]) -> pyev.Periodic */
PyDoc_STRVAR(Loop_periodic_doc,
"periodic(offset, interval, callback[, data, priority]) -> pyev.Periodic");

static PyObject *
Loop_periodic(Loop *self, PyObject *args)
{
    PyObject *offset, *interval;
    PyObject *callback, *data = Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, "periodic", 3, 5,
                           &offset, &interval,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)&PeriodicType,
                                        offset, interval,
                                        self, callback, data, priority, NULL);
}
#if EV_PREPARE_ENABLE
/* Loop.scheduler(scheduler, callback[, data, priority]) -> pyev.Scheduler */
PyDoc_STRVAR(Loop_scheduler_doc,
"scheduler(scheduler, callback[, data, priority]) -> pyev.Scheduler");

static PyObject *
Loop_scheduler(Loop *self, PyObject *args)
{
    PyObject *scheduler;
    PyObject *callback, *data = Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, "scheduler", 2, 4,
                           &scheduler,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)&SchedulerType,
                                        scheduler,
                                        self, callback, data, priority, NULL);
}
#endif
#endif


#if EV_SIGNAL_ENABLE
/* Loop.signal(signum, callback[, data, priority]) -> pyev.Signal */
PyDoc_STRVAR(Loop_signal_doc,
"signal(signum, callback[, data, priority]) -> pyev.Signal");

static PyObject *
Loop_signal(Loop *self, PyObject *args)
{
    PyObject *signum;
    PyObject *callback, *data = Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, "signal", 2, 4,
                           &signum,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)&SignalType,
                                        signum,
                                        self, callback, data, priority, NULL);
}
#endif


#if EV_CHILD_ENABLE
/* Loop.child(pid, trace, callback[, data, priority]) -> pyev.Child */
PyDoc_STRVAR(Loop_child_doc,
"child(pid, trace, callback[, data, priority]) -> pyev.Child");

static PyObject *
Loop_child(Loop *self, PyObject *args)
{
    PyObject *pid, *trace;
    PyObject *callback, *data = Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, "child", 3, 5,
                           &pid, &trace,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)&ChildType,
                                        pid, trace,
                                        self, callback, data, priority, NULL);
}
#endif


#if EV_IDLE_ENABLE
/* Loop.idle(callback[, data, priority]) -> pyev.Idle */
PyDoc_STRVAR(Loop_idle_doc,
"idle(callback[, data, priority]) -> pyev.Idle");

static PyObject *
Loop_idle(Loop *self, PyObject *args)
{
    return Loop_watcher(self, args, "idle", &IdleType);
}
#endif


#if EV_PREPARE_ENABLE
/* Loop.prepare(callback[, data, priority]) -> pyev.Prepare */
PyDoc_STRVAR(Loop_prepare_doc,
"prepare(callback[, data, priority]) -> pyev.Prepare");

static PyObject *
Loop_prepare(Loop *self, PyObject *args)
{
    return Loop_watcher(self, args, "prepare", &PrepareType);
}
#endif


#if EV_CHECK_ENABLE
/* Loop.check(callback[, data, priority]) -> pyev.Check */
PyDoc_STRVAR(Loop_check_doc,
"check(callback[, data, priority]) -> pyev.Check");

static PyObject *
Loop_check(Loop *self, PyObject *args)
{
    return Loop_watcher(self, args, "check", &CheckType);
}
#endif


#if EV_EMBED_ENABLE
/* Loop.embed(other[, callback, data, priority]) -> pyev.Embed */
PyDoc_STRVAR(Loop_embed_doc,
"embed(other[, callback, data, priority]) -> pyev.Embed");

static PyObject *
Loop_embed(Loop *self, PyObject *args)
{
    PyObject *other;
    PyObject *callback = Py_None, *data = Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, "embed", 1, 4,
                           &other,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)&EmbedType,
                                        other,
                                        self, callback, data, priority, NULL);
}
#endif


#if EV_FORK_ENABLE
/* Loop.fork(callback[, data, priority]) -> pyev.Fork */
PyDoc_STRVAR(Loop_fork_doc,
"fork(callback[, data, priority]) -> pyev.Fork");

static PyObject *
Loop_fork(Loop *self, PyObject *args)
{
    return Loop_watcher(self, args, "fork", &ForkType);
}
#endif


#if EV_ASYNC_ENABLE
/* Loop.async(callback[, data, priority]) -> pyev.Async */
PyDoc_STRVAR(Loop_async_doc,
"async(callback[, data, priority]) -> pyev.Async");

static PyObject *
Loop_async(Loop *self, PyObject *args)
{
    return Loop_watcher(self, args, "async", &AsyncType);
}
#endif


/* LoopType.tp_methods */
static PyMethodDef Loop_tp_methods[] = {
    {"start", (PyCFunction)Loop_start,
     METH_VARARGS, Loop_start_doc},
    {"stop", (PyCFunction)Loop_stop,
     METH_VARARGS, Loop_stop_doc},
    {"invoke", (PyCFunction)Loop_invoke,
     METH_NOARGS, Loop_invoke_doc},
    {"reset", (PyCFunction)Loop_reset,
     METH_NOARGS, Loop_reset_doc},
    {"now", (PyCFunction)Loop_now,
     METH_NOARGS, Loop_now_doc},
    {"update", (PyCFunction)Loop_update,
     METH_NOARGS, Loop_update_doc},
    {"suspend", (PyCFunction)Loop_suspend,
     METH_NOARGS, Loop_suspend_resume_doc},
    {"resume", (PyCFunction)Loop_resume,
     METH_NOARGS, Loop_suspend_resume_doc},
    {"unref", (PyCFunction)Loop_unref,
     METH_NOARGS, Loop_ref_unref_doc},
    {"ref", (PyCFunction)Loop_ref,
     METH_NOARGS, Loop_ref_unref_doc},
    {"verify", (PyCFunction)Loop_verify,
     METH_NOARGS, Loop_verify_doc},
    /* watcher methods */
    {"io", (PyCFunction)Loop_io,
     METH_VARARGS, Loop_io_doc},
    {"timer", (PyCFunction)Loop_timer,
     METH_VARARGS, Loop_timer_doc},
#if EV_PERIODIC_ENABLE
    {"periodic", (PyCFunction)Loop_periodic,
     METH_VARARGS, Loop_periodic_doc},
#if EV_PREPARE_ENABLE
    {"scheduler", (PyCFunction)Loop_scheduler,
     METH_VARARGS, Loop_scheduler_doc},
#endif
#endif
#if EV_SIGNAL_ENABLE
    {"signal", (PyCFunction)Loop_signal,
     METH_VARARGS, Loop_signal_doc},
#endif
#if EV_CHILD_ENABLE
    {"child", (PyCFunction)Loop_child,
     METH_VARARGS, Loop_child_doc},
#endif
#if EV_IDLE_ENABLE
    {"idle", (PyCFunction)Loop_idle,
     METH_VARARGS, Loop_idle_doc},
#endif
#if EV_PREPARE_ENABLE
    {"prepare", (PyCFunction)Loop_prepare,
     METH_VARARGS, Loop_prepare_doc},
#endif
#if EV_CHECK_ENABLE
    {"check", (PyCFunction)Loop_check,
     METH_VARARGS, Loop_check_doc},
#endif
#if EV_EMBED_ENABLE
    {"embed", (PyCFunction)Loop_embed,
     METH_VARARGS, Loop_embed_doc},
#endif
#if EV_FORK_ENABLE
    {"fork", (PyCFunction)Loop_fork,
     METH_VARARGS, Loop_fork_doc},
#endif
#if EV_ASYNC_ENABLE
    {"async", (PyCFunction)Loop_async,
     METH_VARARGS, Loop_async_doc},
#endif
    {NULL}  /* Sentinel */
};


/* LoopType.tp_members */
static PyMemberDef Loop_tp_members[] = {
    {"data", T_OBJECT, offsetof(Loop, data), 0, NULL},
    {NULL}  /* Sentinel */
};


/* Loop.callback */
static PyObject *
Loop_callback_get(Loop *self, void *closure)
{
    if (self->callback) {
        Py_INCREF(self->callback);
        return self->callback;
    }
    Py_RETURN_NONE;
}

static int
Loop_callback_set(Loop *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    return Loop_SetCallback(self, value);
}


/* Loop.io_interval/Loop.timeout_interval */
static PyObject *
Loop_interval_get(Loop *self, void *closure)
{
    return PyFloat_FromDouble(
        closure ? self->io_interval : self->timeout_interval);
}

static int
Loop_interval_set(Loop *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    double interval = PyFloat_AsDouble(value);
    if (interval == -1.0 && PyErr_Occurred()) {
        return -1;
    }
    return Loop_SetInterval(self, interval, closure ? 1 : 0);
/*
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
    return Loop_SetInterval(self, interval, (int)closure);
#pragma GCC diagnostic pop
*/
}


/* Loop.debug */
static PyObject *
Loop_debug_get(Loop *self, void *closure)
{
    return PyBool_FromLong(self->debug);
}

static int
Loop_debug_set(Loop *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    int debug = PyObject_IsTrue(value);
    if (debug < 0) {
        return -1;
    }
    self->debug = debug;
    return 0;
}


/* Loop.default */
static PyObject *
Loop_default_get(Loop *self, void *closure)
{
    return PyBool_FromLong(ev_is_default_loop(self->loop));
}


/* Loop.backend */
static PyObject *
Loop_backend_get(Loop *self, void *closure)
{
    return PyInt_FromUnsignedLong(ev_backend(self->loop));
}


/* Loop.pending */
static PyObject *
Loop_pending_get(Loop *self, void *closure)
{
    return PyInt_FromUnsignedLong(ev_pending_count(self->loop));
}


/* Loop.iteration */
static PyObject *
Loop_iteration_get(Loop *self, void *closure)
{
    return PyInt_FromUnsignedLong(ev_iteration(self->loop));
}


/* Loop.depth */
static PyObject *
Loop_depth_get(Loop *self, void *closure)
{
    return PyInt_FromUnsignedLong(ev_depth(self->loop));
}


/* LoopType.tp_getsets */
static PyGetSetDef Loop_tp_getsets[] = {
    {"callback", (getter)Loop_callback_get,
     (setter)Loop_callback_set, NULL, NULL},
    {"io_interval", (getter)Loop_interval_get,
     (setter)Loop_interval_set, NULL, (void *)1},
    {"timeout_interval", (getter)Loop_interval_get,
     (setter)Loop_interval_set, NULL, NULL},
    {"debug", (getter)Loop_debug_get,
     (setter)Loop_debug_set, NULL, NULL},
    {"default", (getter)Loop_default_get,
     Readonly_attribute_set, NULL, NULL},
    {"backend", (getter)Loop_backend_get,
     Readonly_attribute_set, NULL, NULL},
    {"pending", (getter)Loop_pending_get,
     Readonly_attribute_set, NULL, NULL},
    {"iteration", (getter)Loop_iteration_get,
     Readonly_attribute_set, NULL, NULL},
    {"depth", (getter)Loop_depth_get,
     Readonly_attribute_set, NULL, NULL},
    {NULL}  /* Sentinel */
};


/* LoopType.tp_new */
static PyObject *
Loop_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return (PyObject *)Loop_New(type, args, kwargs, 0);
}


/* LoopType */
static PyTypeObject LoopType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Loop",                              /*tp_name*/
    sizeof(Loop),                             /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Loop_tp_dealloc,              /*tp_dealloc*/
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
    Loop_tp_doc,                              /*tp_doc*/
    (traverseproc)Loop_tp_traverse,           /*tp_traverse*/
    (inquiry)Loop_tp_clear,                   /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Loop_tp_methods,                          /*tp_methods*/
    Loop_tp_members,                          /*tp_members*/
    Loop_tp_getsets,                          /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    0,                                        /*tp_init*/
    0,                                        /*tp_alloc*/
    Loop_tp_new,                              /*tp_new*/
};
