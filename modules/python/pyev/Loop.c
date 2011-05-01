/*******************************************************************************
* utilities
*******************************************************************************/

/* report errors and bail out if needed */
void
set_error_Loop(Loop *self, PyObject *context)
{
    if (self->debug) {
        PYEV_EXIT_LOOP(self->loop);
    }
    else {
        PyErr_WriteUnraisable(context);
    }
}


/* loop pending callback */
static void
callback_Loop(ev_loop *loop)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    Loop *self = ev_userdata(loop);
    PyObject *result;

    result = PyObject_CallFunctionObjArgs(self->callback, self, NULL);
    if (!result) {
        PYEV_EXIT_LOOP(loop);
    }
    else {
        Py_DECREF(result);
    }
    PyGILState_Release(gstate);
}


/* set invoke pending callback */
int
set_callback_Loop(Loop *self, PyObject *value)
{
    PyObject *tmp;

    PYEV_CALLABLE_OR_NONE_VALUE(value);
    if (value == Py_None) {
        ev_set_invoke_pending_cb(self->loop, ev_invoke_pending);
    }
    else {
        ev_set_invoke_pending_cb(self->loop, callback_Loop);
    }
    tmp = self->callback;
    Py_INCREF(value);
    self->callback = value;
    Py_XDECREF(tmp);
    return 0;
}


/* set collect interval */
int
set_interval_Loop(Loop *self, double interval, char io)
{
    PYEV_NEGATIVE_FLOAT(interval);
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


/* new_loop - instanciate a Loop */
Loop *
new_Loop(PyTypeObject *type, PyObject *args, PyObject *kwargs, char default_loop)
{
    Loop *self;
    unsigned int flags = EVFLAG_AUTO;
    PyObject *callback = Py_None, *data = NULL, *debug = Py_False;
    double io_interval = 0.0, timeout_interval = 0.0;

    static char *kwlist[] = {"flags", "callback", "data", "debug",
                             "io_interval", "timeout_interval", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|IOOO!dd:__new__", kwlist,
            &flags, &callback, &data, &PyBool_Type, &debug,
            &io_interval, &timeout_interval)) {
        return NULL;
    }
    /* self */
    self = (Loop *)type->tp_alloc(type, 0);
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
    /* self->callback, self->io_interval, self->timeout_interval */
    if (set_callback_Loop(self, callback) ||
        set_interval_Loop(self, io_interval, 1) ||
        set_interval_Loop(self, timeout_interval, 0)) {
        Py_DECREF(self);
        return NULL;
    }
    /* self->data */
    Py_XINCREF(data);
    self->data = data;
    /* self->debug */
    self->debug = (debug == Py_True) ? 1 : 0;
    /* done */
    ev_set_userdata(self->loop, (void *)self);
    return self;
}


/*******************************************************************************
* LoopType
*******************************************************************************/

/* LoopType.tp_doc */
PyDoc_STRVAR(Loop_tp_doc,
"Loop([flags=EVFLAG_AUTO, callback=None, data=None, debug=False,\n\
       io_interval=0.0, timeout_interval=0.0])");


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
        if (ev_is_default_loop(self->loop)) {
            DefaultLoop = NULL;
        }
        ev_loop_destroy(self->loop);
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
}


/* LoopType.tp_new */
static PyObject *
Loop_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return (PyObject *)new_Loop(type, args, kwargs, 0);
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


/* Loop.update() */
PyDoc_STRVAR(Loop_update_doc,
"update()");

static PyObject *
Loop_update(Loop *self)
{
    ev_now_update(self->loop);
    Py_RETURN_NONE;
}


/* Loop.suspend()
   Loop.resume() */
PyDoc_STRVAR(Loop_suspend_resume_doc,
"suspend()\n\
resume()");

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


/* Loop.ref()
   Loop.unref() */
PyDoc_STRVAR(Loop_ref_unref_doc,
"ref()\n\
unref()");

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


/* Loop.invoke() */
PyDoc_STRVAR(Loop_invoke_doc,
"invoke()");

static PyObject *
Loop_invoke(Loop *self)
{
    ev_invoke_pending(self->loop);
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


/* Loop.now() -> float */
PyDoc_STRVAR(Loop_now_doc,
"now() -> float");

static PyObject *
Loop_now(Loop *self)
{
    return PyFloat_FromDouble(ev_now(self->loop));
}


/* Loop.start([flags]) */
PyDoc_STRVAR(Loop_start_doc,
"start([flags])");

static PyObject *
Loop_start(Loop *self, PyObject *args)
{
    int flags = 0;

    if (!PyArg_ParseTuple(args, "|i:start", &flags)) {
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    ev_run(self->loop, flags);
    Py_END_ALLOW_THREADS
    if (PyErr_Occurred()) {
        return NULL;
    }
    Py_RETURN_NONE;
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


/* watcher methods */

PyObject *
Loop_simple_watcher(Loop *self, PyObject *args, const char *name,
                    PyTypeObject *type)
{
    PyObject *callback, *data=Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, name, 1, 3,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)type,
                                        self, callback, data, priority, NULL);
}


/* Loop.io(fd, events, callback[, data, priority]) -> Io */
PyDoc_STRVAR(Loop_io_doc,
"io(fd, events, callback[, data, priority]) -> Io");

static PyObject *
Loop_io(Loop *self, PyObject *args)
{
    PyObject *fd, *events;
    PyObject *callback, *data=Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, "io", 3, 5,
                           &fd, &events,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)&IoType,
                                        fd, events,
                                        self, callback, data, priority, NULL);
}


/* Loop.timer(after, repeat, callback[, data, priority]) -> Timer */
PyDoc_STRVAR(Loop_timer_doc,
"timer(after, repeat, callback[, data, priority]) -> Timer");

static PyObject *
Loop_timer(Loop *self, PyObject *args)
{
    PyObject *after, *repeat;
    PyObject *callback, *data=Py_None, *priority = NULL;

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
/* Loop.periodic(offset, interval, callback[, data, priority]) -> Periodic */
PyDoc_STRVAR(Loop_periodic_doc,
"periodic(offset, interval, callback[, data, priority]) -> Periodic");

static PyObject *
Loop_periodic(Loop *self, PyObject *args)
{
    PyObject *offset, *interval;
    PyObject *callback, *data=Py_None, *priority = NULL;

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
/* Loop.scheduler(scheduler, callback[, data, priority]) -> Scheduler */
PyDoc_STRVAR(Loop_scheduler_doc,
"scheduler(scheduler, callback[, data, priority]) -> Scheduler");

static PyObject *
Loop_scheduler(Loop *self, PyObject *args)
{
    PyObject *scheduler;
    PyObject *callback, *data=Py_None, *priority = NULL;

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
/* Loop.signal(signum, callback[, data, priority]) -> Signal */
PyDoc_STRVAR(Loop_signal_doc,
"signal(signum, callback[, data, priority]) -> Signal");

static PyObject *
Loop_signal(Loop *self, PyObject *args)
{
    PyObject *signum;
    PyObject *callback, *data=Py_None, *priority = NULL;

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
/* Loop.child(pid, trace, callback[, data, priority]) -> Child */
PyDoc_STRVAR(Loop_child_doc,
"child(pid, trace, callback[, data, priority]) -> Child");

static PyObject *
Loop_child(Loop *self, PyObject *args)
{
    PyObject *pid, *trace;
    PyObject *callback, *data=Py_None, *priority = NULL;

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


#if EV_STAT_ENABLE
/* Loop.stat(path, interval, callback[, data, priority]) -> Stat */
PyDoc_STRVAR(Loop_stat_doc,
"stat(path, interval, callback[, data, priority]) -> Stat");

static PyObject *
Loop_stat(Loop *self, PyObject *args)
{
    PyObject *path, *interval;
    PyObject *callback, *data=Py_None, *priority = NULL;

    if (!PyArg_UnpackTuple(args, "stat", 3, 5,
                           &path, &interval,
                           &callback, &data, &priority)) {
        return NULL;
    }
    return PyObject_CallFunctionObjArgs((PyObject *)&StatType,
                                        path, interval,
                                        self, callback, data, priority, NULL);
}
#endif


#if EV_IDLE_ENABLE
/* Loop.idle(callback[, data, priority]) -> Idle */
PyDoc_STRVAR(Loop_idle_doc,
"idle(callback[, data, priority]) -> Idle");

static PyObject *
Loop_idle(Loop *self, PyObject *args)
{
    return Loop_simple_watcher(self, args, "idle", &IdleType);
}
#endif


#if EV_PREPARE_ENABLE
/* Loop.prepare(callback[, data, priority]) -> Prepare */
PyDoc_STRVAR(Loop_prepare_doc,
"prepare(callback[, data, priority]) -> Prepare");

static PyObject *
Loop_prepare(Loop *self, PyObject *args)
{
    return Loop_simple_watcher(self, args, "prepare", &PrepareType);
}
#endif


#if EV_CHECK_ENABLE
/* Loop.check(callback[, data, priority]) -> Check */
PyDoc_STRVAR(Loop_check_doc,
"check(callback[, data, priority]) -> Check");

static PyObject *
Loop_check(Loop *self, PyObject *args)
{
    return Loop_simple_watcher(self, args, "check", &CheckType);
}
#endif


#if EV_EMBED_ENABLE
/* Loop.embed(other[, callback, data, priority]) -> Embed */
PyDoc_STRVAR(Loop_embed_doc,
"embed(other[, callback, data, priority]) -> Embed");

static PyObject *
Loop_embed(Loop *self, PyObject *args)
{
    PyObject *other;
    PyObject *callback = Py_None, *data=Py_None, *priority = NULL;

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
/* Loop.fork(callback[, data, priority]) -> Fork */
PyDoc_STRVAR(Loop_fork_doc,
"fork(callback[, data, priority]) -> Fork");

static PyObject *
Loop_fork(Loop *self, PyObject *args)
{
    return Loop_simple_watcher(self, args, "fork", &ForkType);
}
#endif


#if EV_ASYNC_ENABLE
/* Loop.async(callback[, data, priority]) -> Async */
PyDoc_STRVAR(Loop_async_doc,
"async(callback[, data, priority]) -> Async");

static PyObject *
Loop_async(Loop *self, PyObject *args)
{
    return Loop_simple_watcher(self, args, "async", &AsyncType);
}
#endif


/* LoopType.tp_methods */
static PyMethodDef Loop_tp_methods[] = {
    {"reset", (PyCFunction)Loop_reset,
     METH_NOARGS, Loop_reset_doc},
    {"update", (PyCFunction)Loop_update,
     METH_NOARGS, Loop_update_doc},
    {"suspend", (PyCFunction)Loop_suspend,
     METH_NOARGS, Loop_suspend_resume_doc},
    {"resume", (PyCFunction)Loop_resume,
     METH_NOARGS, Loop_suspend_resume_doc},
    {"ref", (PyCFunction)Loop_ref,
     METH_NOARGS, Loop_ref_unref_doc},
    {"unref", (PyCFunction)Loop_unref,
     METH_NOARGS, Loop_ref_unref_doc},
    {"invoke", (PyCFunction)Loop_invoke,
     METH_NOARGS, Loop_invoke_doc},
    {"verify", (PyCFunction)Loop_verify,
     METH_NOARGS, Loop_verify_doc},
    {"now", (PyCFunction)Loop_now,
     METH_NOARGS, Loop_now_doc},
    {"start", (PyCFunction)Loop_start,
     METH_VARARGS, Loop_start_doc},
    {"stop", (PyCFunction)Loop_stop,
     METH_VARARGS, Loop_stop_doc},
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
#if EV_STAT_ENABLE
    {"stat", (PyCFunction)Loop_stat,
     METH_VARARGS, Loop_stat_doc},
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


/* Loop.data */
PyDoc_STRVAR(Loop_data_doc,
"data");


/* Loop.debug */
PyDoc_STRVAR(Loop_debug_doc,
"debug");


/* LoopType.tp_members */
static PyMemberDef Loop_tp_members[] = {
    {"data", T_OBJECT, offsetof(Loop, data),
     0, Loop_data_doc},
    {"debug", T_BOOL, offsetof(Loop, debug),
     0, Loop_debug_doc},
    {NULL}  /* Sentinel */
};


/* Loop.default */
PyDoc_STRVAR(Loop_default_doc,
"default");

static PyObject *
Loop_default_get(Loop *self, void *closure)
{
    PYEV_RETURN_BOOL(ev_is_default_loop(self->loop));
}


/* Loop.iteration */
PyDoc_STRVAR(Loop_iteration_doc,
"iteration");

static PyObject *
Loop_iteration_get(Loop *self, void *closure)
{
    return PyInt_FromUnsignedLong(ev_iteration(self->loop));
}


/* Loop.depth */
PyDoc_STRVAR(Loop_depth_doc,
"depth");

static PyObject *
Loop_depth_get(Loop *self, void *closure)
{
    return PyInt_FromUnsignedLong(ev_depth(self->loop));
}


/* Loop.backend */
PyDoc_STRVAR(Loop_backend_doc,
"backend");

static PyObject *
Loop_backend_get(Loop *self, void *closure)
{
    return PyInt_FromUnsignedLong(ev_backend(self->loop));
}


/* Loop.pending */
PyDoc_STRVAR(Loop_pending_doc,
"pending");

static PyObject *
Loop_pending_get(Loop *self, void *closure)
{
    return PyInt_FromUnsignedLong(ev_pending_count(self->loop));
}


/* Loop.callback */
PyDoc_STRVAR(Loop_callback_doc,
"callback");

static PyObject *
Loop_callback_get(Loop *self, void *closure)
{
    Py_INCREF(self->callback);
    return self->callback;
}

static int
Loop_callback_set(Loop *self, PyObject *value, void *closure)
{
    PYEV_NULL_VALUE(value);
    return set_callback_Loop(self, value);
}


/* Loop.io_interval
   Loop.timeout_interval */
PyDoc_STRVAR(Loop_interval_doc,
"io_interval\n\
timeout_interval");

static PyObject *
Loop_interval_get(Loop *self, void *closure)
{
    return PyFloat_FromDouble(
        closure ? self->io_interval : self->timeout_interval);
}

static int
Loop_interval_set(Loop *self, PyObject *value, void *closure)
{
    double interval;

    PYEV_NULL_VALUE(value);
    interval = PyFloat_AsDouble(value);
    if (interval == -1 && PyErr_Occurred()) {
        return -1;
    }
    return set_interval_Loop(self, interval, closure ? 1 : 0);
}


/* LoopType.tp_getsets */
static PyGetSetDef Loop_tp_getsets[] = {
    {"default", (getter)Loop_default_get, NULL,
     Loop_default_doc, NULL},
    {"iteration", (getter)Loop_iteration_get, NULL,
     Loop_iteration_doc, NULL},
    {"depth", (getter)Loop_depth_get, NULL,
     Loop_depth_doc, NULL},
    {"backend", (getter)Loop_backend_get, NULL,
     Loop_backend_doc, NULL},
    {"pending", (getter)Loop_pending_get, NULL,
     Loop_pending_doc, NULL},
    {"callback", (getter)Loop_callback_get, (setter)Loop_callback_set,
     Loop_callback_doc, NULL},
    {"io_interval", (getter)Loop_interval_get, (setter)Loop_interval_set,
     Loop_interval_doc, (void *)1},
    {"timeout_interval", (getter)Loop_interval_get, (setter)Loop_interval_set,
     Loop_interval_doc, NULL},
    {NULL}  /* Sentinel */
};


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
