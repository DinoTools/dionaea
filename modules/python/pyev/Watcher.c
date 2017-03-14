/*******************************************************************************
* utils
*******************************************************************************/

void
Watcher_Start(Watcher *self)
{
    switch (self->type) {
        case EV_IO:
            PYEV_WATCHER_START(ev_io, self);
            break;
        case EV_TIMER:
            PYEV_WATCHER_START(ev_timer, self);
            break;
#if EV_PERIODIC_ENABLE
        case EV_PERIODIC:
            PYEV_WATCHER_START(ev_periodic, self);
            break;
#endif
#if EV_SIGNAL_ENABLE
        case EV_SIGNAL:
            PYEV_WATCHER_START(ev_signal, self);
            break;
#endif
#if EV_CHILD_ENABLE
        case EV_CHILD:
            PYEV_WATCHER_START(ev_child, self);
            break;
#endif
#if EV_IDLE_ENABLE
        case EV_IDLE:
            PYEV_WATCHER_START(ev_idle, self);
            break;
#endif
#if EV_PREPARE_ENABLE
        case EV_PREPARE:
            PYEV_WATCHER_START(ev_prepare, self);
            break;
#endif
#if EV_CHECK_ENABLE
        case EV_CHECK:
            PYEV_WATCHER_START(ev_check, self);
            break;
#endif
#if EV_EMBED_ENABLE
        case EV_EMBED:
            PYEV_WATCHER_START(ev_embed, self);
            break;
#endif
#if EV_FORK_ENABLE
        case EV_FORK:
            PYEV_WATCHER_START(ev_fork, self);
            break;
#endif
#if EV_ASYNC_ENABLE
        case EV_ASYNC:
            PYEV_WATCHER_START(ev_async, self);
            break;
#endif
        default:
            Py_FatalError("unknown watcher type");
            break;
    }
}

void
Watcher_Stop(Watcher *self)
{
    switch (self->type) {
        case EV_IO:
            PYEV_WATCHER_STOP(ev_io, self);
            break;
        case EV_TIMER:
            PYEV_WATCHER_STOP(ev_timer, self);
            break;
#if EV_PERIODIC_ENABLE
        case EV_PERIODIC:
            PYEV_WATCHER_STOP(ev_periodic, self);
            break;
#endif
#if EV_SIGNAL_ENABLE
        case EV_SIGNAL:
            PYEV_WATCHER_STOP(ev_signal, self);
            break;
#endif
#if EV_CHILD_ENABLE
        case EV_CHILD:
            PYEV_WATCHER_STOP(ev_child, self);
            break;
#endif
#if EV_IDLE_ENABLE
        case EV_IDLE:
            PYEV_WATCHER_STOP(ev_idle, self);
            break;
#endif
#if EV_PREPARE_ENABLE
        case EV_PREPARE:
            PYEV_WATCHER_STOP(ev_prepare, self);
            break;
#endif
#if EV_CHECK_ENABLE
        case EV_CHECK:
            PYEV_WATCHER_STOP(ev_check, self);
            break;
#endif
#if EV_EMBED_ENABLE
        case EV_EMBED:
            PYEV_WATCHER_STOP(ev_embed, self);
            break;
#endif
#if EV_FORK_ENABLE
        case EV_FORK:
            PYEV_WATCHER_STOP(ev_fork, self);
            break;
#endif
#if EV_ASYNC_ENABLE
        case EV_ASYNC:
            PYEV_WATCHER_STOP(ev_async, self);
            break;
#endif
        default:
            Py_FatalError("unknown watcher type");
            break;
    }
}


/* watcher callback */
static void
Watcher_Callback(struct ev_loop *loop, ev_watcher *watcher, int revents)
{
    Watcher *self = watcher->data;
    if (revents & EV_ERROR) {
        if (!PyErr_Occurred()) {
            if (errno) { // there's a high probability it is related
                PyObject *pymsg =
                    PyString_FromFormat("<%s object at %p> has been stopped",
                                        Py_TYPE(self)->tp_name, self);
                PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, pymsg);
                Py_XDECREF(pymsg);
            }
            else {
                PyErr_Format(Error, "unspecified libev error: "
                             "<%s object at %p> has been stopped",
                             Py_TYPE(self)->tp_name, self);
            }
        }
        PYEV_LOOP_EXIT(loop);
    }
    else if (self->callback != Py_None) {
        PyObject *pyrevents = PyInt_FromLong(revents);
        if (!pyrevents) {
            PYEV_LOOP_EXIT(loop);
        }
        else {
            PyObject *pyresult =
                PyObject_CallFunctionObjArgs(self->callback, self, pyrevents, NULL);
            if (!pyresult) {
                Loop_WarnOrStop(ev_userdata(loop), self->callback);
            }
            else {
                Py_DECREF(pyresult);
            }
            Py_DECREF(pyrevents);
        }
    }
#if EV_EMBED_ENABLE
    else if (revents & EV_EMBED) {
        ev_embed_sweep(loop, (ev_embed *)watcher);
    }
#endif
}


Watcher *
Watcher_New(PyTypeObject *type, int ev_type, size_t size)
{
    Watcher *self = (Watcher *)type->tp_alloc(type, 0);
    if (!self) {
        return NULL;
    }
    self->watcher = PyMem_Malloc(size);
    if (!self->watcher) {
        PyErr_NoMemory();
        Py_DECREF(self);
        return NULL;
    }
    ev_init(self->watcher, Watcher_Callback);
    self->watcher->data = self;
    self->type = ev_type;
    return self;
}


/* set watcher callback */
int
Watcher_SetCallback(Watcher *self, PyObject *callback)
{
    /*switch (self->type) {
        case EV_EMBED:
            PYEV_CHECK_CALLABLE_OR_NONE(callback);
            break;
        default:
            PYEV_CHECK_CALLABLE(callback);
            break;
    }*/
    if (self->type == EV_EMBED) {
        PYEV_CHECK_CALLABLE_OR_NONE(callback);
    }
    else {
        PYEV_CHECK_CALLABLE(callback);
    }
    PyObject *tmp = self->callback;
    Py_INCREF(callback);
    self->callback = callback;
    Py_XDECREF(tmp);
    return 0;
}


/* set watcher priority */
int
Watcher_SetPriority(Watcher *self, int priority)
{
    PYEV_WATCHER_CHECK_PENDING(self, "set the priority of", -1);
    ev_set_priority(self->watcher, priority);
    return 0;
}


int
Watcher_Init(Watcher *self, Loop *loop, PyObject *callback,
             PyObject *data, int priority)
{
    PYEV_WATCHER_CHECK_ACTIVE(self, "init", -1);
    PyObject *tmp = (PyObject *)self->loop;
    Py_INCREF(loop);
    self->loop = loop;
    Py_CLEAR(tmp);
    if (Watcher_SetCallback(self, callback) ||
        Watcher_SetPriority(self, priority)) {
        return -1;
    }
    if (data) {
        tmp = self->data;
        Py_INCREF(data);
        self->data = data;
        Py_XDECREF(tmp);
    }
    return 0;
}


/*******************************************************************************
* WatcherType
*******************************************************************************/

/* WatcherType.tp_traverse */
static int
Watcher_tp_traverse(Watcher *self, visitproc visit, void *arg)
{
    Py_VISIT(self->data);
    Py_VISIT(self->callback);
    Py_VISIT(self->loop);
    return 0;
}


/* WatcherType.tp_clear */
static int
Watcher_tp_clear(Watcher *self)
{
    Py_CLEAR(self->data);
    Py_CLEAR(self->callback);
    Py_CLEAR(self->loop);
    return 0;
}


/* WatcherType.tp_dealloc */
static void
Watcher_tp_dealloc(Watcher *self)
{
    Watcher_tp_clear(self);
    if (self->watcher) {
        if (self->loop) {
            Watcher_Stop(self);
        }
        PyMem_Free(self->watcher);
        self->watcher = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
}


/* Watcher.start() */
PyDoc_STRVAR(Watcher_start_doc,
"start()");

static PyObject *
Watcher_start(Watcher *self)
{
    Watcher_Start(self);
    Py_RETURN_NONE;
}


/* Watcher.stop() */
PyDoc_STRVAR(Watcher_stop_doc,
"stop()");

static PyObject *
Watcher_stop(Watcher *self)
{
    Watcher_Stop(self);
    Py_RETURN_NONE;
}


/* Watcher.invoke(revents) */
PyDoc_STRVAR(Watcher_invoke_doc,
"invoke(revents)");

static PyObject *
Watcher_invoke(Watcher *self, PyObject *args)
{
    int revents;

    if (!PyArg_ParseTuple(args, "i:invoke", &revents)) {
        return NULL;
    }
    ev_invoke(self->loop->loop, self->watcher, revents);
    Py_RETURN_NONE;
}


/* Watcher.clear() -> int */
PyDoc_STRVAR(Watcher_clear_doc,
"clear() -> int");

static PyObject *
Watcher_clear(Watcher *self)
{
    return PyInt_FromLong(ev_clear_pending(self->loop->loop, self->watcher));
}


/* Watcher.feed(revents) */
PyDoc_STRVAR(Watcher_feed_doc,
"feed(revents)");

static PyObject *
Watcher_feed(Watcher *self, PyObject *args)
{
    int revents;

    if (!PyArg_ParseTuple(args, "i:feed", &revents)) {
        return NULL;
    }
    ev_feed_event(self->loop->loop, self->watcher, revents);
    Py_RETURN_NONE;
}


/* WatcherType.tp_methods */
static PyMethodDef Watcher_tp_methods[] = {
    {"start", (PyCFunction)Watcher_start,
     METH_NOARGS, Watcher_start_doc},
    {"stop", (PyCFunction)Watcher_stop,
     METH_NOARGS, Watcher_stop_doc},
    {"invoke", (PyCFunction)Watcher_invoke,
     METH_VARARGS, Watcher_invoke_doc},
    {"clear", (PyCFunction)Watcher_clear,
     METH_NOARGS, Watcher_clear_doc},
    {"feed", (PyCFunction)Watcher_feed,
     METH_VARARGS, Watcher_feed_doc},
    {NULL}  /* Sentinel */
};


/* WatcherType.tp_members */
static PyMemberDef Watcher_tp_members[] = {
    {"data", T_OBJECT, offsetof(Watcher, data), 0, NULL},
    {"loop", T_OBJECT_EX, offsetof(Watcher, loop), READONLY, NULL},
    {NULL}  /* Sentinel */
};


/* Watcher.callback */
static PyObject *
Watcher_callback_get(Watcher *self, void *closure)
{
    Py_INCREF(self->callback);
    return self->callback;
}

static int
Watcher_callback_set(Watcher *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    return Watcher_SetCallback(self, value);
}


/* Watcher.priority */
static PyObject *
Watcher_priority_get(Watcher *self, void *closure)
{
    return PyInt_FromLong(ev_priority(self->watcher));
}

static int
Watcher_priority_set(Watcher *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    PYEV_WATCHER_CHECK_ACTIVE(self, "set the priority of", -1);
    long priority = PyInt_AsLong(value);
    PYEV_CHECK_INT_ATTRIBUTE(priority);
    return Watcher_SetPriority(self, priority);
}


/* Watcher.active */
static PyObject *
Watcher_active_get(Watcher *self, void *closure)
{
    return PyBool_FromLong(ev_is_active(self->watcher));
}


/* Watcher.pending */
static PyObject *
Watcher_pending_get(Watcher *self, void *closure)
{
    return PyBool_FromLong(ev_is_pending(self->watcher));
}


/* WatcherType.tp_getsets */
static PyGetSetDef Watcher_tp_getsets[] = {
    {"callback", (getter)Watcher_callback_get,
     (setter)Watcher_callback_set, NULL, NULL},
    {"priority", (getter)Watcher_priority_get,
     (setter)Watcher_priority_set, NULL, NULL},
    {"active", (getter)Watcher_active_get,
     Readonly_attribute_set, NULL, NULL},
    {"pending", (getter)Watcher_pending_get,
     Readonly_attribute_set, NULL, NULL},
    {NULL}  /* Sentinel */
};


/* WatcherType.tp_init */
static int
Watcher_tp_init(Watcher *self, PyObject *args, PyObject *kwargs)
{
    Loop *loop;
    PyObject *callback, *data = NULL;
    int priority = 0;

    static char *kwlist[] = {"loop", "callback", "data", "priority", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!O|Oi:__init__", kwlist,
            &LoopType, &loop, &callback, &data, &priority)) {
        return -1;
    }
    return Watcher_Init(self, loop, callback, data, priority);
}


/* WatcherType */
static PyTypeObject WatcherType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Watcher",                           /*tp_name*/
    sizeof(Watcher),                          /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Watcher_tp_dealloc,           /*tp_dealloc*/
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
    (traverseproc)Watcher_tp_traverse,        /*tp_traverse*/
    (inquiry)Watcher_tp_clear,                /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Watcher_tp_methods,                       /*tp_methods*/
    Watcher_tp_members,                       /*tp_members*/
    Watcher_tp_getsets,                       /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Watcher_tp_init,                /*tp_init*/
};
