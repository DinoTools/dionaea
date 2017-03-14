/*******************************************************************************
* utilities
*******************************************************************************/

/* set the Io */
int
Io_Set(Watcher *self, PyObject *fd, int events)
{
    int fdnum = PyObject_AsFileDescriptor(fd);
    if (fdnum < 0) {
        return -1;
    }
    if (events & ~(EV_READ | EV_WRITE)) {
        PyErr_SetString(Error, "illegal event mask");
        return -1;
    }
    ev_io_set((ev_io *)self->watcher, fdnum, events);
    return 0;
}


/*******************************************************************************
* IoType
*******************************************************************************/

/* IoType.tp_doc */
PyDoc_STRVAR(Io_tp_doc,
"Io(fd, events, loop, callback[, data=None, priority=0])");


/* Io.set(fd, events) */
PyDoc_STRVAR(Io_set_doc,
"set(fd, events)");

static PyObject *
Io_set(Watcher *self, PyObject *args)
{
    PyObject *fd;
    int events;

    PYEV_WATCHER_SET(self);
    if (!PyArg_ParseTuple(args, "Oi:set", &fd, &events)) {
        return NULL;
    }
    if (Io_Set(self, fd, events)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


/* IoType.tp_methods */
static PyMethodDef Io_tp_methods[] = {
    {"set", (PyCFunction)Io_set,
     METH_VARARGS, Io_set_doc},
    {NULL}  /* Sentinel */
};


/* Io.fd */
static PyObject *
Io_fd_get(Watcher *self, void *closure)
{
    return PyInt_FromLong(((ev_io *)self->watcher)->fd);
}


/* Io.events */
static PyObject *
Io_events_get(Watcher *self, void *closure)
{
    return PyInt_FromLong(((ev_io *)self->watcher)->events);
}


/* IoType.tp_getsets */
static PyGetSetDef Io_tp_getsets[] = {
    {"fd", (getter)Io_fd_get,
     Readonly_attribute_set, NULL, NULL},
    {"events", (getter)Io_events_get,
     Readonly_attribute_set, NULL, NULL},
    {NULL}  /* Sentinel */
};


/* IoType.tp_init */
static int
Io_tp_init(Watcher *self, PyObject *args, PyObject *kwargs)
{
    PyObject *fd;
    int events;
    Loop *loop;
    PyObject *callback, *data = NULL;
    int priority = 0;

    static char *kwlist[] = {"fd", "events",
                             "loop", "callback", "data", "priority", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OiO!O|Oi:__init__", kwlist,
            &fd, &events,
            &LoopType, &loop, &callback, &data, &priority)) {
        return -1;
    }
    if (Watcher_Init(self, loop, callback, data, priority)) {
        return -1;
    }
    return Io_Set(self, fd, events);
}


/* IoType.tp_new */
static PyObject *
Io_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return (PyObject *)Watcher_New(type, EV_IO, sizeof(ev_io));
}


/* IoType */
static PyTypeObject IoType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Io",                                /*tp_name*/
    sizeof(Watcher),                          /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    0,                                        /*tp_dealloc*/
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
    Io_tp_doc,                                /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Io_tp_methods,                            /*tp_methods*/
    0,                                        /*tp_members*/
    Io_tp_getsets,                            /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Io_tp_init,                     /*tp_init*/
    0,                                        /*tp_alloc*/
    Io_tp_new,                                /*tp_new*/
};
