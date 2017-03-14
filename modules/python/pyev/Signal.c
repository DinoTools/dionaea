/*******************************************************************************
* utilities
*******************************************************************************/

/* set the Signal */
int
Signal_Set(Watcher *self, int signum)
{
    ev_signal_set((ev_signal *)self->watcher, signum);
    return 0;
}


/*******************************************************************************
* SignalType
*******************************************************************************/

/* SignalType.tp_doc */
PyDoc_STRVAR(Signal_tp_doc,
"Signal(signum, loop, callback[, data=None, priority=0])");


/* Signal.set(signum) */
PyDoc_STRVAR(Signal_set_doc,
"set(signum)");

static PyObject *
Signal_set(Watcher *self, PyObject *args)
{
    int signum;

    PYEV_WATCHER_SET(self);
    if (!PyArg_ParseTuple(args, "i:set", &signum)) {
        return NULL;
    }
    if (Signal_Set(self, signum)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


/* SignalType.tp_methods */
static PyMethodDef Signal_tp_methods[] = {
    {"set", (PyCFunction)Signal_set,
     METH_VARARGS, Signal_set_doc},
    {NULL}  /* Sentinel */
};


/* Signal.signum */
static PyObject *
Signal_signum_get(Watcher *self, void *closure)
{
    return PyInt_FromLong(((ev_signal *)self->watcher)->signum);
}


/* SignalType.tp_getsets */
static PyGetSetDef Signal_tp_getsets[] = {
    {"signum", (getter)Signal_signum_get,
     Readonly_attribute_set, NULL, NULL},
    {NULL}  /* Sentinel */
};


/* SignalType.tp_init */
static int
Signal_tp_init(Watcher *self, PyObject *args, PyObject *kwargs)
{
    int signum;
    Loop *loop;
    PyObject *callback, *data = NULL;
    int priority = 0;

    static char *kwlist[] = {"signum",
                             "loop", "callback", "data", "priority", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iO!O|Oi:__init__", kwlist,
            &signum,
            &LoopType, &loop, &callback, &data, &priority)) {
        return -1;
    }
    if (Watcher_Init(self, loop, callback, data, priority)) {
        return -1;
    }
    return Signal_Set(self, signum);
}


/* SignalType.tp_new */
static PyObject *
Signal_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return (PyObject *)Watcher_New(type, EV_SIGNAL, sizeof(ev_signal));
}


/* SignalType */
static PyTypeObject SignalType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Signal",                            /*tp_name*/
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
    Signal_tp_doc,                            /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Signal_tp_methods,                        /*tp_methods*/
    0,                                        /*tp_members*/
    Signal_tp_getsets,                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Signal_tp_init,                 /*tp_init*/
    0,                                        /*tp_alloc*/
    Signal_tp_new,                            /*tp_new*/
};
