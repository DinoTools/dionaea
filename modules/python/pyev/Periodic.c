/*******************************************************************************
* utilities
*******************************************************************************/

/* check offset and interval */
int
Periodic_CheckArgs(double offset, double interval)
{
    static const double PYEV_PERIODIC_INTERVAL_MIN = 1/8192;

    PYEV_CHECK_POSITIVE_OR_ZERO_FLOAT(interval);
    if (interval > 0.0) {
        if (interval < PYEV_PERIODIC_INTERVAL_MIN) {
            PyErr_SetString(PyExc_ValueError, "'interval' too small");
            return -1;
        }
        PYEV_CHECK_POSITIVE_OR_ZERO_FLOAT(offset);
        if (offset > interval) {
            PyErr_SetString(PyExc_ValueError, "'offset' bigger than 'interval'");
            return -1;
        }
    }
    return 0;
}


/* set the Periodic */
int
Periodic_Set(Watcher *self, double offset, double interval)
{
    if (Periodic_CheckArgs(offset, interval)) {
        return -1;
    }
    ev_periodic_set((ev_periodic *)self->watcher, offset, interval, 0);
    return 0;
}


/*******************************************************************************
* PeriodicType
*******************************************************************************/

/* PeriodicType.tp_doc */
PyDoc_STRVAR(Periodic_tp_doc,
"Periodic(offset, interval, loop, callback[, data=None, priority=0])");


/* Periodic.set(offset, interval) */
PyDoc_STRVAR(Periodic_set_doc,
"set(offset, interval)");

static PyObject *
Periodic_set(Watcher *self, PyObject *args)
{
    double offset, interval;

    PYEV_WATCHER_SET(self);
    if (!PyArg_ParseTuple(args, "dd:set", &offset, &interval)) {
        return NULL;
    }
    if (Periodic_Set(self, offset, interval)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


/* PeriodicType.tp_methods */
static PyMethodDef Periodic_tp_methods[] = {
    {"set", (PyCFunction)Periodic_set,
     METH_VARARGS, Periodic_set_doc},
    {NULL}  /* Sentinel */
};


/* Periodic.offset */
static PyObject *
Periodic_offset_get(Watcher *self, void *closure)
{
    return PyFloat_FromDouble(((ev_periodic *)self->watcher)->offset);
}

static int
Periodic_offset_set(Watcher *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    double offset = PyFloat_AsDouble(value);
    if (offset == -1.0 && PyErr_Occurred()) {
        return -1;
    }
    if (Periodic_CheckArgs(offset, ((ev_periodic *)self->watcher)->interval)) {
        return -1;
    }
    ((ev_periodic *)self->watcher)->offset = offset;
    return 0;
}


/* Periodic.interval */
static PyObject *
Periodic_interval_get(Watcher *self, void *closure)
{
    return PyFloat_FromDouble(((ev_periodic *)self->watcher)->interval);
}

static int
Periodic_interval_set(Watcher *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    double interval = PyFloat_AsDouble(value);
    if (interval == -1.0 && PyErr_Occurred()) {
        return -1;
    }
    if (Periodic_CheckArgs(((ev_periodic *)self->watcher)->offset, interval)) {
        return -1;
    }
    ((ev_periodic *)self->watcher)->interval = interval;
    return 0;
}


/* PeriodicType.tp_getsets */
static PyGetSetDef Periodic_tp_getsets[] = {
    {"offset", (getter)Periodic_offset_get,
     (setter)Periodic_offset_set, NULL, NULL},
    {"interval", (getter)Periodic_interval_get,
     (setter)Periodic_interval_set, NULL, NULL},
    {NULL}  /* Sentinel */
};


/* PeriodicType.tp_init */
static int
Periodic_tp_init(Watcher *self, PyObject *args, PyObject *kwargs)
{
    double offset, interval;
    Loop *loop;
    PyObject *callback, *data = NULL;
    int priority = 0;

    static char *kwlist[] = {"offset", "interval",
                             "loop", "callback", "data", "priority", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ddO!O|Oi:__init__", kwlist,
            &offset, &interval,
            &LoopType, &loop, &callback, &data, &priority)) {
        return -1;
    }
    if (Watcher_Init(self, loop, callback, data, priority)) {
        return -1;
    }
    return Periodic_Set(self, offset, interval);
}


/* PeriodicType */
static PyTypeObject PeriodicType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Periodic",                          /*tp_name*/
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
    Periodic_tp_doc,                          /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Periodic_tp_methods,                      /*tp_methods*/
    0,                                        /*tp_members*/
    Periodic_tp_getsets,                      /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Periodic_tp_init,               /*tp_init*/
};
