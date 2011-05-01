/*******************************************************************************
* utilities
*******************************************************************************/

static const double PYEV_MININTERVAL = (double)1/8192;


/* set the Periodic */
int
set_Periodic(Periodic *self, double offset, double interval)
{
    PYEV_NEGATIVE_FLOAT(interval);
    if (interval > 0.0) {
        PYEV_NEGATIVE_FLOAT(offset);
        if (interval < PYEV_MININTERVAL) {
            PyErr_SetString(PyExc_ValueError, "'interval' too small");
            return -1;
        }
    }
    ev_periodic_set(&((PeriodicBase *)self)->periodic, offset, interval, 0);
    return 0;
}


/*******************************************************************************
* PeriodicType
*******************************************************************************/

/* PeriodicType.tp_doc */
PyDoc_STRVAR(Periodic_tp_doc,
"Periodic(offset, interval, loop, callback[, data=None, priority=0])");


/* PeriodicType.tp_init */
static int
Periodic_tp_init(Periodic *self, PyObject *args, PyObject *kwargs)
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
    if (init_Watcher((Watcher *)self, loop, callback, 1, data, priority)) {
        return -1;
    }
    return set_Periodic(self, offset, interval);
}


/* Periodic.set(offset, interval) */
PyDoc_STRVAR(Periodic_set_doc,
"set(offset, interval)");

static PyObject *
Periodic_set(Periodic *self, PyObject *args)
{
    double offset, interval;

    PYEV_SET_ACTIVE_WATCHER(self);
    if (!PyArg_ParseTuple(args, "dd:set", &offset, &interval)) {
        return NULL;
    }
    if (set_Periodic(self, offset, interval)) {
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
PyDoc_STRVAR(Periodic_offset_doc,
"offset");


/* PeriodicType.tp_members */
static PyMemberDef Periodic_tp_members[] = {
    {"offset", T_DOUBLE, offsetof(Periodic, periodicbase.periodic.offset),
     0, Periodic_offset_doc},
    {NULL}  /* Sentinel */
};


/* Periodic.interval */
PyDoc_STRVAR(Periodic_interval_doc,
"interval");

static PyObject *
Periodic_interval_get(Periodic *self, void *closure)
{
    return PyFloat_FromDouble(((PeriodicBase *)self)->periodic.interval);
}

static int
Periodic_interval_set(Periodic *self, PyObject *value, void *closure)
{
    double interval;

    PYEV_NULL_VALUE(value);
    interval = PyFloat_AsDouble(value);
    if (interval == -1 && PyErr_Occurred()) {
        return -1;
    }
    PYEV_NEGATIVE_FLOAT(interval);
    ((PeriodicBase *)self)->periodic.interval = interval;
    return 0;
}


/* PeriodicType.tp_getsets */
static PyGetSetDef Periodic_tp_getsets[] = {
    {"interval", (getter)Periodic_interval_get, (setter)Periodic_interval_set,
     Periodic_interval_doc, NULL},
    {NULL}  /* Sentinel */
};


/* PeriodicType */
static PyTypeObject PeriodicType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Periodic",                          /*tp_name*/
    sizeof(Periodic),                         /*tp_basicsize*/
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
    Periodic_tp_members,                      /*tp_members*/
    Periodic_tp_getsets,                      /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Periodic_tp_init,               /*tp_init*/
};
