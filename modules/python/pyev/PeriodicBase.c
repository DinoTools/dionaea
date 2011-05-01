/*******************************************************************************
* PeriodicBaseType
*******************************************************************************/

/* PeriodicBaseType.tp_new */
static PyObject *
PeriodicBase_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    PeriodicBase *self = (PeriodicBase *)WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }
    new_Watcher((Watcher *)self, (ev_watcher *)&self->periodic, EV_PERIODIC);
    return (PyObject *)self;
}


/* PeriodicBase.reset() */
PyDoc_STRVAR(PeriodicBase_reset_doc,
"reset()");

static PyObject *
PeriodicBase_reset(PeriodicBase *self)
{
    ev_periodic_again(((Watcher *)self)->loop->loop, &self->periodic);
    Py_RETURN_NONE;
}


/* PeriodicBase.at() -> float */
PyDoc_STRVAR(PeriodicBase_at_doc,
"at() -> float");

static PyObject *
PeriodicBase_at(PeriodicBase *self)
{
    return PyFloat_FromDouble(ev_periodic_at(&self->periodic));
}


/* PeriodicBaseType.tp_methods */
static PyMethodDef PeriodicBase_tp_methods[] = {
    {"reset", (PyCFunction)PeriodicBase_reset,
     METH_NOARGS, PeriodicBase_reset_doc},
    {"at", (PyCFunction)PeriodicBase_at,
     METH_NOARGS, PeriodicBase_at_doc},
    {NULL}  /* Sentinel */
};


/* PeriodicBaseType */
static PyTypeObject PeriodicBaseType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.PeriodicBase",                      /*tp_name*/
    sizeof(PeriodicBase),                     /*tp_basicsize*/
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
    0,                                        /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    PeriodicBase_tp_methods,                  /*tp_methods*/
    0,                                        /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    0,                                        /*tp_init*/
    0,                                        /*tp_alloc*/
    PeriodicBase_tp_new,                      /*tp_new*/
};
