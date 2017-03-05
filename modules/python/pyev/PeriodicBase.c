/*******************************************************************************
* PeriodicBaseType
*******************************************************************************/

/* PeriodicBase.reset() */
PyDoc_STRVAR(PeriodicBase_reset_doc,
"reset()");

static PyObject *
PeriodicBase_reset(Watcher *self)
{
    ev_periodic_again(self->loop->loop, (ev_periodic *)self->watcher);
    Py_RETURN_NONE;
}


/* PeriodicBaseType.tp_methods */
static PyMethodDef PeriodicBase_tp_methods[] = {
    {"reset", (PyCFunction)PeriodicBase_reset,
     METH_NOARGS, PeriodicBase_reset_doc},
    {NULL}  /* Sentinel */
};


/* PeriodicBase.at */
static PyObject *
PeriodicBase_at_get(Watcher *self, void *closure)
{
    return PyFloat_FromDouble(
        ev_periodic_at((ev_periodic *)self->watcher));
}


/* PeriodicBaseType.tp_getsets */
static PyGetSetDef PeriodicBase_tp_getsets[] = {
    {"at", (getter)PeriodicBase_at_get,
     Readonly_attribute_set, NULL, NULL},
    {NULL}  /* Sentinel */
};


/* PeriodicBaseType.tp_new */
static PyObject *
PeriodicBase_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return (PyObject *)Watcher_New(type, EV_PERIODIC, sizeof(ev_periodic));
}


/* PeriodicBaseType */
static PyTypeObject PeriodicBaseType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.PeriodicBase",                      /*tp_name*/
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
    Py_TPFLAGS_DEFAULT,                       /*tp_flags*/
    0,                                        /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    PeriodicBase_tp_methods,                  /*tp_methods*/
    0,                                        /*tp_members*/
    PeriodicBase_tp_getsets,                  /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    0,                                        /*tp_init*/
    0,                                        /*tp_alloc*/
    PeriodicBase_tp_new,                      /*tp_new*/
};
