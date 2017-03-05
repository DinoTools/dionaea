/*******************************************************************************
* IdleType
*******************************************************************************/

/* IdleType.tp_doc */
PyDoc_STRVAR(Idle_tp_doc,
"Idle(loop, callback[, data=None, priority=0])");


/* IdleType.tp_new */
static PyObject *
Idle_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return (PyObject *)Watcher_New(type, EV_IDLE, sizeof(ev_idle));
}


/* IdleType */
static PyTypeObject IdleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Idle",                              /*tp_name*/
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
    Idle_tp_doc,                              /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    0,                                        /*tp_methods*/
    0,                                        /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    0,                                        /*tp_init*/
    0,                                        /*tp_alloc*/
    Idle_tp_new,                              /*tp_new*/
};
