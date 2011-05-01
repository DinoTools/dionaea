/*******************************************************************************
* AsyncType
*******************************************************************************/

/* AsyncType.tp_doc */
PyDoc_STRVAR(Async_tp_doc,
"Async(loop, callback[, data=None, priority=0])");


/* AsyncType.tp_new */
static PyObject *
Async_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Async *self = (Async *)WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }
    new_Watcher((Watcher *)self, (ev_watcher *)&self->async, EV_ASYNC);
    return (PyObject *)self;
}


/* Async.send() */
PyDoc_STRVAR(Async_send_doc,
"send()");

static PyObject *
Async_send(Async *self)
{
    ev_async_send(((Watcher *)self)->loop->loop, &self->async);
    Py_RETURN_NONE;
}


/* AsyncType.tp_methods */
static PyMethodDef Async_tp_methods[] = {
    {"send", (PyCFunction)Async_send,
     METH_NOARGS, Async_send_doc},
    {NULL}  /* Sentinel */
};


/* Async.sent */
PyDoc_STRVAR(Async_sent_doc,
"sent");

static PyObject *
Async_sent_get(Async *self, void *closure)
{
    PYEV_RETURN_BOOL(ev_async_pending(&self->async));
}


/* AsyncType.tp_getsets */
static PyGetSetDef Async_tp_getsets[] = {
    {"sent", (getter)Async_sent_get, NULL,
     Async_sent_doc, NULL},
    {NULL}  /* Sentinel */
};


/* AsyncType */
static PyTypeObject AsyncType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Async",                             /*tp_name*/
    sizeof(Async),                            /*tp_basicsize*/
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
    Async_tp_doc,                             /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Async_tp_methods,                         /*tp_methods*/
    0,                                        /*tp_members*/
    Async_tp_getsets,                         /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    0,                                        /*tp_init*/
    0,                                        /*tp_alloc*/
    Async_tp_new,                             /*tp_new*/
};
