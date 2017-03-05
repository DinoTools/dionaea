/*******************************************************************************
* utilities
*******************************************************************************/

int
Embed_Set(Embed *self, Loop *other)
{
    if (!(ev_backend(other->loop) & ev_embeddable_backends())) {
        PyErr_SetString(Error, "'other' must be embeddable");
        return -1;
    }
    PyObject *tmp = (PyObject *)self->other;
    Py_INCREF(other);
    self->other = other;
    Py_XDECREF(tmp);
    ev_embed_set((ev_embed *)((Watcher *)self)->watcher, other->loop);
    return 0;
}


/*******************************************************************************
* EmbedType
*******************************************************************************/

/* EmbedType.tp_doc */
PyDoc_STRVAR(Embed_tp_doc,
"Embed(other, loop[, callback=None, data=None, priority=0])");


/* EmbedType.tp_traverse */
static int
Embed_tp_traverse(Embed *self, visitproc visit, void *arg)
{
    Py_VISIT(self->other);
    return 0;
}


/* EmbedType.tp_clear */
static int
Embed_tp_clear(Embed *self)
{
    Py_CLEAR(self->other);
    return 0;
}


/* EmbedType.tp_dealloc */
static void
Embed_tp_dealloc(Embed *self)
{
    Embed_tp_clear(self);
    WatcherType.tp_dealloc((PyObject *)self);
}


/* Embed.set(other) */
PyDoc_STRVAR(Embed_set_doc,
"set(other)");

static PyObject *
Embed_set(Embed *self, PyObject *args)
{
    Loop *other;

    PYEV_WATCHER_SET((Watcher *)self);
    if (!PyArg_ParseTuple(args, "O!:set", &LoopType, &other)) {
        return NULL;
    }
    if (Embed_Set(self, other)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


/* Embed.sweep() */
PyDoc_STRVAR(Embed_sweep_doc,
"sweep()");

static PyObject *
Embed_sweep(Embed *self)
{
    ev_embed_sweep(((Watcher *)self)->loop->loop,
                   (ev_embed *)((Watcher *)self)->watcher);
    Py_RETURN_NONE;
}


/* EmbedType.tp_methods */
static PyMethodDef Embed_tp_methods[] = {
    {"set", (PyCFunction)Embed_set,
     METH_VARARGS, Embed_set_doc},
    {"sweep", (PyCFunction)Embed_sweep,
     METH_NOARGS, Embed_sweep_doc},
    {NULL}  /* Sentinel */
};


/* EmbedType.tp_members */
static PyMemberDef Embed_tp_members[] = {
    {"other", T_OBJECT_EX, offsetof(Embed, other), READONLY, NULL},
    {NULL}  /* Sentinel */
};


/* EmbedType.tp_init */
static int
Embed_tp_init(Embed *self, PyObject *args, PyObject *kwargs)
{
    Loop *other, *loop;
    PyObject *callback = Py_None, *data = NULL;
    int priority = 0;

    static char *kwlist[] = {"other",
                             "loop", "callback", "data", "priority", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!O!|OOi:__init__", kwlist,
            &LoopType, &other,
            &LoopType, &loop, &callback, &data, &priority)) {
        return -1;
    }
    if (Watcher_Init((Watcher *)self, loop, callback, data, priority)) {
        return -1;
    }
    return Embed_Set(self, other);
}


/* EmbedType.tp_new */
static PyObject *
Embed_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return (PyObject *)Watcher_New(type, EV_EMBED, sizeof(ev_embed));
}


/* EmbedType */
static PyTypeObject EmbedType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Embed",                             /*tp_name*/
    sizeof(Embed),                            /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Embed_tp_dealloc,             /*tp_dealloc*/
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
    Embed_tp_doc,                             /*tp_doc*/
    (traverseproc)Embed_tp_traverse,          /*tp_traverse*/
    (inquiry)Embed_tp_clear,                  /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Embed_tp_methods,                         /*tp_methods*/
    Embed_tp_members,                         /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Embed_tp_init,                  /*tp_init*/
    0,                                        /*tp_alloc*/
    Embed_tp_new,                             /*tp_new*/
};
