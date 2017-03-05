/*******************************************************************************
* utilities
*******************************************************************************/

/* set the Child */
int
Child_Set(Watcher *self, int pid, int trace)
{
    ev_child_set((ev_child *)self->watcher, pid, trace);
    return 0;
}


/*******************************************************************************
* ChildType
*******************************************************************************/

/* ChildType.tp_doc */
PyDoc_STRVAR(Child_tp_doc,
"Child(pid, trace, loop, callback[, data=None, priority=0])");


/* Child.set(pid, trace) */
PyDoc_STRVAR(Child_set_doc,
"set(pid, trace)");

static PyObject *
Child_set(Watcher *self, PyObject *args)
{
    int pid, trace;

    PYEV_WATCHER_SET(self);
    if (!PyArg_ParseTuple(args, "iO&:set", &pid, Boolean_Predicate, &trace)) {
        return NULL;
    }
    if (Child_Set(self, pid, trace)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


/* ChildType.tp_methods */
static PyMethodDef Child_tp_methods[] = {
    {"set", (PyCFunction)Child_set,
     METH_VARARGS, Child_set_doc},
    {NULL}  /* Sentinel */
};


/* Child.rpid */
static PyObject *
Child_rpid_get(Watcher *self, void *closure)
{
    return PyInt_FromLong(((ev_child *)self->watcher)->rpid);
}

static int
Child_rpid_set(Watcher *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    long rpid = PyInt_AsLong(value);
    PYEV_CHECK_INT_ATTRIBUTE(rpid);
    ((ev_child *)self->watcher)->rpid = rpid;
    return 0;
}


/* Child.rstatus */
static PyObject *
Child_rstatus_get(Watcher *self, void *closure)
{
    return PyInt_FromLong(((ev_child *)self->watcher)->rstatus);
}

static int
Child_rstatus_set(Watcher *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    long rstatus = PyInt_AsLong(value);
    PYEV_CHECK_INT_ATTRIBUTE(rstatus);
    ((ev_child *)self->watcher)->rstatus = rstatus;
    return 0;
}


/* Child.pid */
static PyObject *
Child_pid_get(Watcher *self, void *closure)
{
    return PyInt_FromLong(((ev_child *)self->watcher)->pid);
}


/* ChildType.tp_getsets */
static PyGetSetDef Child_tp_getsets[] = {
    {"rpid", (getter)Child_rpid_get,
     (setter)Child_rpid_set, NULL, NULL},
    {"rstatus", (getter)Child_rstatus_get,
     (setter)Child_rstatus_set, NULL, NULL},
    {"pid", (getter)Child_pid_get,
     Readonly_attribute_set, NULL, NULL},
    {NULL}  /* Sentinel */
};


/* ChildType.tp_init */
static int
Child_tp_init(Watcher *self, PyObject *args, PyObject *kwargs)
{
    int pid, trace;
    Loop *loop;
    PyObject *callback, *data = NULL;
    int priority = 0;

    static char *kwlist[] = {"pid", "trace",
                             "loop", "callback", "data", "priority", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iO&O!O|Oi:__init__", kwlist,
            &pid, Boolean_Predicate, &trace,
            &LoopType, &loop, &callback, &data, &priority)) {
        return -1;
    }
    if (!ev_is_default_loop(loop->loop)) {
        PyErr_SetString(Error,
                        "Child watchers are only supported in the 'default loop'");
        return -1;
    }
    if (Watcher_Init(self, loop, callback, data, priority)) {
        return -1;
    }
    return Child_Set(self, pid, trace);
}


/* ChildType.tp_new */
static PyObject *
Child_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return (PyObject *)Watcher_New(type, EV_CHILD, sizeof(ev_child));
}


/* ChildType */
static PyTypeObject ChildType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Child",                             /*tp_name*/
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
    Child_tp_doc,                             /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Child_tp_methods,                         /*tp_methods*/
    0,                                        /*tp_members*/
    Child_tp_getsets,                         /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Child_tp_init,                  /*tp_init*/
    0,                                        /*tp_alloc*/
    Child_tp_new,                             /*tp_new*/
};
