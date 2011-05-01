/*******************************************************************************
* utilities
*******************************************************************************/

/* set the Child */
void
set_Child(Child *self, int pid, PyObject *trace)
{
    ev_child_set(&self->child, pid, (trace == Py_True) ? 1 : 0);
}


/*******************************************************************************
* ChildType
*******************************************************************************/

/* ChildType.tp_doc */
PyDoc_STRVAR(Child_tp_doc,
"Child(pid, trace, loop, callback[, data=None, priority=0])");


/* ChildType.tp_new */
static PyObject *
Child_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Child *self = (Child *)WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }
    new_Watcher((Watcher *)self, (ev_watcher *)&self->child, EV_CHILD);
    return (PyObject *)self;
}


/* ChildType.tp_init */
static int
Child_tp_init(Child *self, PyObject *args, PyObject *kwargs)
{
    int pid;
    PyObject *trace;
    Loop *loop;
    PyObject *callback, *data = NULL;
    int priority = 0;

    static char *kwlist[] = {"pid", "trace",
                             "loop", "callback", "data", "priority", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iO!O!O|Oi:__init__", kwlist,
            &pid, &PyBool_Type, &trace,
            &LoopType, &loop, &callback, &data, &priority)) {
        return -1;
    }
    if (!ev_is_default_loop(loop->loop)) {
        PyErr_SetString(Error, "loop must be the 'default loop'");
        return -1;
    }
    if (init_Watcher((Watcher *)self, loop, callback, 1, data, priority)) {
        return -1;
    }
    set_Child(self, pid, trace);
    return 0;
}


/* Child.set(pid, trace) */
PyDoc_STRVAR(Child_set_doc,
"set(pid, trace)");

static PyObject *
Child_set(Child *self, PyObject *args)
{
    int pid;
    PyObject *trace;

    PYEV_SET_ACTIVE_WATCHER(self);
    if (!PyArg_ParseTuple(args, "iO!:set", &pid, &PyBool_Type, &trace)) {
        return NULL;
    }
    set_Child(self, pid, trace);
    Py_RETURN_NONE;
}


/* ChildType.tp_methods */
static PyMethodDef Child_tp_methods[] = {
    {"set", (PyCFunction)Child_set,
     METH_VARARGS, Child_set_doc},
    {NULL}  /* Sentinel */
};


/* Child.pid */
PyDoc_STRVAR(Child_pid_doc,
"pid");


/* Child.rpid */
PyDoc_STRVAR(Child_rpid_doc,
"rpid");


/* Child.rstatus */
PyDoc_STRVAR(Child_rstatus_doc,
"rstatus");


/* ChildType.tp_members */
static PyMemberDef Child_tp_members[] = {
    {"pid", T_INT, offsetof(Child, child.pid),
     READONLY, Child_pid_doc},
    {"rpid", T_INT, offsetof(Child, child.rpid),
     0, Child_rpid_doc},
    {"rstatus", T_INT, offsetof(Child, child.rstatus),
     0, Child_rstatus_doc},
    {NULL}  /* Sentinel */
};


/* ChildType */
static PyTypeObject ChildType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Child",                             /*tp_name*/
    sizeof(Child),                            /*tp_basicsize*/
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
    Child_tp_members,                         /*tp_members*/
    0,                                        /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Child_tp_init,                  /*tp_init*/
    0,                                        /*tp_alloc*/
    Child_tp_new,                             /*tp_new*/
};
