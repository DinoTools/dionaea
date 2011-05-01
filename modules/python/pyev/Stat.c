/*******************************************************************************
* StatdataType
*******************************************************************************/

static PyStructSequence_Field Statdata_fields[] = {
    {"dev",   "device"},
    {"rdev",  "device type"},
    {"ino",   "inode"},
    {"size",  "total size, in bytes"},
    {"nlink", "number of hard links"},
    {"mode",  "protection bits"},
    {"uid",   "user ID of owner"},
    {"gid",   "group ID of owner"},
    {"atime", "time of last access"},
    {"mtime", "time of last modification"},
    {"ctime", "time of last status change"},
    {NULL}  /* Sentinel */
};


static PyStructSequence_Desc Statdata_desc = {
    "pyev.Statdata",                          /*name*/
    "Statdata object",                        /*doc*/
    Statdata_fields,                          /*fields*/
    11,                                       /*n_in_sequence*/
};


/* new_Statdata - instanciate a Statdata */
PyObject *
new_Statdata(ev_statdata *statdata)
{
    PyObject *self;

    self = PyStructSequence_New(&StatdataType);
    if (!self) {
        return NULL;
    }

#ifdef HAVE_LONG_LONG
    PyStructSequence_SET_ITEM(self, 0,
        PyLong_FromUnsignedLongLong((unsigned PY_LONG_LONG)statdata->st_dev));
    PyStructSequence_SET_ITEM(self, 1,
        PyLong_FromUnsignedLongLong((unsigned PY_LONG_LONG)statdata->st_rdev));
#else
    PyStructSequence_SET_ITEM(self, 0,
        PyLong_FromUnsignedLong((unsigned long)statdata->st_dev));
    PyStructSequence_SET_ITEM(self, 1,
        PyLong_FromUnsignedLong((unsigned long)statdata->st_rdev));
#endif

#ifdef HAVE_LARGEFILE_SUPPORT
    PyStructSequence_SET_ITEM(self, 2,
        PyLong_FromUnsignedLongLong((unsigned PY_LONG_LONG)statdata->st_ino));
    PyStructSequence_SET_ITEM(self, 3,
        PyLong_FromLongLong((PY_LONG_LONG)statdata->st_size));
#else
    PyStructSequence_SET_ITEM(self, 2,
        PyLong_FromUnsignedLong((unsigned long)statdata->st_ino));
    PyStructSequence_SET_ITEM(self, 3,
        PyLong_FromLong((long)statdata->st_size));
#endif

    PyStructSequence_SET_ITEM(self, 4,
        PyInt_FromUnsignedLong((unsigned long)statdata->st_nlink));
    PyStructSequence_SET_ITEM(self, 5,
        PyInt_FromUnsignedLong((unsigned long)statdata->st_mode));
    PyStructSequence_SET_ITEM(self, 6,
        PyInt_FromUnsignedLong((unsigned long)statdata->st_uid));
    PyStructSequence_SET_ITEM(self, 7,
        PyInt_FromUnsignedLong((unsigned long)statdata->st_gid));

#if SIZEOF_TIME_T > SIZEOF_LONG
    PyStructSequence_SET_ITEM(self, 8,
        PyLong_FromLongLong((PY_LONG_LONG)statdata->st_atime));
    PyStructSequence_SET_ITEM(self, 9,
        PyLong_FromLongLong((PY_LONG_LONG)statdata->st_mtime));
    PyStructSequence_SET_ITEM(self, 10,
        PyLong_FromLongLong((PY_LONG_LONG)statdata->st_ctime));
#else
    PyStructSequence_SET_ITEM(self, 8,
        PyLong_FromLong((long)statdata->st_atime));
    PyStructSequence_SET_ITEM(self, 9,
        PyLong_FromLong((long)statdata->st_mtime));
    PyStructSequence_SET_ITEM(self, 10,
        PyLong_FromLong((long)statdata->st_ctime));
#endif

    if (PyErr_Occurred()) {
        Py_DECREF(self);
        return NULL;
    }
    return self;
}


/*******************************************************************************
* utilities
*******************************************************************************/

/* update Stat current and previous member */
int
update_Stat(Stat *self)
{
    PyObject *current, *tmp;

    current = new_Statdata(&self->stat.attr);
    if (!current) {
        return -1;
    }
    tmp = self->previous;
    self->previous = self->current;
    self->current = current;
    Py_XDECREF(tmp);
    return 0;
}


/* set the Stat */
int
set_Stat(Stat *self, PyObject *pypath, double interval)
{
    const char *path;

    path = PyString_AsPath(pypath);
    if (!path) {
        return -1;
    }
    ev_stat_set(&self->stat, path, interval);
    return 0;
}


/*******************************************************************************
* StatType
*******************************************************************************/

/* StatType.tp_doc */
PyDoc_STRVAR(Stat_tp_doc,
"Stat(path, interval, loop, callback[, data=None, priority=0])");


/* StatType.tp_dealloc */
static void
Stat_tp_dealloc(Stat *self)
{
    Py_XDECREF(self->previous);
    Py_XDECREF(self->current);
    WatcherType.tp_dealloc((PyObject *)self);
}


/* StatType.tp_new */
static PyObject *
Stat_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Stat *self = (Stat *)WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }
    new_Watcher((Watcher *)self, (ev_watcher *)&self->stat, EV_STAT);
    return (PyObject *)self;
}


/* StatType.tp_init */
static int
Stat_tp_init(Stat *self, PyObject *args, PyObject *kwargs)
{
    PyObject *path;
    double interval;
    Loop *loop;
    PyObject *callback, *data = NULL;
    int priority = 0;

    static char *kwlist[] = {"path", "interval",
                             "loop", "callback", "data", "priority", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OdO!O|Oi:__init__", kwlist,
            &path, &interval,
            &LoopType, &loop, &callback, &data, &priority)) {
        return -1;
    }
    if (init_Watcher((Watcher *)self, loop, callback, 1, data, priority)) {
        return -1;
    }
    return set_Stat(self, path, interval);
}


/* Stat.set(path, interval) */
PyDoc_STRVAR(Stat_set_doc,
"set(path, interval)");

static PyObject *
Stat_set(Stat *self, PyObject *args)
{
    PyObject *path;
    double interval;

    PYEV_SET_ACTIVE_WATCHER(self);
    if (!PyArg_ParseTuple(args, "Od:set", &path, &interval)) {
        return NULL;
    }
    if (set_Stat(self, path, interval)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


/* Stat.stat() */
PyDoc_STRVAR(Stat_stat_doc,
"stat()");

static PyObject *
Stat_stat(Stat *self)
{
    ev_stat_stat(((Watcher *)self)->loop->loop, &self->stat);
    if (!self->stat.attr.st_nlink) {
        return PyErr_SetFromErrnoWithFilename(PyExc_OSError,
                                              (char *)self->stat.path);
    }
    if (update_Stat(self)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


/* StatType.tp_methods */
static PyMethodDef Stat_tp_methods[] = {
    {"set", (PyCFunction)Stat_set,
     METH_VARARGS, Stat_set_doc},
    {"stat", (PyCFunction)Stat_stat,
     METH_NOARGS, Stat_stat_doc},
    {NULL}  /* Sentinel */
};


/* Stat.current */
PyDoc_STRVAR(Stat_current_doc,
"current");


/* Stat.previous */
PyDoc_STRVAR(Stat_previous_doc,
"previous");


/* Stat.interval */
PyDoc_STRVAR(Stat_interval_doc,
"interval");


/* StatType.tp_members */
static PyMemberDef Stat_tp_members[] = {
    {"current", T_OBJECT, offsetof(Stat, current),
     READONLY, Stat_current_doc},
    {"previous", T_OBJECT, offsetof(Stat, previous),
     READONLY, Stat_previous_doc},
    {"interval", T_DOUBLE, offsetof(Stat, stat.interval),
     READONLY, Stat_interval_doc},
    {NULL}  /* Sentinel */
};


/* Stat.path */
PyDoc_STRVAR(Stat_path_doc,
"path");

static PyObject *
Stat_path_get(Stat *self, void *closure)
{
    return PyString_FromPath(self->stat.path);
}


/* StatType.tp_getsets */
static PyGetSetDef Stat_tp_getsets[] = {
    {"path", (getter)Stat_path_get, NULL,
     Stat_path_doc, NULL},
    {NULL}  /* Sentinel */
};


/* StatType */
static PyTypeObject StatType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Stat",                              /*tp_name*/
    sizeof(Stat),                             /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Stat_tp_dealloc,              /*tp_dealloc*/
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
    Stat_tp_doc,                              /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Stat_tp_methods,                          /*tp_methods*/
    Stat_tp_members,                          /*tp_members*/
    Stat_tp_getsets,                          /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Stat_tp_init,                   /*tp_init*/
    0,                                        /*tp_alloc*/
    Stat_tp_new,                              /*tp_new*/
};
