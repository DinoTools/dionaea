/*******************************************************************************
* utilities
*******************************************************************************/

/* set the Timer */
int
Timer_Set(Watcher *self, double after, double repeat)
{
    PYEV_CHECK_POSITIVE_OR_ZERO_FLOAT(repeat);
    ev_timer_set((ev_timer *)self->watcher, after, repeat);
    return 0;
}


/*******************************************************************************
* TimerType
*******************************************************************************/

/* TimerType.tp_doc */
PyDoc_STRVAR(Timer_tp_doc,
"Timer(after, repeat, loop, callback[, data=None, priority=0])");


/* Timer.set(after, repeat) */
PyDoc_STRVAR(Timer_set_doc,
"set(after, repeat)");

static PyObject *
Timer_set(Watcher *self, PyObject *args)
{
    double after, repeat;

    PYEV_WATCHER_SET(self);
    if (!PyArg_ParseTuple(args, "dd:set", &after, &repeat)) {
        return NULL;
    }
    if (Timer_Set(self, after, repeat)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


/* Timer.reset() */
PyDoc_STRVAR(Timer_reset_doc,
"reset()");

static PyObject *
Timer_reset(Watcher *self)
{
    ev_timer_again(self->loop->loop, (ev_timer *)self->watcher);
    Py_RETURN_NONE;
}


/* TimerType.tp_methods */
static PyMethodDef Timer_tp_methods[] = {
    {"set", (PyCFunction)Timer_set,
     METH_VARARGS, Timer_set_doc},
    {"reset", (PyCFunction)Timer_reset,
     METH_NOARGS, Timer_reset_doc},
    {NULL}  /* Sentinel */
};


/* Timer.repeat */
static PyObject *
Timer_repeat_get(Watcher *self, void *closure)
{
    return PyFloat_FromDouble(((ev_timer *)self->watcher)->repeat);
}

static int
Timer_repeat_set(Watcher *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    double repeat = PyFloat_AsDouble(value);
    if (repeat == -1.0 && PyErr_Occurred()) {
        return -1;
    }
    PYEV_CHECK_POSITIVE_OR_ZERO_FLOAT(repeat);
    ((ev_timer *)self->watcher)->repeat = repeat;
    return 0;
}


/* Timer.remaining */
static PyObject *
Timer_remaining_get(Watcher *self, void *closure)
{
    return PyFloat_FromDouble(
        ev_timer_remaining(self->loop->loop, (ev_timer *)self->watcher));
}


/* TimerType.tp_getsets */
static PyGetSetDef Timer_tp_getsets[] = {
    {"repeat", (getter)Timer_repeat_get,
     (setter)Timer_repeat_set, NULL, NULL},
    {"remaining", (getter)Timer_remaining_get,
     Readonly_attribute_set, NULL, NULL},
    {NULL}  /* Sentinel */
};


/* TimerType.tp_init */
static int
Timer_tp_init(Watcher *self, PyObject *args, PyObject *kwargs)
{
    double after, repeat;
    Loop *loop;
    PyObject *callback, *data = NULL;
    int priority = 0;

    static char *kwlist[] = {"after", "repeat",
                             "loop", "callback", "data", "priority", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ddO!O|Oi:__init__", kwlist,
            &after, &repeat,
            &LoopType, &loop, &callback, &data, &priority)) {
        return -1;
    }
    if (Watcher_Init(self, loop, callback, data, priority)) {
        return -1;
    }
    return Timer_Set(self, after, repeat);
}


/* TimerType.tp_new */
static PyObject *
Timer_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return (PyObject *)Watcher_New(type, EV_TIMER, sizeof(ev_timer));
}


/* TimerType */
static PyTypeObject TimerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Timer",                             /*tp_name*/
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
    Timer_tp_doc,                             /*tp_doc*/
    0,                                        /*tp_traverse*/
    0,                                        /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    Timer_tp_methods,                         /*tp_methods*/
    0,                                        /*tp_members*/
    Timer_tp_getsets,                         /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Timer_tp_init,                  /*tp_init*/
    0,                                        /*tp_alloc*/
    Timer_tp_new,                             /*tp_new*/
};
