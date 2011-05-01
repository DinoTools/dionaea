/*******************************************************************************
* utilities
*******************************************************************************/

/* set the Timer */
int
set_Timer(Timer *self, double after, double repeat)
{
    PYEV_NEGATIVE_FLOAT(repeat);
    ev_timer_set(&self->timer, after, repeat);
    return 0;
}


/*******************************************************************************
* TimerType
*******************************************************************************/

/* TimerType.tp_doc */
PyDoc_STRVAR(Timer_tp_doc,
"Timer(after, repeat, loop, callback[, data=None, priority=0])");


/* TimerType.tp_new */
static PyObject *
Timer_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Timer *self = (Timer *)WatcherType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }
    new_Watcher((Watcher *)self, (ev_watcher *)&self->timer, EV_TIMER);
    return (PyObject *)self;
}


/* TimerType.tp_init */
static int
Timer_tp_init(Timer *self, PyObject *args, PyObject *kwargs)
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
    if (init_Watcher((Watcher *)self, loop, callback, 1, data, priority)) {
        return -1;
    }
    return set_Timer(self, after, repeat);
}


/* Timer.set(after, repeat) */
PyDoc_STRVAR(Timer_set_doc,
"set(after, repeat)");

static PyObject *
Timer_set(Timer *self, PyObject *args)
{
    double after, repeat;

    PYEV_SET_ACTIVE_WATCHER(self);
    if (!PyArg_ParseTuple(args, "dd:set", &after, &repeat)) {
        return NULL;
    }
    if (set_Timer(self, after, repeat)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


/* Timer.reset() */
PyDoc_STRVAR(Timer_reset_doc,
"reset()");

static PyObject *
Timer_reset(Timer *self)
{
    ev_timer_again(((Watcher *)self)->loop->loop, &self->timer);
    Py_RETURN_NONE;
}


/* Timer.remaining() -> float */
PyDoc_STRVAR(Timer_remaining_doc,
"remaining() -> float");

static PyObject *
Timer_remaining(Timer *self)
{
    return PyFloat_FromDouble(ev_timer_remaining(((Watcher *)self)->loop->loop,
                                                 &self->timer));
}


/* TimerType.tp_methods */
static PyMethodDef Timer_tp_methods[] = {
    {"set", (PyCFunction)Timer_set,
     METH_VARARGS, Timer_set_doc},
    {"reset", (PyCFunction)Timer_reset,
     METH_NOARGS, Timer_reset_doc},
    {"remaining", (PyCFunction)Timer_remaining,
     METH_NOARGS, Timer_remaining_doc},
    {NULL}  /* Sentinel */
};


/* Timer.repeat */
PyDoc_STRVAR(Timer_repeat_doc,
"repeat");

static PyObject *
Timer_repeat_get(Timer *self, void *closure)
{
    return PyFloat_FromDouble(self->timer.repeat);
}

static int
Timer_repeat_set(Timer *self, PyObject *value, void *closure)
{
    double repeat;

    PYEV_NULL_VALUE(value);
    repeat = PyFloat_AsDouble(value);
    if (repeat == -1 && PyErr_Occurred()) {
        return -1;
    }
    PYEV_NEGATIVE_FLOAT(repeat);
    self->timer.repeat = repeat;
    return 0;
}


/* TimerType.tp_getsets */
static PyGetSetDef Timer_tp_getsets[] = {
    {"repeat", (getter)Timer_repeat_get, (setter)Timer_repeat_set,
     Timer_repeat_doc, NULL},
    {NULL}  /* Sentinel */
};


/* TimerType */
static PyTypeObject TimerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Timer",                             /*tp_name*/
    sizeof(Timer),                            /*tp_basicsize*/
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
