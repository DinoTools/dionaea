/*******************************************************************************
* utilities
*******************************************************************************/

int
set_scheduler_Scheduler(Scheduler *self, PyObject *value)
{
    PyObject *tmp;

    PYEV_CALLABLE_VALUE(value);
    tmp = self->scheduler;
    Py_INCREF(value);
    self->scheduler = value;
    Py_XDECREF(tmp);
    return 0;
}


static void
stop_scheduler_Scheduler(ev_loop *loop, ev_prepare *prepare, int revents)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    Scheduler *self = prepare->data;

    ev_periodic_stop(loop, &((PeriodicBase *)self)->periodic);
    ev_prepare_stop(loop, &self->prepare);
    PyErr_Restore(self->err_type, self->err_value, self->err_traceback);
    if (self->err_fatal) {
        PYEV_EXIT_LOOP(loop);
    }
    else {
        set_error_Loop(ev_userdata(loop), self->scheduler);
    }
    self->err_fatal = 0;
    self->err_traceback = NULL;
    self->err_value = NULL;
    self->err_type = NULL;
    PyGILState_Release(gstate);
}


/* Scheduler scheduler callback */
static double
scheduler_Scheduler(ev_periodic *periodic, double now)
{
    PyGILState_STATE gstate = PyGILState_Ensure();
    double result;
    Scheduler *self = periodic->data;
    PyObject *pynow, *pyresult = NULL;

    pynow = PyFloat_FromDouble(now);
    if (!pynow) {
        self->err_fatal = 1;
        goto error;
    }
    pyresult = PyObject_CallFunctionObjArgs(self->scheduler, self, pynow, NULL);
    if (!pyresult) {
        goto error;
    }
    result = PyFloat_AsDouble(pyresult);
    if (result == -1 && PyErr_Occurred()) {
        goto error;
    }
    if (result < now) {
        PyErr_SetString(Error, "returned value must be >= 'now' param");
        goto error;
    }
    goto finish;

error:
    PyErr_Fetch(&self->err_type, &self->err_value, &self->err_traceback);
    ev_prepare_start(((Watcher *)self)->loop->loop, &self->prepare);
    result = now + 1e30;

finish:
    Py_XDECREF(pyresult);
    Py_XDECREF(pynow);
    PyGILState_Release(gstate);
    return result;
}


/*******************************************************************************
* SchedulerType
*******************************************************************************/

/* SchedulerType.tp_doc */
PyDoc_STRVAR(Scheduler_tp_doc,
"Scheduler(scheduler, loop, callback[, data=None, priority=0])");


/* SchedulerType.tp_traverse */
static int
Scheduler_tp_traverse(Scheduler *self, visitproc visit, void *arg)
{
    Py_VISIT(self->err_traceback);
    Py_VISIT(self->err_value);
    Py_VISIT(self->err_type);
    Py_VISIT(self->scheduler);
    return 0;
}


/* SchedulerType.tp_clear */
static int
Scheduler_tp_clear(Scheduler *self)
{
    Py_CLEAR(self->err_traceback);
    Py_CLEAR(self->err_value);
    Py_CLEAR(self->err_type);
    Py_CLEAR(self->scheduler);
    return 0;
}


/* SchedulerType.tp_dealloc */
static void
Scheduler_tp_dealloc(Scheduler *self)
{
    if (((Watcher *)self)->loop) {
        ev_prepare_stop(((Watcher *)self)->loop->loop, &self->prepare);
    }
    Scheduler_tp_clear(self);
    PeriodicBaseType.tp_dealloc((PyObject *)self);
}


/* SchedulerType.tp_new */
static PyObject *
Scheduler_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Scheduler *self = (Scheduler *)PeriodicBaseType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }
    self->prepare.data = (void *)self;
    ev_prepare_init(&self->prepare, stop_scheduler_Scheduler);
    ev_periodic_set(&((PeriodicBase *)self)->periodic, 0.0, 0.0,
                    scheduler_Scheduler);
    return (PyObject *)self;
}


/* SchedulerType.tp_init */
static int
Scheduler_tp_init(Scheduler *self, PyObject *args, PyObject *kwargs)
{
    PyObject *scheduler;
    Loop *loop;
    PyObject *callback, *data = NULL;
    int priority = 0;

    static char *kwlist[] = {"scheduler",
                             "loop", "callback", "data", "priority", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO!O|Oi:__init__", kwlist,
            &scheduler,
            &LoopType, &loop, &callback, &data, &priority)) {
        return -1;
    }
    if (init_Watcher((Watcher *)self, loop, callback, 1, data, priority)) {
        return -1;
    }
    return set_scheduler_Scheduler(self, scheduler);
}


/* Scheduler.scheduler */
PyDoc_STRVAR(Scheduler_scheduler_doc,
"scheduler");

static PyObject *
Scheduler_scheduler_get(Scheduler *self, void *closure)
{
    Py_INCREF(self->scheduler);
    return self->scheduler;
}

static int
Scheduler_scheduler_set(Scheduler *self, PyObject *value, void *closure)
{
    PYEV_NULL_VALUE(value);
    return set_scheduler_Scheduler(self, value);
}


/* SchedulerType.tp_getsets */
static PyGetSetDef Scheduler_tp_getsets[] = {
    {"scheduler", (getter)Scheduler_scheduler_get,
     (setter)Scheduler_scheduler_set,
     Scheduler_scheduler_doc, NULL},
    {NULL}  /* Sentinel */
};


/* SchedulerType */
static PyTypeObject SchedulerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyev.Scheduler",                         /*tp_name*/
    sizeof(Scheduler),                        /*tp_basicsize*/
    0,                                        /*tp_itemsize*/
    (destructor)Scheduler_tp_dealloc,         /*tp_dealloc*/
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
    Scheduler_tp_doc,                         /*tp_doc*/
    (traverseproc)Scheduler_tp_traverse,      /*tp_traverse*/
    (inquiry)Scheduler_tp_clear,              /*tp_clear*/
    0,                                        /*tp_richcompare*/
    0,                                        /*tp_weaklistoffset*/
    0,                                        /*tp_iter*/
    0,                                        /*tp_iternext*/
    0,                                        /*tp_methods*/
    0,                                        /*tp_members*/
    Scheduler_tp_getsets,                     /*tp_getsets*/
    0,                                        /*tp_base*/
    0,                                        /*tp_dict*/
    0,                                        /*tp_descr_get*/
    0,                                        /*tp_descr_set*/
    0,                                        /*tp_dictoffset*/
    (initproc)Scheduler_tp_init,              /*tp_init*/
    0,                                        /*tp_alloc*/
    Scheduler_tp_new,                         /*tp_new*/
};
