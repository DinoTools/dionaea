/*******************************************************************************
* utilities
*******************************************************************************/

static void
Scheduler_Stop(struct ev_loop *loop, ev_prepare *prepare, int revents)
{
    Scheduler *self = prepare->data;
    ev_periodic_stop(loop, (ev_periodic *)((Watcher *)self)->watcher);
    ev_prepare_stop(loop, prepare);
    PyErr_Restore(self->err_type, self->err_value, self->err_traceback);
    if (self->err_fatal) {
        PYEV_LOOP_EXIT(loop);
    }
    else {
        Loop_WarnOrStop(ev_userdata(loop), self->scheduler);
    }
    self->err_fatal = 0;
    self->err_traceback = NULL;
    self->err_value = NULL;
    self->err_type = NULL;
}


static double
Scheduler_Schedule(ev_periodic *periodic, double now)
{
    Scheduler *self = periodic->data;
    PyObject *pynow = NULL, *pyresult = NULL;
    double result;

    pynow = PyFloat_FromDouble(now);
    if (!pynow) {
        self->err_fatal = 1;
        goto fail;
    }
    pyresult = PyObject_CallFunctionObjArgs(self->scheduler, self, pynow, NULL);
    if (!pyresult) {
        goto fail;
    }
    result = PyFloat_AsDouble(pyresult);
    if (result == -1.0 && PyErr_Occurred()) {
        goto fail;
    }
    if (result < now) {
        PyErr_SetString(Error, "returned value must be >= 'now' param");
        goto fail;
    }
    goto finish;

fail:
    PyErr_Fetch(&self->err_type, &self->err_value, &self->err_traceback);
    ev_prepare_start(((Watcher *)self)->loop->loop, self->prepare);
    result = now + 1e30;

finish:
    Py_XDECREF(pyresult);
    Py_XDECREF(pynow);
    return result;
}


int
Scheduler_SetScheduler(Scheduler *self, PyObject *scheduler)
{
    PYEV_CHECK_CALLABLE(scheduler);
    PyObject *tmp = self->scheduler;
    Py_INCREF(scheduler);
    self->scheduler = scheduler;
    Py_XDECREF(tmp);
    return 0;
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
    Scheduler_tp_clear(self);
    if (self->prepare) {
        if (((Watcher *)self)->loop) {
            ev_prepare_stop(((Watcher *)self)->loop->loop, self->prepare);
        }
        PyMem_Free(self->prepare);
        self->prepare = NULL;
    }
    PeriodicBaseType.tp_dealloc((PyObject *)self);
}


/* Scheduler.scheduler */
static PyObject *
Scheduler_scheduler_get(Scheduler *self, void *closure)
{
    Py_INCREF(self->scheduler);
    return self->scheduler;
}

static int
Scheduler_scheduler_set(Scheduler *self, PyObject *value, void *closure)
{
    PYEV_PROTECTED_ATTRIBUTE(value);
    return Scheduler_SetScheduler(self, value);
}


/* SchedulerType.tp_getsets */
static PyGetSetDef Scheduler_tp_getsets[] = {
    {"scheduler", (getter)Scheduler_scheduler_get,
     (setter)Scheduler_scheduler_set, NULL, NULL},
    {NULL}  /* Sentinel */
};


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
    if (Watcher_Init((Watcher *)self, loop, callback, data, priority)) {
        return -1;
    }
    return Scheduler_SetScheduler(self, scheduler);
}


/* SchedulerType.tp_new */
static PyObject *
Scheduler_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    Scheduler *self = (Scheduler *)PeriodicBaseType.tp_new(type, args, kwargs);
    if (!self) {
        return NULL;
    }
    self->prepare = PyMem_Malloc(sizeof(ev_prepare));
    if (!self->prepare) {
        PyErr_NoMemory();
        Py_DECREF(self);
        return NULL;
    }
    ev_prepare_init(self->prepare, Scheduler_Stop);
    self->prepare->data = self;
    ev_periodic_set((ev_periodic *)((Watcher *)self)->watcher,
                    0.0, 0.0, Scheduler_Schedule);
    return (PyObject *)self;
}


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
