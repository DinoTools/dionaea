import random
from collections import OrderedDict
from datetime import datetime

CFG_STAT_VARS = [
    {
        "name": "pid",
        "type": "uint32",
        "value": {
            "value_min": 2000,
            "value_max": 4000,
            "value_random": True
        }
    },
    {
        "name": "uptime",
        "type": "uptime",
    },
    {
        "name": "time",
        "type": "time",
    },
    {
        "name": "version",
        "type": "string",
        "value": "1.4.25"
    },
    {
        "name": "pointer_size",
        "type": "uint32",
        "value": 64
    },
    {
        "name": "rusage_user",
        "type": "float",
        "value": 0.55
    },
    {
        "name": "rusage_system",
        "type": "float",
        "value": 0.253
    },
    {
        "name": "accepting_conns ",
        "type": "bool",
        "value": True
    },
]


class VarHandler(object):
    def __init__(self):
        self.values = OrderedDict()

    def _get_var_class(self, name):
        if name == "bool":
            return Bool
        if name == "float":
            return Float
        if name == "string":
            return String
        if name == "time":
            return Time
        if name == "uint32":
            return UInt32
        if name == "uint64":
            return UInt64
        if name == "uptime":
            return Uptime

    def load(self, vars):
        for var in vars:
            var_cls = self._get_var_class(var.get("type"))
            value = var.get("value", None)

            var_params = {}
            if isinstance(value, dict):
                var_params = value
            elif value is not None:
                var_params = {"value": value}
            self.values[var.get("name")] = var_cls(**var_params)


class BaseVar(object):
    pass


class Bool(BaseVar):
    def __init__(self, value=False):
        if not isinstance(value, bool):
            raise ValueError("Value must be boolean")
        self.value = value

    def __str__(self):
        if self.value:
            return "1"
        return "0"


class Float(BaseVar):
    def __init__(self, value=0.0):
        self._value = 0.0
        self.value = value

    def __str__(self):
        return "%.6f" % self.value

    def _get_value(self):
        return self._value

    def _set_value(self, value):
        self._value = value

    value = property(_get_value, _set_value)


class String(BaseVar):
    def __init__(self, value=""):
        if not isinstance(value, str):
            raise ValueError("Value must be string")
        self.value = value

    def __str__(self):
        return self.value


class Time(BaseVar):
    @property
    def value(self):
        return int(datetime.now().timestamp())

    def __str__(self):
        return str(self.value)


class UIntBase(BaseVar):
    default_value_max = 0

    def __init__(self, value=0, value_min=0, value_max=None, value_random=False):
        if not isinstance(value, int):
            raise ValueError("Value must be integer")
        self._value = 0
        self.value_min = value_min
        self.value_max = self.default_value_max
        if value_max is not None:
            self.value_max = value_max

        if value_random:
            self.value = random.randint(self.value_min, self.value_max)
        else:
            self.value = value

    def __str__(self):
        return str(self.value)

    def _value_get(self):
        return self._value

    def _value_set(self, value):
        if value < 0 or value > 2**32-1:
            raise ValueError("Value is '%d' but allowed range ist >0 and < 2°32-1", value)
        self._value = value

    value = property(_value_get, _value_set)


class UInt32(UIntBase):
    default_value_max = 2**32-1


class UInt64(UIntBase):
    default_value_max = 2**64-1


class Uptime(BaseVar):
    def __init__(self):
        self.start_time = datetime.now()

    def __str__(self):
        return str(self.value)

    @property
    def value(self):
        delta = datetime.now() - self.start_time
        return delta.seconds
