# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Markus Koetter
# SPDX-FileCopyrightText: 2016-2020 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import glob
import logging
import pkgutil
import traceback
from threading import Event, Thread
from typing import Callable, Optional

import yaml

logger = logging.getLogger('dionaea')
logger.setLevel(logging.DEBUG)

loaded_submodules = []


class RegisterClasses(type):
    def __init__(self, name, bases, nmspc):
        super(RegisterClasses, self).__init__(name, bases, nmspc)
        if not hasattr(self, 'registry'):
            self.registry = set()

        self.registry.add(self)
        self.registry -= set(bases)

    def __iter__(self):
        return iter(self.registry)


class ServiceLoader(object, metaclass=RegisterClasses):
    @classmethod
    def start(cls, addr, iface=None):
        raise NotImplementedError("do it")

    @classmethod
    def stop(cls, daemon):
        daemon.close()


class IHandlerLoader(object, metaclass=RegisterClasses):
    @classmethod
    def start(cls):
        raise NotImplementedError("do it")

    @classmethod
    def stop(cls, ihandler):
        ihandler.stop()


class SubTimer(Thread):
    """
    Our own Timer class because some attributes we have to user are undocumented in the Python stub files.

    :param interval: Wait interval sconds until the callback is called.
    :param function: The callback function.
    :param delay: Time in seconds before the callback is called for the first time. It not set interval is used.
    :param repeat: Call function every $interval seconds.
    :param args: Optional arguments passed to the callback function.
    :param kwargs: Opional arguments passed to the callback function.
    """
    def __init__(self, interval: float, function: Callable, delay: Optional[float] = None, repeat=False,
                 args: Optional[list] = None, kwargs: Optional[dict] = None):
        Thread.__init__(self)
        self.interval = interval
        self.function = function
        self.delay = delay
        if self.delay is None:
            self.delay = self.interval
        self.repeat = repeat
        self.args = args if args is not None else []
        self.kwargs = kwargs if kwargs is not None else {}
        self.finished = Event()

    def cancel(self):
        """Stop the timer if it hasn't finished yet."""
        self.finished.set()

    def run(self) -> None:
        self.finished.wait(self.delay)
        if not self.finished.is_set():
            self.function(*self.args, **self.kwargs)
        while self.repeat and not self.finished.wait(self.interval):
            if not self.finished.is_set():
                self.function(*self.args, **self.kwargs)


class Timer(object):
    """
    Extend Timer with additional functions like cancel and reset it. It uses the SubTimer() internally.

    :param interval: Wait interval sconds until the callback is called.
    :param function: The callback function.
    :param delay: Time in seconds before the callback is called for the first time. It not set interval is used.
    :param repeat: Call function every $interval seconds.
    :param args: Optional arguments passed to the callback function.
    :param kwargs: Opional arguments passed to the callback function.
    """
    def __init__(self, interval: float, function: Callable, delay: Optional[float] = None, repeat=False,
                 args: Optional[list] = None, kwargs: Optional[dict] = None):
        self.interval = interval
        self.function = function
        self.delay = delay
        if self.delay is None:
            self.delay = self.interval
        self.repeat = repeat
        self.args = args if args is not None else []
        self.kwargs = kwargs if kwargs is not None else {}
        self._timer: Optional[SubTimer] = None

    def start(self) -> None:
        """Start the Timer"""
        self._timer = SubTimer(
            interval=self.interval,
            function=self.function,
            delay=self.delay,
            repeat=self.repeat,
            args=self.args,
            kwargs=self.kwargs,
        )
        self._timer.start()

    def cancel(self) -> None:
        """Cancel the Timer"""
        if self._timer:
            self._timer.cancel()

    def reset(self) -> None:
        """Restart the Timer"""
        self.cancel()
        self.start()


def load_submodules(base_pkg=None):
    if base_pkg is None:
        import dionaea as base_pkg

    prefix = base_pkg.__name__ + "."
    for importer, modname, ispkg in pkgutil.iter_modules(base_pkg.__path__, prefix):
        if modname in loaded_submodules:
            continue

        logger.info("Import module %s", modname)
        try:
            __import__(modname, fromlist="dummy")
        except Exception as e:
            logger.warning("Error loading module: {}".format(str(e)))

            for msg in traceback.format_exc().split("\n"):
                logger.warning(msg.rstrip())

        loaded_submodules.append(modname)


def load_config_from_files(filename_patterns):
    configs = []
    for filename_pattern in filename_patterns:
        for filename in glob.glob(filename_pattern):
            fp = open(filename)
            try:
                file_configs = yaml.safe_load(fp)
            except yaml.YAMLError as e:
                if hasattr(e, 'problem_mark'):
                    mark = e.problem_mark
                    logger.error(
                        "Error while parsing config file '%s' at line: %d column: %d message: '%s'",
                        filename,
                        mark.line + 1,
                        mark.column + 1,
                        e.problem
                    )
                    if e.context is not None:
                        logger.debug("Parser(context): %s" % e.context)
                else:
                    logger.error("Unknown error while parsing config file '%s'", filename)

                # Skip processing
                continue

            if isinstance(file_configs, (tuple, list)):
                configs += file_configs
    return configs
