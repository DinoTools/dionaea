import glob
import logging
import pkgutil
import traceback

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