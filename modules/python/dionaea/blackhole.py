import logging

from dionaea import ServiceLoader
from dionaea.core import connection
from dionaea.exception import ServiceConfigError


logger = logging.getLogger("blackhole")
logger.setLevel(logging.DEBUG)


class BlackholeService(ServiceLoader):
    name = "blackhole"

    @classmethod
    def start(cls, addr, iface=None, config=None):
        if config is None:
            config = {}

        services = config.get("services")
        if services is None:
            logger.warning("No services configured")

        daemons = []

        for service in services:
            protocol = service.get("protocol")
            port = service.get("port")
            if protocol is None:
                protocol = "tcp"

            if port is None:
                logger.warning("port not defined")
                continue
            if not isinstance(port, int):
                logger.warning("port must be integer")
                continue

            daemon = Blackhole(proto=protocol)
            try:
                daemon.apply_config(config)
            except ServiceConfigError as e:
                logger.error(e.msg, *e.args)
                continue

            daemon.bind(addr, port, iface=iface)
            daemon.listen()
            daemons.append(daemon)

        return daemons


class Blackhole(connection):
    def __init__(self, proto):
        logger.debug("start blackhole")
        connection.__init__(self, proto)

    def handle_established(self):
        self.timeouts.idle = 10
        self.processors()

    def handle_io_in(self, data):
        return len(data)

    def handle_timeout_idle(self):
        logger.debug("%r handle_timeout_idle", self)
        self.close()
        return False
