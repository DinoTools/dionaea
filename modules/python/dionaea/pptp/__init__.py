from dionaea import ServiceLoader
from dionaea.exception import ServiceConfigError
from .pptp import pptpd


class PPTPService(ServiceLoader):
    name = "pptp"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        daemon = pptpd()
        try:
            daemon.apply_config(config)
        except ServiceConfigError as e:
            logger.error(e.msg, *e.args)
            return
        daemon.bind(addr, 1723, iface=iface)
        daemon.listen()
        return daemon
