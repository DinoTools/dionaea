from dionaea import ServiceLoader
from .pptp import pptpd


class PPTPService(ServiceLoader):
    name = "pptp"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        daemon = pptpd()
        daemon.bind(addr, 1723, iface=iface)
        daemon.listen()
        return daemon
