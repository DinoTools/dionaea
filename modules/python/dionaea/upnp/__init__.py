from dionaea import ServiceLoader
from dionaea.core import g_dionaea
from .upnp import upnpd


class UPNPService(ServiceLoader):
    name = "upnp"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        daemon = upnpd()
        daemon.apply_config(config)
        daemon.bind(addr, 1900, iface=iface)
        daemon.listen()
        return daemon
