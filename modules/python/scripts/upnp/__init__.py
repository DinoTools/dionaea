from dionaea import ServiceLoader
from dionaea.core import g_dionaea
from .upnp import upnpd


class UPNPService(ServiceLoader):
    name = "upnp"

    @classmethod
    def start(cls, addr,  iface=None):
        daemon = upnpd()
        daemon.bind(addr, 1900, iface=iface)
        daemon.chroot(g_dionaea.config()['modules']['python']['upnp']['root'])
        daemon.listen()
        return daemon
