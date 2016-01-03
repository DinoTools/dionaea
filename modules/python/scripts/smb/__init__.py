from dionaea import ServiceLoader
from .smb import epmapper, smbd


class EPMAPService(ServiceLoader):
    name = "epmap"

    @classmethod
    def start(cls, addr,  iface=None):
        daemon = epmapper()
        daemon.bind(addr, 135, iface=iface)
        daemon.listen()
        return daemon


class SMBService(ServiceLoader):
    name = "smb"

    @classmethod
    def start(cls, addr,  iface=None):
        daemon = smbd()
        daemon.bind(addr, 445, iface=iface)
        daemon.listen()
        return daemon
