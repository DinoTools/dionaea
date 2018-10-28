from dionaea import ServiceLoader
from dionaea.exception import ServiceConfigError
from .smb import epmapper, smbd, smblog


class EPMAPService(ServiceLoader):
    name = "epmap"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        daemon = epmapper()
        daemon.bind(addr, 135, iface=iface)
        daemon.listen()
        return daemon


class SMBService(ServiceLoader):
    name = "smb"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        daemon = smbd()
        try:
            daemon.apply_config(config=config)
        except ServiceConfigError as e:
            smblog.error(e.msg, *e.args)
            return
        daemon.bind(addr, daemon.config.port, iface=iface)
        daemon.listen()
        return daemon
