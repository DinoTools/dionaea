from dionaea import ServiceLoader
from .mysql import mysqld


class MYSQLService(ServiceLoader):
    name = "mysql"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        daemon = mysqld()
        daemon.apply_config(config)
        daemon.bind(addr, 3306, iface=iface)
        daemon.listen()
        return daemon
