from dionaea import ServiceLoader
from .mysql import mysqld


class MYSQLService(ServiceLoader):
    name = "mysql"

    @classmethod
    def start(cls, addr,  iface=None):
        daemon = mysqld()
        daemon.bind(addr, 3306, iface=iface)
        daemon.listen()
        return daemon
