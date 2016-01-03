from dionaea import ServiceLoader
from .mssql import mssqld

class MSSQLService(ServiceLoader):
    name = "mssql"

    @classmethod
    def start(cls, addr,  iface=None):
        daemon = mssqld()
        daemon.bind(addr, 1433, iface=iface)
        daemon.listen()
        return daemon
