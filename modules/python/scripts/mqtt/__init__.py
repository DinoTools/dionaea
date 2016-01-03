from dionaea import ServiceLoader
from .mqtt import mqttd


class MQTTService(ServiceLoader):
    name = "mqtt"

    @classmethod
    def start(cls, addr,  iface=None):
        daemon = mqttd()
        daemon.bind(addr, 1883, iface=iface)
        daemon.listen()
        return daemon
