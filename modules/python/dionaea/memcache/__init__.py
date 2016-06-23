import logging

from dionaea import ServiceLoader
from dionaea.core import connection, incident
from dionaea.exception import ServiceConfigError
from .command import Command
from .var import VarHandler


logger = logging.getLogger("memcache")
logger.setLevel(logging.DEBUG)


class MemcacheService(ServiceLoader):
    name = "memcache"

    @classmethod
    def start(cls, addr, iface=None, config=None):
        if config is None:
            config = {}

        daemon = Memcache(proto="tcp")
        try:
            daemon.apply_config(config)
        except ServiceConfigError as e:
            logger.error(e.msg, *e.args)
            return

        daemon.bind(addr, 11211, iface=iface)
        daemon.listen()

        return [daemon]


class Memcache(connection):
    stat_vars = VarHandler()

    def __init__(self, proto="tcp"):
        logger.debug("start memcache")
        connection.__init__(self, proto)
        self.command = None

    def _handle_add(self, data):
        read_len = self._handle_storage_command(data)
        if read_len == 0:
            return 0
        self.command = None
        self._send_line("STORED")
        return read_len

    def _handle_append(self, data):
        read_len = self._handle_storage_command(data)
        if read_len == 0:
            return 0
        self.command = None
        self._send_line("STORED")
        return read_len

    def _handle_delete(self, data):
        self.command = None
        self._send_line("DELETED")
        return 0

    def _handle_get(self, data):
        self.command = None
        self._send_line("END")
        return 0

    def _handle_prepand(self, data):
        read_len = self._handle_storage_command(data)
        if read_len == 0:
            return 0
        self.command = None
        self._send_line("STORED")
        return read_len

    def _handle_replace(self, data):
        read_len = self._handle_storage_command(data)
        if read_len == 0:
            return 0
        self.command = None
        self._send_line("STORED")
        return read_len

    def _handle_set(self, data):
        read_len = self._handle_storage_command(data)
        if read_len == 0:
            return 0
        self.command = None
        self._send_line("STORED")
        return read_len

    def _handle_storage_command(self, data):
        if len(data) < self.command.byte_count + 2:
            return 0
        return self.command.byte_count + 2

    def _handle_stats(self, data):
        if self.command.sub_command is None:
            for name, var in self.stat_vars.values.items():
                self._send_line("STAT %s %s" % (name, str(var)))
            self._send_line("END")
        elif self.command.sub_command == "conns":
            self._send_line("END")
        # elif self.command.sub_command == "items":
        #     self._send_line("END")
        # elif self.command.sub_command == "settings":
        #     self._send_line("END")
        # elif self.command.sub_command == "sizes":
        #     self._send_line("END")
        # elif self.command.sub_command == "slabs":
        #     self._send_line("END")
        self.command = None
        return 0

    def _send_line(self, line):
        self.send(line + "\r\n")

    def apply_config(self, config):
        from .var import CFG_STAT_VARS
        self.stat_vars.load(CFG_STAT_VARS)

    def handle_established(self):
        self.timeouts.idle = 10
        self.processors()

    def handle_io_in(self, data):
        processed_bytes = 0
        if self.command is None:
            # End Of Command
            eoc = data.find(b"\r\n")
            if eoc == -1:
                return 0
            logger.debug("Command line: %r", data[:eoc])
            self.command = Command.from_line(cmd_line=data[:eoc])
            # End of Line
            processed_bytes = eoc + 2
            data = data[processed_bytes:]

        if self.command is not None:
            func = getattr(self, "_handle_%s" % self.command.name)
            processed_bytes = processed_bytes + func(data)

        return processed_bytes
