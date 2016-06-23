import re


class Command(object):
    @classmethod
    def from_line(cls, cmd_line):
        for cmd_cls in [Stats, StorageCommand, Delete, Get]:
            cmd = cmd_cls.from_line(cmd_line)
            if cmd is not None:
                return cmd


class Delete(Command):
    name = "delete"
    regex_cmd = re.compile(b"^(?P<command>\w+) (?P<key>\w+)( (?P<noreply>noreply))?$")

    def __init__(self, key=None, no_reply=None):
        self.key = key
        self.no_reply = no_reply

    @classmethod
    def from_line(cls, cmd_line):
        m = cls.regex_cmd.match(cmd_line)
        if m and m.group("command") == b"delete":
            return cls(
                key=m.group("key"),
                no_reply=m.group("noreply")
            )


class Get(Command):
    name = "get"

    def __init__(self, keys=None):
        if keys is None:
            keys = []
        self.keys = keys

    @classmethod
    def from_line(cls, cmd_line):
        cmd_parts = cmd_line.split(b" ")
        if len(cmd_parts) == 0:
            return None
        if cmd_parts[0] == b"get" or cmd_parts[0] == b"gets":
            return cls(keys=cmd_parts[1:])
        return None


class StorageCommand(Command):
    regex_cmd = re.compile(b"^(?P<command>\w+) (?P<key>\w+) (?P<flags>\d+) (?P<exptime>\d+) (?P<byte_count>\d+)( (?P<noreply>noreply))?")

    def __init__(self, key=None, flags=None, exptime=None, byte_count=None, noreply=None):
        self.key = key
        self.flags = flags
        self.exptime = exptime
        self.byte_count = byte_count
        self.noreply = noreply

    @classmethod
    def from_line(cls, cmd_line):
        cmd_classes = {
            b"add": Add
        }
        m = cls.regex_cmd.match(cmd_line)
        if m:
            cmd_class = cmd_classes.get(m.group("command"))
            if cmd_class is None:
                return None

            return cmd_class(
                key=m.group("key"),
                flags=m.group("flags"),
                exptime=m.group("exptime"),
                byte_count=int(m.group("byte_count")),
                noreply=m.group("noreply")
            )
        return None


class Add(StorageCommand):
    name = "add"


class Append(StorageCommand):
    name = "append"


class Prepand(StorageCommand):
    name = "prepand"


class Replace(StorageCommand):
    name = "replace"


class Set(StorageCommand):
    name = "set"


class Stats(Command):
    name = "stats"

    def __init__(self, arguments=None):
        if arguments is None:
            arguments = []
        self.arguments = arguments

    @property
    def sub_command(self):
        if len(self.arguments) > 0:
            return self.arguments[0]
        return None

    @classmethod
    def from_line(cls, cmd_line):
        cmd_parts = cmd_line.split(b" ")
        if len(cmd_parts) == 0:
            return None
        if cmd_parts[0] == b"stats":
            return cls(arguments=cmd_parts[1:])
        return None
