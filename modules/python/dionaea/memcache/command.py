class Command(object):
    @classmethod
    def from_line(cls, cmd_line):
        for cmd_cls in [Stats]:
            cmd = cmd_cls.from_line(cmd_line)
            if cmd is not None:
                return cmd


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
