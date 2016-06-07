class DionaeaError(Exception):
    def __init__(self, msg, *args):
        self.msg = msg
        self.args = args

    def __str__(self):
        return self.msg % self.args


class LoaderError(DionaeaError):
    pass
