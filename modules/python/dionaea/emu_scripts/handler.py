import re


class BaseHandler(object):
    name = ""


class RawURL(object):
    name = "raw_url"

    def __init__(self, config=None):
        self._config = {}
        if isinstance(config, dict):
            self._config = config

        self._regex_url = re.compile(
            b"(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
        )

    def run(self, data):
        urls = []
        for m in self._regex_url.finditer(data):
            urls.append(m.group("url"))
        return urls
