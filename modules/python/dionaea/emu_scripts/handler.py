import logging
import re

logger = logging.getLogger("emu_scripts")


class BaseHandler(object):
    name = ""

    def __init__(self, config=None):
        self._config = {}
        if isinstance(config, dict):
            self._config = config

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


class PowerShell(BaseHandler):
    name = "powershell"

    def __init__(self, config=None):
        BaseHandler.__init__(self, config=config)

        self._regex_detect = [
            re.compile(b"New-Object\s+System\.Net\.WebClient"),
            re.compile(b"DownloadFile([^,]+?,[^,]+?)"),
            re.compile(b"Invoke-Expression([^)]+?)")
        ]

        self._regex_url = re.compile(
            b"\w+\s*=\s*\"(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)\""
        )

    def run(self, data):
        match_count = 0
        for regex in self._regex_detect:
            m = regex.search(data)
            if m:
                match_count += 1

        if match_count < 2:
            logger.info("Match count is %d should at least be %d", match_count, 2)
            return

        urls = []
        for m in self._regex_url.finditer(data):
            urls.append(m.group("url"))
        return urls
