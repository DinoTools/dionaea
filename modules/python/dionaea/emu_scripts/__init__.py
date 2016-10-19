#################################################################################
#                                Dionaea
#                            - catches bugs -
#
#  Copyright (c) 2016 PhiBo (DinoTools)
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
################################################################################

import logging

from dionaea import IHandlerLoader
from dionaea.core import ihandler, incident
from dionaea.exception import LoaderError


logger = logging.getLogger("emu_scripts")
logger.setLevel(logging.DEBUG)


class EmulateScriptsLoader(IHandlerLoader):
    name = "emu_scripts"

    @classmethod
    def start(cls, config=None):
        try:
            return EmulateScriptsHandler("*", config=config)
        except LoaderError as e:
            logger.error(e.msg, *e.args)


class EmulateScriptsHandler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!", self.__class__.__name__)
        ihandler.__init__(self, path)
        self.path = path
        self._config = config
        self.handlers = []
        self.connection_url_levels = {}

        from .handler import RawURL

        tmp_handlers = {}
        for h in (RawURL,):
            tmp_handlers[h.name] = h

        enabled_handlers = config.get("enabled_handlers")
        if not isinstance(enabled_handlers, list) or len(enabled_handlers) == 0:
            logger.warning("No handlers specified")
            # Set empty list on error
            enabled_handlers = []

        handler_configs = config.get("handler_configs")
        if not isinstance(handler_configs, dict):
            handler_configs = {}

        for handler_name in enabled_handlers:
            h = tmp_handlers.get(handler_name)
            if h is None:
                logger.warning("Unable to load handler '%s'", handler_name)
                continue

            handler_config = handler_configs.get(handler_name)
            if not isinstance(handler_config, dict):
                handler_config = {}

            self.handlers.append(h(config=handler_config))

    def handle_incident_dionaea_connection_free(self, icd):
        # Delete levels for this connection
        del self.connection_url_levels[icd.con]

    def handle_incident_dionaea_download_complete(self, icd):
        urls = []

        url_levels = self.connection_url_levels.get(icd.con)
        if not isinstance(url_levels, dict):
            url_levels = {}
            # Store dict pointer in list, so others can use it
            self.connection_url_levels[icd.con] = url_levels

        next_level = url_levels.get(icd.url, 0) + 1
        if next_level > 1:
            # ToDo: use config value
            return

        fp = open(icd.path, "rb")
        # ToDo: check size
        data = fp.read()
        fp.close()
        for handler in self.handlers:
            urls = urls + handler.run(data)

        for url in set(urls):
            if url in url_levels:
                # don't download a file multiple times
                continue

            url_levels[url] = next_level
            i = incident("dionaea.download.offer")
            i.con = icd.con
            i.url = url
            i.report()
