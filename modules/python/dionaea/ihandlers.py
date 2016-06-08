#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2010  Markus Koetter & Tan Kean Siong
#* Copyright (C) 2009  Paul Baecher & Markus Koetter & Mark Schloesser
#*
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#*
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#*
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#*
#*
#*             contact nepenthesdev@gmail.com
#*
#*******************************************************************************/

import logging

from dionaea import IHandlerLoader, load_config_from_files, load_submodules
from dionaea.core import g_dionaea

logger = logging.getLogger('ihandlers')
logger.setLevel(logging.DEBUG)

# global handler list
# keeps a ref on our handlers
# allows restarting
g_handlers = None
g_handler_configs = []


def new():
    global g_handler_configs
    logger.info("Load iHandlers")
    load_submodules()

    module_config = g_dionaea.config().get("module")
    filename_patterns = module_config.get("ihandler_configs", [])
    g_handler_configs = load_config_from_files(filename_patterns)


def start():
    global g_handlers
    g_handlers = {}
    logger.warn("START THE IHANDLERS")

    for ihandler_config in g_handler_configs:
        for h in IHandlerLoader:
            if ihandler_config.get("name") != h.name:
                continue
            if h not in g_handlers:
                g_handlers[h] = []

            handlers = h.start(config=ihandler_config.get("config", {}))
            if isinstance(handlers, (list, tuple)):
                g_handlers[h] += handlers
            elif handlers is not None:
                g_handlers[h].append(handlers)

    for handler_loader, ihandlers in g_handlers.items():
        for i in ihandlers:
            logger.info("Starting %s", str(i))
            method = getattr(i, "start")
            if method is not None:
                method()


def stop():
    global g_handlers
    for handler_loader, ihandlers in g_handlers.items():
        for i in ihandlers:
            logger.debug("deleting %s" % str(i))
            handler_loader.stop(i)
            del i
    del g_handlers
