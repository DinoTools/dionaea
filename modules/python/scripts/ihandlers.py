import logging
import os
import imp

# service imports
import tftp
import ftp
import cmd
import emu
import store

logger = logging.getLogger('ihandlers')
logger.setLevel(logging.DEBUG)


# reload service imports
imp.reload(tftp)
imp.reload(ftp)
imp.reload(cmd)
imp.reload(emu)
imp.reload(store)

# global handler list
# keeps a ref on our handlers
# allows restarting
global g_handlers


def start():
	global g_handlers
	g_handlers = []
	g_handlers.append(ftp.ftpdownloadhandler())
	g_handlers.append(tftp.tftpdownloadhandler())
	g_handlers.append(emu.emuprofilehandler())
	g_handlers.append(cmd.cmdshellhandler())
	g_handlers.append(store.storehandler())


def stop():
	global g_handlers
	for i in g_handlers:
		del i
	del g_handlers

