import logging
import os
import imp

# service imports
import tftp
import ftp
import cmd
import emu
import store
import test

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
	g_handlers.append(ftp.ftpdownloadhandler('dionaea.download.offer'))
	g_handlers.append(tftp.tftpdownloadhandler('dionaea.download.offer'))
	g_handlers.append(emu.emuprofilehandler('dionaea.module.emu.profile'))
	g_handlers.append(cmd.cmdshellhandler('dionaea.service.shell.*'))
	g_handlers.append(store.storehandler('dionaea.download.complete'))
	g_handlers.append(test.uniquedownloadihandler('dionaea.download.complete.unique'))


def stop():
	global g_handlers
	for i in g_handlers:
		del i
	del g_handlers

