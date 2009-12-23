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

from dionaea import g_dionaea

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

	if "ftpdownload" in g_dionaea.config()['modules']['python']['ihandlers']['handlers']:
		g_handlers.append(ftp.ftpdownloadhandler('dionaea.download.offer'))

	if "tftpdownload" in g_dionaea.config()['modules']['python']['ihandlers']['handlers']:
		g_handlers.append(tftp.tftpdownloadhandler('dionaea.download.offer'))

	if "emuprofile" in g_dionaea.config()['modules']['python']['ihandlers']['handlers']:
		g_handlers.append(emu.emuprofilehandler('dionaea.module.emu.profile'))

	if "cmdshell" in g_dionaea.config()['modules']['python']['ihandlers']['handlers']:
		g_handlers.append(cmd.cmdshellhandler('dionaea.service.shell.*'))

	if "store" in g_dionaea.config()['modules']['python']['ihandlers']['handlers']:
		g_handlers.append(store.storehandler('dionaea.download.complete'))

	if "uniquedownload" in g_dionaea.config()['modules']['python']['ihandlers']['handlers']:
		g_handlers.append(test.uniquedownloadihandler('dionaea.download.complete.unique'))

	if "surfids" in g_dionaea.config()['modules']['python']['ihandlers']['handlers']:
		import surfids
		g_handlers.append(surfids.surfidshandler('*'))

	if "logsql" in g_dionaea.config()['modules']['python']['ihandlers']['handlers']:
		import logsql
		g_handlers.append(logsql.logsqlhandler("*"))

	if "p0f" in g_dionaea.config()['modules']['python']['ihandlers']['handlers']:
		import p0f
		g_handlers.append(p0f.p0fhandler(g_dionaea.config()['modules']['python']['p0f']['path']))

def stop():
	global g_handlers
	for i in g_handlers:
		logger.debug("deleting %s" % str(i))
		del i
	del g_handlers

