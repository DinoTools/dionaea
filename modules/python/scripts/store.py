from dionaea.core import ihandler, incident, g_dionaea
from dionaea.util import md5file

import os
import logging
logger = logging.getLogger('store')
logger.setLevel(logging.DEBUG)


class storehandler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)
	def handle_incident(self, icd):
		logger.debug("storing file")
		p = icd.path
		md5 = md5file(p)
		n = g_dionaea.config()['downloads']['dir'] + '/' + md5
		i = incident("dionaea.download.complete.hash")
		i.file = n
		i.url = icd.url
		if hasattr(icd, 'con'):
			i.con = icd.con
		i.md5hash = md5
		i.report()

		try:
			f = os.stat(n)
			i = incident("dionaea.download.complete.again")
			logger.debug("file %s already existed" % md5)
		except OSError:
			logger.debug("saving new file %s to %s" % (md5, n))
			os.link(p, n)
			i = incident("dionaea.download.complete.unique")
		i.file = n
		if hasattr(icd, 'con'):
			i.con = icd.con
		i.md5hash = md5
		i.report()

		


