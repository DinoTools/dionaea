from dionaea import ihandler, incident, g_dionaea
from util import md5file

import os
import logging
logger = logging.getLogger('store')
logger.setLevel(logging.DEBUG)


class storehandler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)
	def handle(self, icd):
		logger.debug("storing file")
		p = icd.get('path')
		logger.debug("got path")
		md5 = md5file(p)
		logger.debug("got hash")
		n = g_dionaea.config()['downloads']['dir'] + '/' + md5
		logger.debug("got n")
		try:
			f = os.stat(n)
		except OSError:
			logger.debug("saving new file %s to %s" % (md5, n))
			os.link(p, n)
			i = incident("dionaea.download.complete.unique")
			i.set("file", n)
			i.report()
			return
		logger.debug("file %s already existed" % md5)


