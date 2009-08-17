from dionaea import ihandler, g_dionaea
from util import md5file

import os
import logging
logger = logging.getLogger('store')
logger.setLevel(logging.DEBUG)


class storehandler(ihandler):
	def __init__(self):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, "dionaea.download.complete")
	def handle(self, icd):
		logger.debug("storing file")
		p = icd.get('path')
		md5 = md5file(p)
		try:
			f = os.stat(md5)
		except OSError:
			n = g_dionaea.config()['downloads']['dir'] + '/' + md5
			logger.debug("saving new file %s to %s" % (md5, n))
			os.link(p, n)

