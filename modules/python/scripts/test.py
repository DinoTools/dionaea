from dionaea import ihandler, incident, g_dionaea
from dionaea import connection
import logging
import json
global p

logger = logging.getLogger('test')
logger.setLevel(logging.DEBUG)


class uniquedownloadihandler(ihandler):
	def __init__(self):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, "dionaea.download.complete.unique")
	def handle(self, icd):
		logger.debug("submitting file")
		try:
			file = icd.get('file')
			email = g_dionaea.config()['submit']['email']
		except:
			logger.warn("complete download without file?")
			return

		for url in g_dionaea.config()['submit']['urls']:
			i = incident("dionaea.upload.request")
			i.set('email', email)
			i.set('url', url)
			i.set('file',file)
			i.report()
