from dionaea import ihandler, incident, g_dionaea
from dionaea import connection
import logging
import json
global p

logger = logging.getLogger('test')
logger.setLevel(logging.DEBUG)


class uniquedownloadihandler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)
	def handle_incident(self, icd):
		logger.debug("submitting file")
		try:
			tos = g_dionaea.config()['submit']
		except:
			return

		for to in tos:
			if 'urls' not in g_dionaea.config()['submit'][to]:
				logger.warn("your configuration lacks urls to submit to %s" % to)
				continue
			for url in g_dionaea.config()['submit'][to]['urls']:
				i = incident("dionaea.upload.request")
				i.url = url
				i.file = icd.file
				# copy all values for this url
				for key in g_dionaea.config()['submit'][to]:
					if key == 'urls':
						continue
					i.set(key, g_dionaea.config()['submit'][to][key])
				i.report()
