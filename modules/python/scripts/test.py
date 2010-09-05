from dionaea.core import ihandler, incident, g_dionaea
from dionaea.core import connection
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
			if 'urls' not in tos[to]:
				logger.warn("your configuration lacks urls to submit to %s" % to)
				continue
			for url in tos[to]['urls']:
				i = incident("dionaea.upload.request")
				i.url = url
				# copy all values for this url
				for key in tos[to]:
					if key == 'urls':
						continue
					if key == 'file_fieldname':
						i.set("file://" + tos[to][key], icd.file)
						continue
					i.set(key, tos[to][key])
				i.report()
