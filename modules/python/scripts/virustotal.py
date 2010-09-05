from dionaea.core import ihandler, incident, g_dionaea

import logging
import json

logger = logging.getLogger('virustotal')
logger.setLevel(logging.DEBUG)

class virustotalhandler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)
		self.apikey = g_dionaea.config()['modules']['python']['virustotal']['apikey']
		self.polling = {}
	
	def handle_incident(self, icd):
		pass

	def handle_incident_dionaea_download_complete_unique(self, icd):
		i = incident("dionaea.upload.request")
		i.url = "http://www.virustotal.com/api/get_file_report.json"
		
		i.resource = icd.md5hash
		i.key = self.apikey

		i._callback = "dionaea.modules.python.virustotal.get_file_report"
		i._userdata = icd.md5hash

		i.report()

	def handle_incident_dionaea_modules_python_virustotal_get_file_report(self, icd):
		f = open(icd.path, mode='r')
		j = json.load(f)

		md5hash = icd._userdata

		if j['result'] == -1:
			logger.warn("something is wrong with your virustotal api key")

		elif j['result'] == 0:
			logger.warn("file %s is unknown to virus total, uploading" % md5hash)

			i = incident("dionaea.upload.request")
			i.url = "http://www.virustotal.com/api/scan_file.json"
			i.key = self.apikey

			i.set('file://file', '/opt/dionaea/var/dionaea/binaries/' + md5hash)
			i.file_fieldname = "file"
			i._callback = "dionaea.modules.python.virustotal_scan_file"
			i._userdata = md5hash
			i.report()

			i = incident("dionaea.upload.request")
			i.url = "http://www.virustotal.com/api/make_comment.json"
			i.key = self.apikey
			i.file = md5hash
			i.tags = "malware;networkworm"
			i.comment = "This sample was captured in the wild and uploaded by the dionaea honeypot."
			i._callback = "dionaea.modules.python.virustotal_make_comment"
			i._userdata = md5hash
			i.report()

		if j['result'] == 1:
			date = j['report'][0]
			scans = j['report'][1]
			for av in scans:
				logger.debug("scanner {} result {}".format(av,scans[av]))

			i = incident("dionaea.module.python.modules.virustotal.report")
			i.md5hash = md5hash
			i.path = icd.path
			i.report()


	def handle_incident_dionaea_modules_python_virustotal_scan_file(self, icd):
		pass

	def handle_incident_dionaea_modules_python_virustotal_make_comment(self, icd):
		pass

