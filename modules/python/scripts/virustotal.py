from dionaea.core import ihandler, incident, g_dionaea

import logging
import json
import os
import uuid
from dionaea import pyev

logger = logging.getLogger('virustotal')
logger.setLevel(logging.DEBUG)

class vtreport:
	def __init__(self, md5hash, file):
		self.md5hash = md5hash
		self.file = file
		self.comment_timer = None
		self.comment_retries = 0


class virustotalhandler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)
		self.apikey = g_dionaea.config()['modules']['python']['virustotal']['apikey']
		self.cookies = {}
		self.loop = pyev.default_loop()
	
	def handle_incident(self, icd):
		pass

	def handle_incident_dionaea_download_complete_unique(self, icd):
		cookie = str(uuid.uuid4())
		self.cookies[cookie] = vtreport(icd.md5hash, icd.file)

		i = incident("dionaea.upload.request")
		i.url = "http://www.virustotal.com/api/get_file_report.json"
		
		i.resource = icd.md5hash
		i.key = self.apikey

		i._callback = "dionaea.modules.python.virustotal.get_file_report"
		i._userdata = cookie

		i.report()

	def handle_incident_dionaea_modules_python_virustotal_get_file_report(self, icd):
		f = open(icd.path, mode='r')
		j = json.load(f)

		cookie = icd._userdata
		vtr = self.cookies[cookie]

		if j['result'] == -1:
			logger.warn("something is wrong with your virustotal api key")

		elif j['result'] == 0:
			logger.warn("file {} is unknown to virus total, uploading".format(vtr.md5hash) )

			i = incident("dionaea.upload.request")
			i.url = "http://www.virustotal.com/api/scan_file.json"
			i.key = self.apikey

			i.set('file://file', vtr.file)
			i._callback = "dionaea.modules.python.virustotal_scan_file"
			i._userdata = cookie
			i.report()

		elif j['result'] == 1:
			logger.debug("report {}".format(j) )
			date = j['report'][0]
			scans = j['report'][1]
			for av in scans:
				logger.debug("scanner {} result {}".format(av,scans[av]))

			i = incident("dionaea.module.python.modules.virustotal.report")
			i.md5hash = vtr.md5hash
			i.path = icd.path
			i.report()


	def handle_incident_dionaea_modules_python_virustotal_scan_file(self, icd):
		f = open(icd.path, mode='r')
		j = json.load(f)
		logger.debug("scan_file {}".format(j))
		cookie = icd._userdata
		vtr = self.cookies[cookie]

		if j['result'] == 1:
			vtr.comment_timer = pyev.Timer(60, 0, self.loop, self.__handle_comment_timeout)
			vtr.comment_timer.data = cookie
			vtr.comment_timer.start()
		
	def __handle_comment_timeout(self, watcher, event):
		cookie = watcher.data
		vtr = self.cookies[cookie]
		vtr.comment_retries += 1

		i = incident("dionaea.upload.request")
		i.url = "http://www.virustotal.com/api/make_comment.json"
		i.key = self.apikey
		i.file = vtr.md5hash
		i.tags = "honeypot;malware;networkworm"
		i.comment = "This sample was captured in the wild and uploaded by the dionaea honeypot, still testing comments ..."
		i._callback = "dionaea.modules.python.virustotal_make_comment"
		i._userdata = cookie
		i.report()

	def handle_incident_dionaea_modules_python_virustotal_make_comment(self, icd):
		cookie = icd._userdata
		vtr = self.cookies[cookie]
		f = open(icd.path, mode='r')
		try:
			j = json.load(f)
			logger.debug("posting comment success (try {}) ".format(vtr.comment_retries))
		except Exception as e:
			f.seek(0, os.SEEK_SET)
			msg = f.readline(1024)
			logger.warn("posting comment failed, server returned '{}'".format(msg))
			if vtr.comment_retries > 10:
				logger.warn("posting comment failed {:i} times, giving up".format(vtr.comment_retries))
				del self.cookies[cookie]
				return
			
			vtr.comment_timer = pyev.Timer(60, 0, self.loop, self.__handle_comment_timeout)
			vtr.comment_timer.data = cookie
			vtr.comment_timer.start()
			return

		logger.debug("comment {}".format(j))
		del self.cookies[cookie]


