from dionaea.core import ihandler, incident, g_dionaea
from dionaea.util import md5file, sha512file
from dionaea import pyev

import logging
import json
import uuid

logger = logging.getLogger('submit_http')
logger.setLevel(logging.DEBUG)

class submithttp_report:
	def __init__(self, sha512h, md5, filepath):
		self.sha512h, self.md5h, self.filepath = sha512h, md5, filepath
		self.saddr, self.sport, self.daddr, self.dport = ('', )*4
		self.download_url = ''


class handler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)
		mwsconfig = g_dionaea.config()['modules']['python']['submit_http']
		self.backendurl = mwsconfig['url']
		self.email = 'email' in mwsconfig and mwsconfig['email'] or 'dionaea@carnivore.it'
		self.user = 'user' in mwsconfig and mwsconfig['user'] or ''
		self.passwd = 'pass' in mwsconfig and mwsconfig['pass'] or ''
		self.cookies = {}

		# heartbeats
		dinfo = g_dionaea.version()
		self.software = 'dionaea {0} {1}/{2} - {3} {4}'.format(
			dinfo['dionaea']['version'],
			dinfo['compiler']['os'],
			dinfo['compiler']['arch'],
			dinfo['compiler']['date'],
			dinfo['compiler']['time'],
		)
		self.loop = pyev.default_loop()

	def handle_incident(self, icd):
		pass

	def handle_incident_dionaea_download_complete_unique(self, icd):
		cookie = str(uuid.uuid4())

		i = incident("dionaea.upload.request")
		i._url = self.backendurl

		i.sha512 = sha512file(icd.file)
		i.md5 = md5file(icd.file)
		i.email = self.email
		i.user = self.user
		i.set('pass', self.passwd)

		mr = submithttp_report(i.sha512, i.md5, icd.file)

		if hasattr(icd, 'con'):
			i.source_host = icd.con.remote.host
			i.source_port = str(icd.con.remote.port)
			i.target_host = icd.con.local.host
			i.target_port = str(icd.con.local.port)
			mr.saddr, mr.sport, mr.daddr, mr.dport = i.source_host, i.source_port, i.target_host, i.target_port
		if hasattr(icd, 'url'):
			i.download_url = icd.url
			mr.download_url = icd.url

		i._callback = "dionaea.modules.python.submithttp.result"
		i._userdata = cookie

		self.cookies[cookie] = mr
		i.report()

	# handle agains in the same way
	handle_incident_dionaea_download_complete_again = handle_incident_dionaea_download_complete_unique

	def handle_incident_dionaea_modules_python_submithttp_result(self, icd):
		fh = open(icd.path, mode="rb")
		c = fh.read()
		logger.info("submithttp result: {0}".format(c))

		cookie = icd._userdata
		mr = self.cookies[cookie]

		# does backend want us to upload?
		if b'UNKNOWN' in c or b'S_FILEREQUEST' in c:
			i = incident("dionaea.upload.request")
			i._url = self.backendurl

			i.sha512 = mr.sha512h
			i.md5 = mr.md5h
			i.email = self.email
			i.user = self.user
			i.set('pass', self.passwd)

			i.set('file://data', mr.filepath)

			i.source_host = mr.saddr
			i.source_port = mr.sport
			i.target_host = mr.daddr
			i.target_port = mr.dport
			i.download_url = mr.download_url

			i._callback = "dionaea.modules.python.submithttp.uploadresult"
			i._userdata = cookie

			i.report()
		else:
			del self.cookies[cookie]

	def handle_incident_dionaea_modules_python_submithttp_uploadresult(self, icd):
		fh = open(icd.path, mode="rb")
		c = fh.read()
		logger.info("submithttp uploadresult: {0}".format(c))

		del self.cookies[icd._userdata]


