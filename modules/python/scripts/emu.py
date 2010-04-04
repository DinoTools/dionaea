from dionaea.core import ihandler, incident
from dionaea.core import connection
from dionaea.cmd import cmdexe
import logging
import json

logger = logging.getLogger('emu')
logger.setLevel(logging.DEBUG)

class emuprofilehandler(ihandler):

	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)

	def handle_incident(self, icd):
		logger.warn("profiling")
		p = icd.get("profile")
		try:
			con = icd.get("con")
		except AttributeError:
			con = None
		p = json.loads(p)
#		print(p)
		logger.info("profiledump %s" % (p))
		state = "NONE"
		host = None
		port = None
		for api in p:

			if state == "NONE":
				if api['call'] == 'WSASocket' or api['call'] == 'socket':
					state = "SOCKET"
				if api['call'] == 'URLDownloadToFile':
					url = api['args'][1]
					logger.debug("download file %s" % (url))
					i = incident("dionaea.download.offer")
					i.set("url", url)
					if con is not None:
						i.set("con", con)
					i.report()
				if api['call'] == 'WinExec':
					r = cmdexe(None)
					r.con = con
					r.handle_io_in(api['args'][0].encode() + b'\0')
				if api['call'] == 'CreateProcess':
					r = cmdexe(None)
					r.con = con
					r.handle_io_in(api['args'][1].encode() + b'\0')

			elif state == "SOCKET": 
				if api['call'] == 'bind':
					state = "BIND"
					host = api['args'][1]['sin_addr']['s_addr']
					port = api['args'][1]['sin_port']
				elif api['call'] == 'connect':
					state = "CONNECT"
					host = api['args'][1]['sin_addr']['s_addr']
					port = api['args'][1]['sin_port']

			elif state == "BIND": 
				if api['call'] == 'listen':
					state = "LISTEN"

			elif state == "LISTEN": 
				if api['call'] == 'accept':
					state = "ACCEPT"

			elif state == "ACCEPT": 
				if api['call'] == 'CreateProcess':
					logger.debug("bindshell host %s port %s"  % (host, port) )
					i = incident("dionaea.service.shell.listen")
					i.set("port", int(port))
					if con is not None:
						i.set("con", con)
					i.report()

			elif state == "CONNECT": 
				if api['call'] == 'CreateProcess':
					logger.debug("connectbackshell host %s port %s"  % (host, port) )
					i = incident("dionaea.service.shell.connect")
					i.set("port", int(port))
					i.set("host", host)
					if con is not None:
						i.set("con", con)
					i.report()

