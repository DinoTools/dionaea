from dionaea import ihandler, incident
from dionaea import connection
import logging
import json
global p

logger = logging.getLogger('test')
logger.setLevel(logging.DEBUG)

class profiler(ihandler):

	def __init__(self):
		ihandler.__init__(self, "dionaea.module.emu.profile")

	def handle(self, icd):
		logger.warn("profiling")
		p = icd.get("profile")
		con = icd.get("con")
		p = json.loads(p)
#		print(p)
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
					i.set("con", con)
					i.report()

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
					i.set("con", con)
					i.report()

			elif state == "CONNECT": 
				if api['call'] == 'CreateProcess':
					logger.debug("connectbackshell host %s port %s"  % (host, port) )
					i = incident("dionaea.service.shell.connect")
					i.set("port", int(port))
					i.set("host", host)
					i.set("con", con)
					i.report()

class doshell(ihandler):

	def __init__(self):
		ihandler.__init__(self, "dionaea.service.shell.*")

	def handle(self, icd):
		logger.warn("do shell")
		c = remoteshell()
		con = icd.get("con")
		if icd.origin == "dionaea.service.shell.listen":
			c.bind(con.local.host,icd.get('port'))
			c.listen()
		elif icd.origin == "dionaea.service.shell.connect":
			c.bind(con.local.host,0)
			c.connect(icd.get('host'), icd.get('port'))
		else:
			c.close()

class cmdexe:
	def __init__(self, w):
		self.specials = [' ', '\t', '"', '\\']
		if w:
			self.send = w
		else:
			self.send = self.void

	def io_in(self, data):
		logger.debug(data)
#		self.send(data)
		c = True
		dlen = len(data)
		logger.debug("DATA: %s" % (data))
		while c:
			data,line,c = self.line(data)
			logger.debug("LINE: %s" % (line))
			cmd,args,redir = self.parse(line)
			logger.debug("CMD: %s %s %s" % (cmd, args, redir))
			if not cmd:
				continue

			out = self.execute(cmd,args)

#			logger.debug("DATA: %s" % (data))
		return dlen-len(data)

	def execute(self, cmd, args):
		try:
			cmd = cmd.encode()
		except:
			return None
		cmd = cmd.upper()
		if cmd.endswith(".EXE"):
			cmd = cmd[:len(cmd)-4]
		return None

	def parse(self, line):
		args = []
		cmd = None
		redir = None
		line = line.strip()

		if len(line) == 0:
			return cmd,args,redir

		end = line[len(line)-1]
		if end == ord('&') or end == ord(';') or end == ord('\n'):
			line = line[:len(line)-1]
		cmd = line
		i=0
		for i in range(len(line)):
			if line[i] == ord(' '):
				cmd = line[:i]
				line = line[i:]
				break
		argstr = line[i+1:]

		escape = False
		for i in range(len(line)):
			if line[i] == ord('^'):
				if escape == False:
					escape == True
				else:
					escape == False
			elif ( line[i] == ord('>') and escape == False):
				argstr = line[:i]
				redir = line[i:]
				break
		
		args = argstr.split()

		return cmd,args,redir

	def line(self, data, eof=False):
		escape = False
		for i in range(len(data)):
			if data[i] == ord('^'):
				if escape == False:
					escape == True
				else:
					escape == False
			elif ( (data[i] == ord(';') and escape == False) 
				or data[i] == ord('&') 
				or data[i] == ord('\0') 
				or data[i] == ord('\n')):
				i=i+1
				line = data[:i]
				data = data[i:]
				return data,line,True

		if eof:
			line = data[:i]
			data = data[i:]
			return data,line,False

		return data,b'',False

	def void(self, data):
		pass


class remoteshell(cmdexe,connection):
	def __init__(self):
		connection.__init__(self,'tcp')
		cmdexe.__init__(self, self.send)
		self.timeouts.listen = 10
		self.timeouts.connecting = 5
		self.timeouts.idle = 1
		self.timeouts.sustain = 15
		self._in.accounting.limit = 1024
	
	def established(self):
		self.send("Microsoft Windows 2000 [Version 5.00.2195]\n(C) Copyright 1985-2000 Microsoft Corp.\n\nC:\\WINDOWS\\System32>")

	def disconnect(self):
		return False

	def error(self, err):
		pass

	def idle (self):
		self.send("\n")
		return True

	def sustain(self):
		return False


def start():
	global a
	logger.warn("test?")
	a = profiler()

def stop():
	global a
	del a

	
from test import *
c = remoteshell()
#c.connect('localhost',6667)
c.bind('::',6667)
c.listen()

do = doshell()
