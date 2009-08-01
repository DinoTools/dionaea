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
					i.set("con", con)
					i.report()
				if api['call'] == 'WinExec':
					r = cmdexe(None)
					r.con = con
					r.io_in(api['args'][0])
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
		if not w == None:
			self.send = w
		else:
			self.send = self.void
		self.files = {}
		self.cwd = 'C:\WINDOWS\System32'

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

			out,err = self.execute(cmd,args)
			logger.debug("DATA: %s" % (data))
			self.redir(out, err, redir)
		self.send(self.cwd + '>')
		return dlen-len(data)

	def redir (self, out, err, redir):
		if out != None:
			if redir != None:
				redir = redir.decode()
				redir = redir.strip()
				if redir.startswith('>>'):
					target = redir[2:]
				elif redir.startswith('>'):
					target = redir[1:]
					if target in self.files:
						del self.files[target]
				if target:
					target = target.strip()
					target = target.rstrip()
					if not target in self.files:
						self.files[target] = ""
					self.files[target] += out
					logger.debug("file %s = %s" % (target,self.files[target]))
			else:
				self.send(out)

		if err != None:
			self.send(err)

	def execute(self, cmd, args):
		cmd = cmd.upper()
		if cmd.endswith(".EXE"):
			cmd = cmd[:len(cmd)-4]
		method = getattr(self, "cmd_" + cmd, None)
		if method is not None:
			return method(args)
		else:
			return None,"Command not found"
		return None,None

	def cmd_ECHO(self, args):
		out = " ".join(args) + '\n'
		logger.debug("echo %s" % (out))
		return out,None

	def cmd_FTP(self, args):
		out = "downloading ..."
		# ftp [-v] [-d] [-i] [-n] [-g] [-s:filename] [-a] [-w:Windowsize] [-A]     [host]
		host = None
		port = 21
		user = None
		passwd = "guest"
		fpath = ""
		dfile = ""
		autoconnect = True
		cmdfile = None
		for i in range(len(args)):
			if args[i] == '-v':
				continue
			elif args[i] == '-d':
				continue
			elif args[i] == '-i':
				continue
			elif args[i] == '-n':
				autoconnect = False
			elif args[i] == '-g':
				continue
			elif args[i].startswith('-s:'):
				cmdfile = args[i][3:]
			elif args[i] == '-A':
				continue
			elif args[i].startswith('-w:'):
				continue
			elif args[i] == '-A':
				user = 'anonymous'
				passwd = 'guest'
			else:
				if host != False:
					host = args[i]

		if cmdfile == None:
			return "failed downloading",None

		file = self.files[cmdfile]
		lines = file.split('\n')
		state = 'NEXT_IS_SOMETHING'
		for i in range(len(lines)):
			line = lines[i]
			logger.debug("FTP CMD LINE: %s" % (line) )
			args = line.split()
			if len(args) == 0:
				continue
			logger.debug("FTP CMD ARGS: %s" % (args) )
			if state == 'NEXT_IS_SOMETHING':
				if args[0] == 'open':
					if len(args) == 1:
						state = 'NEXT_IS_HOST'
					else:
						host = args[1]
						if len(args) == 3:
							port = int(args[2])
						else:
							port = 21
					if autoconnect == True and user == None:
						state = 'NEXT_IS_USER'
					else:
						state = 'NEXT_IS_SOMETHING'
				elif args[0] == 'user':
					if user != None:
						logger.debug("State error USER")
					else:
						if len(args) >= 1:
							state = 'NEXT_IS_USER'
						if len(args) >= 2:
							user = args[1]
							state = 'NEXT_IS_PASS'
						if len(args) == 3:
							passwd = args[2]
							state = 'NEXT_IS_SOMETHING'
				elif args[0] == 'get':
					if len(args) == 1:
						state = 'NEXT_IS_FILE'
					elif len(args) == 2:
						dfile = args[1]
						i = incident("dionaea.download.offer")
						if self.con:
							i.set("con", self.con)
						i.set("url", "ftp://%s:%s@%s:%i/%s" % (user,passwd,host,port,dfile))
						i.report()
				elif args[0] == 'cd':
					if len(args) == 1:
						state = 'NEXT_IS_PATH'
					elif len(args) == 2:
						fpath = args[1]

			elif state == 'NEXT_IS_HOST':
				if len(args) >= 2:
					host = args[1]
				if len(args) == 3:
					port = args[2]
				else:
					port = 21
				if user == None:
					state = 'NEXT_IS_USER'
				else:
					state = 'NEXT_IS_SOMETHING'

			elif state == 'NEXT_IS_USER':
				if len(args) == 1:
					user = args[0]
					if user != 'anonymous':
						state = 'NEXT_IS_PASS'
					else:
						state = 'NEXT_IS_SOMETHING'

			elif state == 'NEXT_IS_PASS':
				if len(args) == 1:
					passwd = args[0]
					state = 'NEXT_IS_SOMETHING'

			elif state == 'NEXT_IS_FILE':
				if len(args) == 1:
					dfile = args[0]
					state = 'NEXT_IS_SOMETHING'
					i = incident("dionaea.download.offer")
					if self.con:
						i.set("con", self.con)
					i.set("url", "ftp://%s:%s@%s:%i/%s" % (user,passwd,host,port,dfile))
					i.report()


			elif state == 'NEXT_IS_PATH':
				if len(args) == 1:
					fpath = args[0]
					state = 'NEXT_IS_SOMETHING'
		logger.info("ftp://%s:%s@%s:%i/%s/%s" % (user,passwd,host,port,fpath,dfile))
		return out,None

	def cmd_TFTP(self, args):
		logger.debug("TFTP %s" % (args) )
		if len(args) != 4:
			logger.debug("invalid number of args")
			return "foo","error, invalid number of args"
		if args[0] == '-i' and args[2].lower() == 'get':
			host = args[1]
			file = args[3]
			logger.debug("TFTP %s %s" % (host, file))
			return "downloading",None
		return None,None

	def cmd_CMD(self, args):
		for i in range(len(args)):
			if args[i] == '/c' or args[i] == '/k':
				line = " ".join(args[i+1:])
				line = line.encode('UTF-8')
				cmd,args,redir = self.parse(line)
				out,err = self.execute(cmd,args)
				return out,err
				
				
		return None,None

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
		argstr = line

		if cmd != None:
			cmd = cmd.decode()

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
		
		args = argstr.decode().split()

		return cmd,args,redir

	def line(self, data, eof=False):
		if type(data) == str:
			data = data.encode()

		escape = False
		for i in range(len(data)):
			if int(data[i]) == ord('^'):
				if escape == False:
					escape == True
				else:
					escape == False
			elif ( (data[i] == ord(';') and escape == False) 
				or data[i] == ord('&') 
				or data[i] == ord('\0') 
				or data[i] == ord('\n')):
				j=i+1
				while j < len(data) and data[j] == ord('&'):
					j=j+1
				line = data[:i]
				data = data[j:]
				if i+1 == len(data):
					return data,line,False
				else:
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

import re
import random
_linesep_regexp = re.compile(b"\r?\n")

class ftpctrl(connection):
	def __init__(self, ftp):
		connection.__init__(self, 'tcp')
		self.ftp = ftp
		self.state = 'USER'

	def established(self):
		logger.debug("FTP CTRL connection established")

	def io_in(self, data):
		dlen = len(data)
		lines = _linesep_regexp.split(data)#.decode('UTF-8'))
		
		remain = lines.pop()
		dlen = dlen - len(remain)
		
		for line in lines:
			print(line)
			c = int(line[:3])
			s = line[3:4]
			if self.state == 'USER':
				if c == 220 and s != b'-':
					self.cmd('USER ' + self.ftp.user)
					self.state = 'PASS'
			elif self.state == 'PASS':
				if c == 331 and s != b'-':
					self.cmd('PASS ' + self.ftp.passwd)
					self.state = 'WELCOME'
			elif self.state == 'WELCOME':
				if c == 230 and s != b'-':
					if self.ftp.mode == 'binary':
						self.cmd('TYPE I')
						self.state = 'TYPE'
					else:
						port = self.ftp.makeport()
						self.cmd('PORT ' + port)
						self.state = 'PORT'
			elif self.state == 'TYPE':
				if (c >= 200 and c < 300) and s != b'-':
					port = self.ftp.makeport()
					self.cmd('PORT ' + port)
					self.state = 'PORT'
			elif self.state == 'PORT':
					if c == 200 and s != b'-':
						self.cmd('RETR ' + self.ftp.file)
						self.state = 'RETR'
					else:
						logger.warn("PORT command failed")
			elif self.state == 'RETR':
					if (c > 200 and c < 300)  and s != b'-':
						self.cmd('QUIT')
						self.state = 'QUIT'
						self.ftp.ctrldone()

		return dlen

	def cmd(self, cmd):
		logger.debug("FTP CMD: '" + cmd +"'")
		self.send(cmd + '\r\n')

	def error(self, err):
		pass

	def disconnect(self):
		if self.state != 'QUIT':
			self.ftp.fail()
		return False

	def idle(self):
		return False

	def sustain(self):
		return False

class ftpdata(connection):
	def __init__(self, ftp=None):
		connection.__init__(self, 'tcp')
		self.ftp = ftp
		self.timeouts.listen = 10
		

	def established(self):
		logger.debug("FTP DATA established")
		self.timeouts.idle = 10

	def learn(self, parent):
		self.ftp = parent.ftp
		self.ftp.dataconn = self
		self.ftp.datalistener.close()
		self.ftp.datalistener = None

	def io_in(self, data):
		return len(data)

	def idle(self):
		self.ftp.fail()
		return False

	def disconnect(self):
		logger.debug("received %i bytes" %(self._in.accounting.bytes))
		self.ftp.dataconn = None
		self.ftp.datadone()
		return False

	def timeout(self):
		self.ftp.fail()
		return False

class ftp:
	def __init__(self):
		self.ctrl = ftpctrl(self)

	def download(self, local, user, passwd, host, port, file, mode):
		self.user = user
		self.passwd = passwd
		self.host = host
		self.port = port
		self.file = file
		self.mode = mode
		self.local = local
		self.ctrl.bind(local, 0)
		self.ctrl.connect(host, port)
		self.dataconn = None
		self.datalistener = None

	def makeport(self):
		self.datalistener = ftpdata(ftp=self)
		ports = list(filter(lambda port: ((port >> 4) & 0xf) != 0, range(62001, 63000))) # NAT, use a port range which is forwarded to your honeypot
		random.shuffle(ports)
		host = None
		port = None
		for port in ports:
			self.datalistener.bind(self.local, port)
			if self.datalistener.listen() == True:
				host = self.datalistener.local.host # NAT, replace this with something like host = socket.gethostbyname('honeypot.dyndns.org')
				port = self.datalistener.local.port
				break
		hbytes = host.split('.')
		pbytes = [repr(port//256), repr(port%256)]
		bytes = hbytes + pbytes
		port = ','.join(bytes)
		logger.debug("PORT CMD %s" % (port))
		return port

	def ctrldone(self):
		logger.info("SUCCESS DOWNLOADING FILE")
		self.done()

	def datadone(self):
		logger.info("FILE received")
		self.done()

	def done(self):
		if self.ctrl and self.ctrl.state == 'QUIT' and self.dataconn == None:
			logger.info("proceed processing file!")
			self.ctrl = None


	def fail(self):
		self.finish()

	def finish(self):
		if self.ctrl != None:
			self.ctrl.close()
			self.ctrl = None
		if self.datalistener and self.datalistener != None:
			self.datalistener.close()
			self.datalistener = None
		if self.dataconn and self.dataconn != None:
			self.dataconn.close()
			self.dataconn = None

# ftp://ftp.kernel.org/pub/linux/kernel/v2.6/linux-2.6.29.6.tar.gz
#f = ftp()
#f.download('0.0.0.0', 'anonymous','guest','ftp.kernel.org',21, '/pub/linux/kernel/v2.6/linux-2.6.29.6.tar.gz', 'binary')
#f.download('....', 'anonymous','guest','ftp.kernel.org',21, 'welcome.msg', 'binary')


import urllib.parse
from tftp import TftpClient


class ftpdownloader(ihandler):
	def __init__(self):
		ihandler.__init__(self, 'dionaea.download.offer')
	def handle(self, icd):
		logger.warn("do download")
		url = icd.get("url")
		p = urllib.parse.urlsplit(url)
		print(p)
		con = icd.get('con')
		if p.scheme == 'ftp':
			f = ftp()
			f.download(con.local.host, p.username, p.password, p.hostname, p.port, p.path, 'binary')
		if p.scheme == 'tftp':
			t = TftpClient()
			t.bind(con.local.host, 0)
			t.download('192.168.53.21', 69, 'zero')

x = ftpdownloader()
