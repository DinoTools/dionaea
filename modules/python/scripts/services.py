import imp
import sys
import traceback

from dionaea import *

# service imports
import http
import tftp
import mirror
from smb import smb

# reload service imports
imp.reload(http)
imp.reload(tftp)
imp.reload(smb)

# global slave
# keeps track of running services (daemons)
# able to restart them
global g_slave
global addrs

class slave():
	def __init__(self):
		self.services = []
		self.daemons = {}

	def start(self, addrs):
		print("STARTING SERVICES")
		for addr in addrs:
			try:
				print(addr)
				self.daemons[addr] = {}
				for s in self.services:
					self.daemons[addr][s] = []
					d = s.start(s, addr, iface=addrs[addr])
					self.daemons[addr][s].append(d)
			except BaseException as e:
				print(e)
				traceback.print_exc(file=sys.stdout)


# for netlink, 
# allows listening on new addrs
# and discarding listeners on closed addrs
class nlslave(ihandler):
	def __init__(self):
		ihandler.__init__(self, "dionaea.*.addr.*")
		self.services = []
		self.daemons = {}
	def handle(self, icd):
		print("SERVANT!\n")
		addr = icd.get("addr")
		iface = icd.get("iface")
		if icd.origin == "dionaea.module.nl.addr.new" or "dionaea.module.nl.addr.hup":
			self.daemons[addr] = {}
			for s in self.services:
				self.daemons[addr][s] = []
				d = s.start(s, addr, iface=iface)
				self.daemons[addr][s].append(d)
		if icd.origin == "dionaea.module.nl.addr.del":
			print(icd.origin)
			for s in self.daemons[addr]:
				for d in self.daemons[addr][s]:
					s.stop(s, d)

	def start(self, addrs):
		pass

class service:
	def start(self, addr, iface=None):
		raise NotImplementedError("do it")
	def stop(self, daemon):
		raise NotImplementedError("do it")

class httpservice(service):
	def start(self, addr, iface=None):
		daemon = http.httpd()
		daemon.bind(addr, 9999, iface=iface)
		daemon.listen()
		return daemon
	def stop(self, daemon):
		daemon.close()

class tftpservice(service):
	def start(self, addr,  iface=None):
		daemon = tftp.TftpServer()
		daemon.chroot('/tmp/')
		daemon.bind(addr, 69, iface=iface)
		return daemon
	def stop(self, daemon):
		daemon.close()

class mirrorservice(service):
	def start(self, addr, iface=None):
		daemon = mirror.mirrord('tcp', addr, 42, iface)
	def stop(self, daemon):
		daemon.close()

class smbservice(service):
	def start(self, addr,  iface=None):
		daemon = smb.smbd()
		daemon.bind(addr, 445, iface=iface)
		daemon.listen()
		return daemon
	def stop(self, daemon):
		daemon.close()

class epmapservice(service):
	def start(self, addr,  iface=None):
		daemon = smb.epmapper()
		daemon.bind(addr, 135, iface=iface)
		daemon.listen()
		return daemon
	def stop(self, daemon):
		daemon.close()

mode = 'getifaddrs'
addrs = { '::' : '*' }


def start():
	print("START")
	global g_slave, mode, addrs
	global addrs
	if mode == 'manual':
		g_slave = slave()
	elif mode == 'getifaddrs':
		g_slave = slave()
		ifaces = g_dionaea.getifaddrs()
		addrs = {}
		for iface in ifaces.keys():
			afs = ifaces[iface]
			for af in afs.keys():
				if af == 2 or af == 10:
					configs = afs[af]
					for config in afs[af]:
						addrs[config['addr']] = iface
		print(addrs)
	elif mode == 'nl':
		g_slave = nlslave()


	g_slave.services.append(httpservice)
	g_slave.services.append(tftpservice)
	g_slave.services.append(mirrorservice)
	g_slave.services.append(smbservice)
	g_slave.services.append(epmapservice)

	g_slave.start(addrs)

def stop():
	
	global g_slave
	for addr in g_slave.daemons:
		for s in g_slave.daemons[addr]:
			for d in g_slave.daemons[addr][s]:
				s.stop(s, d)
	del g_slave

