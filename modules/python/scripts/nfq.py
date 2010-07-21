

from dionaea.core import *
from dionaea.mirror import mirrord, mirrorc

import logging

logger = logging.getLogger('nfq')
logger.setLevel(logging.DEBUG)


class nfqmirrorc(connection):
	def __init__(self, peer=None):
		logger.debug("nfqmirror connection %s %s" %( peer.remote.host, peer.local.host))
		connection.__init__(self,peer.transport)
		self.bind(peer.local.host,0)
		self.connect(peer.remote.host,peer.local.port)
		self.peer = peer

	def handle_established(self):
		self.peer.peer = self

	def handle_io_in(self, data):
		if self.peer:
			self.peer.send(data)
		return len(data)

	def handle_error(self, err):
		if self.peer:
			self.peer.peer = None
			self.peer.close()

	def handle_disconnect(self):
		if self.peer:
			self.peer.close()
		if self.peer:
			self.peer.peer = None
		return 0

class nfqmirrord(connection):
	def __init__(self, proto=None, host=None, port=None, iface=None):
		connection.__init__(self,proto)
		if host:
			self.timeouts.listen = 5
			self.bind(host, port, iface)
			self.listen()
		self.peer=None

	def handle_established(self):
		self.processors()

		self.timeouts.sustain = 60
		self._in.accounting.limit  = 200*1024
		self._out.accounting.limit = 200*1024

		self.peer=nfqmirrorc(self)
		i = incident('dionaea.connection.link')
		i.parent = self
		i.child = self.peer
		i.report()


	def handle_io_in(self, data):
		if self.peer:
			self.peer.send(data)
		return len(data)

	def handle_error(self, err):
		logger.debug("mirrord connection error?, should not happen")
		if self.peer:
			self.peer.peer = None

	def handle_disconnect(self):
		if self.peer:
			self.peer.close()
		if self.peer:
			self.peer.peer = None
		return 0

class nfqhandler(ihandler):
	def __init__(self):
		logger.debug("nfqhandler")
		ihandler.__init__(self, 'dionaea.connection.tcp.pending')
		self.service = mirrord

	def handle_incident(self, icd):
		if icd.origin == 'dionaea.connection.tcp.pending':
			con = icd.con
			logger.warn(con.protocol)
			logger.warn(con.local.host)
			logger.warn("%i" % con.local.port)
			m = nfqmirrord('tcp', con.local.host, con.local.port)
			i = incident('dionaea.connection.link')
			i.parent = con
			i.child = m
			i.report()

			

