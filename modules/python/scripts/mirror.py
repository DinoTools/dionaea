#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter
#* Copyright (c) 2006-2009 Michael P. Soulier
#* 
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#* 
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#* 
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#* 
#* 
#*             contact nepenthesdev@gmail.com  
#*
#*******************************************************************************/

from dionaea.core import connection
import struct
import logging
import os
import sys
import datetime

logger = logging.getLogger('mirror')
logger.setLevel(logging.DEBUG)

class mirrorc(connection):
	def __init__(self, peer=None):
		logger.debug("mirror connection %s %s" %( peer.remote.host, peer.local.host))
		connection.__init__(self,peer.transport)
		self.bind(peer.local.host,0)
		self.connect(peer.remote.host,peer.local.port)
#		self.connect('',peer.local.port)
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

class mirrord(connection):
	def __init__(self, proto=None, host=None, port=None, iface=None):
		connection.__init__(self,proto)
		if host:
			self.bind(host, port, iface)
			self.listen()
		self.peer=None
		
	def handle_established(self):
		self.peer=mirrorc(self)
		self.timeouts.sustain = 60
		self._in.accounting.limit  = 100*1024
		self._out.accounting.limit = 100*1024
		
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

