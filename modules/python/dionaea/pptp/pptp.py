#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2015  Tan Kean Siong
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

from dionaea.core import *

import datetime
import traceback
import logging
import binascii
import os
import tempfile

from dionaea.pptp.include.packets import *

logger = logging.getLogger('pptp')

class pptpd(connection):
	def __init__ (self):
		connection.__init__(self,"tcp")
		self.buf = b''

	def handle_established(self):
		self.timeouts.idle = 120
		self.processors()

	def handle_io_in(self, data):
		l=0
		size = 0
		chunk = b''
		
		if len(data) > l:
			p = None
			x = None
			try:

				if len(data) > 100:
					p = PPTP_StartControlConnection_Request(data);
					p.show()

					if p.Length == 0:
						logger.warn("Bad PPTP Packet, Length = 0")
						return l

					self.pendingPacketType = p.ControlMessageType

				if len(data) < 100:
					logger.warn("PPTP Packet, Length < 100")
					
			except:
				t = traceback.format_exc()
				logger.critical(t)
				return l
	
			if self.pendingPacketType == PPTP_CTRMSG_TYPE_STARTCTRCON_REQUEST:
				x = PPTP_StartControlConnection_Request(data)
				
				# we can gather some values from the client, maybe use for fingerprinting clients
				#l = p.getlayer(PPTP_StartControlConnection_Request)
				i = incident("dionaea.modules.python.pptp.connect")
				i.con = self
				logger.debug("pptp remote hostname: %s", x.HostName)
				i.remote_hostname = x.HostName
				i.report()

			elif self.pendingPacketType == PPTP_CTRMSG_TYPE_OUTGOINGCALL_REQUEST:
				x = PPTP_OutgoingCall_Request(data)

			# FIXME after these, the client will send in Generic Routing Encapsulation (PPP) traffic
			# dionaea currently not able to support these PPP traffic

			self.buf = b''
			x.show()

			r = None			
			r = self.process( self.pendingPacketType, x)

			if r:
				r.show()
				self.send(r.build())
				
		return len(data)

	def process(self, PacketType, p):
		r =''
		rp = None
		
		if PacketType == PPTP_CTRMSG_TYPE_STARTCTRCON_REQUEST:
			r = PPTP_StartControlConnection_Reply()
		elif PacketType ==  PPTP_CTRMSG_TYPE_OUTGOINGCALL_REQUEST:
			r = PPTP_OutgoingCall_Reply()
		else:
			logger.warn("UNKNOWN PACKET TYPE FOR PPTP %s", PacketType)
		
		return r
	
	def handle_timeout_idle(self):
		return False

	def handle_disconnect(self):
		return False

