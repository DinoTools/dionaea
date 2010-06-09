#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter & Mark Schloesser
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
import tempfile
import binascii
import os
from uuid import UUID

from .include.smbfields import *


smblog = logging.getLogger('SMB')

STATE_START = 0
STATE_SESSIONSETUP = 1
STATE_TREECONNECT = 2
STATE_NTCREATE = 3
STATE_NTWRITE = 4
STATE_NTREAD = 5

registered_services = {}

def register_rpc_service(service):
	uuid = service.uuid
	global registered_calls
	registered_services[uuid] = service


class smbd(connection):
	def __init__ (self):
		connection.__init__(self,"tcp")
		self.state = {
			'lastcmd': None,
			'readcount': 0,
			'stop': False,
		}
		self.buf = b''
		self.outbuf = None
		self.files = {}

	def handle_established(self):
		self.timeouts.sustain = 120
#		self._in.accounting.limit  = 2000*1024
#		self._out.accounting.limit = 2000*1024
		self.processors()

	def handle_io_in(self,data):

		try:
			p = NBTSession(data, _ctx=self)
		except:
			t = traceback.format_exc()
			smblog.critical(t)
			return len(data)

		if len(data) < (p.LENGTH+4):
			#we probably do not have the whole packet yet -> return 0
			smblog.critical('=== SMB did not get enough data')
			return 0

		if p.TYPE == 0x81:
			self.send(NBTSession(TYPE=0x82).build())
			return len(data)
		elif p.TYPE != 0:
			# we currently do not handle anything else
			return len(data)

		if p.haslayer(SMB_Header) and p[SMB_Header].Start != b'\xffSMB':
			# not really SMB Header -> bail out
			smblog.critical('=== not really SMB')
			self.close()
			return len(data)

		p.show()

		r = None

		# this is one of the things you have to love, it violates the spec, but has to work ...
		if p.haslayer(SMB_Sessionsetup_ESEC_AndX_Request) and p.getlayer(SMB_Sessionsetup_ESEC_AndX_Request).WordCount == 13: 
			smblog.debug("recoding session setup request!")
			p.getlayer(SMB_Header).decode_payload_as(SMB_Sessionsetup_AndX_Request2) 

		r = self.process(p)
		smblog.debug('packet: {0}'.format(p.summary()))

		if p.haslayer(Raw):
			smblog.warning('p.haslayer(Raw): {0}'.format(p.getlayer(Raw).build()))
			p.show()

#		i = incident("dionaea.module.python.smb.info")
#		i.con = self
#		i.direction = 'in'
#		i.data = p.summary()
#		i.report()

		if r:
			smblog.debug('response: {0}'.format(r.summary()))
			r.show()

#			i = incident("dionaea.module.python.smb.info")
#			i.con = self
#			i.direction = 'out'
#			i.data = r.summary()
#			i.report()

#			r.build()
			#r.show2()
			self.send(r.build())
		else:
			if self.state['stop']:
				smblog.debug('process() returned None.')
			else:
				smblog.critical('process() returned None.')

		if p.haslayer(Raw):
			smblog.warning('p.haslayer(Raw): {0}'.format(p.getlayer(Raw).build()))
			p.show()
			# some rest seems to be not parsed correctly
			# could be start of some other packet, junk, or failed packet dissection
			# TODO: recover from this...
			return len(data) - len(p.getlayer(Raw).load)

		return len(data)

	def process(self, p):
		r = ''
		rp = None
		self.state['readcount'] = 0
		#if self.state == STATE_START and p.getlayer(SMB_Header).Command == 0x72:
		if p.getlayer(SMB_Header).Command == SMB_COM_NEGOTIATE:
			# Negociate Protocol -> Send response that supports minimal features in NT LM 0.12 dialect
			# (could be randomized later to avoid detection - but we need more dialects/options support)
			r = SMB_Negociate_Protocol_Response()
			# we have to select dialect
			c = 0
			tmp = p.getlayer(SMB_Negociate_Protocol_Request_Counts)
			while c < len(tmp.Requests):
				request = tmp.Requests[c]
				if request.BufferData.decode('ascii').find('NT LM 0.12') != -1:
					break
				c += 1

			r.DialectIndex = c

#			r.Capabilities = r.Capabilities & ~CAP_EXTENDED_SECURITY
			if not p.Flags2 & SMB_FLAGS2_EXT_SEC:
				r.Capabilities = r.Capabilities & ~CAP_EXTENDED_SECURITY

		#elif self.state == STATE_SESSIONSETUP and p.getlayer(SMB_Header).Command == 0x73:
		elif p.getlayer(SMB_Header).Command == SMB_COM_SESSION_SETUP_ANDX:
			if p.haslayer(SMB_Sessionsetup_ESEC_AndX_Request):
				r = SMB_Sessionsetup_ESEC_AndX_Response()
			elif p.haslayer(SMB_Sessionsetup_AndX_Request2):
				r = SMB_Sessionsetup_AndX_Response2()
			else:
				smblog.warn("Unknown Session Setup Type used")
		elif p.getlayer(SMB_Header).Command == SMB_COM_TREE_CONNECT_ANDX:
			r = SMB_Treeconnect_AndX_Response()
		elif p.getlayer(SMB_Header).Command == SMB_COM_TREE_DISCONNECT:
			r = SMB_Treedisconnect()
		elif p.getlayer(SMB_Header).Command == SMB_COM_CLOSE:
			r = p.getlayer(SMB_Close)
		elif p.getlayer(SMB_Header).Command == SMB_COM_LOGOFF_ANDX:
			r = SMB_Logoff_AndX()
		elif p.getlayer(SMB_Header).Command == SMB_COM_NT_CREATE_ANDX:
			r = SMB_NTcreate_AndX_Response()
#			# if a normal file is requested, provide a file
			h = p.getlayer(SMB_NTcreate_AndX_Request)
			if h.FileAttributes & SMB_FA_NORMAL:
				smblog.warn("OPEN FILE!")
				r.FID = 0x4000
				self.files[0x4000] = tempfile.NamedTemporaryFile(delete=False, prefix="smb-", suffix=".tmp", dir=g_dionaea.config()['downloads']['dir'])
		elif p.getlayer(SMB_Header).Command == SMB_COM_OPEN_ANDX:
			r = SMB_Open_AndX_Response()
			r.FID = 0x9000
			self.files[0x9000] = tempfile.NamedTemporaryFile(delete=False, prefix="smb-", suffix=".tmp", dir=g_dionaea.config()['downloads']['dir'])
		elif p.getlayer(SMB_Header).Command == SMB_COM_ECHO:
			r = p.getlayer(SMB_Header).payload
		elif p.getlayer(SMB_Header).Command == SMB_COM_WRITE_ANDX:
			r = SMB_Write_AndX_Response()
			h = p.getlayer(SMB_Write_AndX_Request)
			r.CountLow = h.DataLenLow
			if h.FID in self.files:
				smblog.warn("WRITE FILE!")
				self.files[h.FID].write(h.Data)
			else:
				self.buf += h.Data
				self.process_dcerpc_packet(p.getlayer(SMB_Write_AndX_Request).Data)
		elif p.getlayer(SMB_Header).Command == SMB_COM_READ_ANDX:
			r = SMB_Read_AndX_Response()
			if self.state['lastcmd'] == 'SMB_COM_WRITE_ANDX':
				# lastcmd was WRITE
				# - self.buf should contain a DCERPC packet now
				# - build response packet and store in self.outbuf
				# - send out like client wants to recv

				self.outbuf = self.process_dcerpc_packet(self.buf)
				self.buf = b''

			# self.outbuf should contain response packet now
			if not self.outbuf:
				if self.state['stop']:
					smblog.debug('drop dead!')
				else:
					smblog.critical('dcerpc processing failed. bailing out.')
				return rp

			rdata = SMB_Data()
			if p.getlayer(SMB_Read_AndX_Request).MaxCountLow < len(self.outbuf.build())-self.state['readcount'] :
#				rdata.Bytecount = p.getlayer(SMB_Read_AndX_Request).MaxCountLow+1
#			else:
				rdata.ByteCount = len(self.outbuf.build()) - self.state['readcount']

			rdata.Bytes = self.outbuf.build()[ self.state['readcount']: self.state['readcount'] + p.getlayer(SMB_Read_AndX_Request).MaxCountLow ]
#			rdata.ByteCount = len(rdata.Bytes)

			self.state['readcount'] += p.Remaining
			r.DataLenLow = len(rdata.Bytes)
			r /= rdata

		elif p.getlayer(SMB_Header).Command == SMB_COM_TRANSACTION:
			self.outbuf = self.process_dcerpc_packet(p.getlayer(DCERPC_Header))

			if not self.outbuf:
				if self.state['stop']:
					smblog.debug('drop dead!')
				else:
					smblog.critical('dcerpc processing failed. bailing out.')
				return rp

			dceplen = len(self.outbuf.build())
			r = SMB_Trans_Response()
			r.TotalDataCount = dceplen
			r.DataCount = dceplen

			rdata = SMB_Data()
			rdata.ByteCount = dceplen
			rdata.Bytes = self.outbuf.build()
			
			r /= rdata
		elif p.getlayer(SMB_Header).Command == SMB_COM_TRANSACTION2:
			r = SMB_Trans2_Response()
		else:
			smblog.critical('...unknown SMB Command. bailing out.')
			p.show()

		if r:
			smbh = SMB_Header()
			smbh.Command = r.smb_cmd
			smbh.Flags2 = p.getlayer(SMB_Header).Flags2
#			smbh.Flags2 = p.getlayer(SMB_Header).Flags2 & ~SMB_FLAGS2_EXT_SEC
			smbh.MID = p.getlayer(SMB_Header).MID
			smbh.PID = p.getlayer(SMB_Header).PID
			rp = NBTSession()/smbh/r

		if p.getlayer(SMB_Header).Command in SMB_Commands:
			self.state['lastcmd'] = SMB_Commands[p.getlayer(SMB_Header).Command]
		else:
			self.state['lastcmd'] = "UNKNOWN"
		return rp

	def process_dcerpc_packet(self, buf):
		if not isinstance(buf, DCERPC_Header):
			smblog.debug("got buf, make DCERPC_Header")
			dcep = DCERPC_Header(buf)
		else:
			dcep = buf

		global registered_calls

		outbuf = None

		smblog.debug("data")
		dcep.show()

		if dcep.PacketType == 11: #bind
			outbuf = DCERPC_Header()/DCERPC_Bind_Ack()
			outbuf.CallID = dcep.CallID

#			tmp = dcep.getlayer(DCERPC_CtxItem)
			c = 0
			outbuf.CtxItems = []
			while c < len(dcep.CtxItems): #isinstance(tmp, DCERPC_CtxItem):
				tmp = dcep.CtxItems[c]
				ctxitem = DCERPC_Ack_CtxItem()
				service_uuid = UUID(bytes_le=tmp.UUID)
				transfersyntax_uuid = UUID(bytes_le=tmp.TransferSyntax)
				if str(transfersyntax_uuid) == '8a885d04-1ceb-11c9-9fe8-08002b104860':
					if service_uuid.hex in registered_services:
						service = registered_services[service_uuid.hex]
						smblog.info('Found a registered UUID (%s). Accepting Bind for %s' % (service_uuid , service.__class__.__name__))
						self.state['uuid'] = service_uuid.hex
						# Copy Transfer Syntax to CtxItem
						ctxitem.AckResult = 0
						ctxitem.AckReason = 0
						ctxitem.TransferSyntax = tmp.TransferSyntax[:16]
						ctxitem.TransferSyntaxVersion = tmp.TransferSyntaxVersion
					else:
						smblog.warn("Attempt to register %s failed, UUID does not exist or is not implemented" % service_uuid)
				else:
					smblog.warn("Attempt to register %s failed, TransferSyntax %s is unknown" % (service_uuid, transfersyntax_uuid) )
				outbuf.CtxItems.append(ctxitem)
				i = incident("dionaea.modules.python.smb.dcerpc.bind")
				i.con = self
				i.uuid = str(service_uuid)
				i.transfersyntax = str(transfersyntax_uuid)
				i.report()
#				tmp = tmp.payload
				c += 1
			outbuf.NumCtxItems = c
			outbuf.FragLen = len(outbuf.build())
			smblog.debug("dce reply")
			outbuf.show()
		elif dcep.PacketType == 0: #request
			resp = None
			if 'uuid' in self.state:
				service = registered_services[self.state['uuid']]
				resp = service.processrequest(service, self, dcep.OpNum, dcep)
				i = incident("dionaea.modules.python.smb.dcerpc.request")
				i.con = self
				i.uuid = str(UUID(bytes=bytes.fromhex(self.state['uuid'])))
				i.opnum = dcep.OpNum
				i.report()
			else:
				smblog.info("DCERPC Request without pending action")
			if not resp:
				self.state['stop'] = True

			outbuf = resp
		else:
			# unknown DCERPC packet -> logcrit and bail out.
			smblog.critical('unknown DCERPC packet. bailing out.')


		return outbuf

	def handle_disconnect(self):
		now = datetime.datetime.now()
		dirname = "%04i-%02i-%02i" % (now.year, now.month, now.day)
		dir = os.path.join(g_dionaea.config()['bistreams']['python']['dir'], dirname)
		if not os.path.exists(dir):
			os.makedirs(dir)
		self.fileobj = tempfile.NamedTemporaryFile(delete=False, prefix="smb-" + self.remote.host + ":" + str(self.remote.port) + "-", suffix=".py", dir=dir)
		self.fileobj.write(b"stream = ")
		self.fileobj.write(str(self.bistream).encode())
		self.fileobj.close()
		return 0

class epmapper(smbd):
	def __init__ (self):
		connection.__init__(self,"tcp")
		smbd.__init__(self)

	def handle_io_in(self,data):
		try:
			p = DCERPC_Header(data)
		except:
			t = traceback.format_exc()
			smblog.critical(t)
			return len(data)

		if len(data) < p.FragLen:
			smblog.warning("epmapper - not enough data")
			return 0

		smblog.debug('packet: {0}'.format(p.summary()))

		r = self.process_dcerpc_packet(p)

		if not r or r is None:
			if self.state['stop']:
				smblog.debug('drop dead!')
			else:
				smblog.critical('dcerpc processing failed. bailing out.')
			return len(data)

		smblog.debug('response: {0}'.format(r.summary()))
		self.send(r.build())

		if p.haslayer(Raw):
			smblog.warning('p.haslayer(Raw): {0}'.format(p.getlayer(Raw).build()))
			p.show()

		return len(data)


from . import rpcservices
import inspect
services = inspect.getmembers(rpcservices, inspect.isclass)
for name, servicecls in services:
	if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
		register_rpc_service(servicecls())

