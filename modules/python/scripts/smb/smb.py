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

from dionaea import *

import traceback
import logging
import tempfile

from .include.smbfields import *


smblog = logging.getLogger('SMB')

STATE_START = 0
STATE_SESSIONSETUP = 1
STATE_TREECONNECT = 2
STATE_NTCREATE = 3
STATE_NTWRITE = 4
STATE_NTREAD = 5

# dict with uuid -> [(checkfn, callback),]
registered_calls = {}

# if there are several registered calls for a UUID,
# the smbd will call checkfn on each DCERPC packet and
# return some error if both callbacks want it.
# (should not happen anyway)

def register_dcerpc_call(vuln):
	uuid = vuln.uuid

	global registered_calls
	if uuid in registered_calls:
		registered_calls[uuid].append( vuln )
	else:
		registered_calls[uuid] = [ vuln, ]

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

	def handle_established(self):
		self.timeouts.sustain = 60
		self._in.accounting.limit  = 100*1024
		self._out.accounting.limit = 100*1024
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

		r = self.process(p)
		smblog.debug('packet: {0}'.format(p.summary()))

		if p.haslayer(Raw):
			smblog.warning('p.haslayer(Raw): {0}'.format(p.getlayer(Raw).build()))
			p.show()


		if r:
			smblog.debug('response: {0}'.format(r.summary()))
			#r.show()
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
		#if self.state == STATE_START and p.getlayer(SMB_Header).Command == 0x72:
		if p.getlayer(SMB_Header).Command == 0x72:
			# Negociate Protocol -> Send response that supports minimal features in NT LM 0.12 dialect
			# (could be randomized later to avoid detection - but we need more dialects/options support)
			r = SMB_Negociate_Protocol_Response()
			# we have to select dialect
			c = 0
			tmp = p.getlayer(SMB_Negociate_Protocol_Request_Tail)
			while isinstance(tmp, SMB_Negociate_Protocol_Request_Tail):
				if tmp.BufferData.decode('ascii').find('NT LM 0.12') != -1:
					break
				c += 1
				tmp = tmp.payload

			r.DialectIndex = c

		#elif self.state == STATE_SESSIONSETUP and p.getlayer(SMB_Header).Command == 0x73:
		elif p.getlayer(SMB_Header).Command == 0x73:
#			r = None
#			if p.getlayer(SMB_Sessionsetup_ESEC_AndX_Request).WordCount == 13:
#				print("\n\nDECODING\n\n")
#				#try decoding with wordcount 13
#				p.getlayer(SMB_Header).decode_payload_as(SMB_Sessionsetup_AndX_Request2)
#				r = SMB_Sessionsetup_AndX_Response2()
#			else:
				r = SMB_Sessionsetup_ESEC_AndX_Response()
		elif p.getlayer(SMB_Header).Command == SMB_COM_TREE_CONNECT_ANDX:
			r = SMB_Treeconnect_AndX_Response()
		elif p.getlayer(SMB_Header).Command == SMB_COM_TREE_DISCONNECT:
			r = SMB_Treedisconnect()
		elif p.getlayer(SMB_Header).Command == SMB_COM_NT_CREATE_ANDX:
			r = SMB_NTcreate_AndX_Response()
		elif p.getlayer(SMB_Header).Command == SMB_COM_WRITE:
			r = SMB_Write_AndX_Response()
			r.CountLow = p.getlayer(SMB_Write_AndX_Request).DataLenLow
			self.buf += p.getlayer(SMB_Write_AndX_Request).Data
		elif p.getlayer(SMB_Header).Command == SMB_COM_READ:
			r = SMB_Read_AndX_Response()
			if self.state['lastcmd'] == 'SMB_COM_WRITE':
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
#			if p.getlayer(SMB_Read_AndX_Request).MaxCountLow < len(self.outbuf.build())-self.state['readcount'] :
#				rdata.Bytecount = p.getlayer(SMB_Read_AndX_Request).MaxCountLow+1
#			else:
#				rdata.Bytecount = len(self.outbuf.build()) - self.state['readcount'] +1
#
#			rdata.Bytes = b'\x00' + self.outbuf.build()[ self.state['readcount']: self.state['readcount'] + p.getlayer(SMB_Read_AndX_Request).MaxCountLow ]

			self.state['readcount'] += p.Remaining
			r.DataLenLow = p.Remaining
			r /= rdata

		elif p.getlayer(SMB_Header).Command == 0x25:
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
			rdata.Bytecount = dceplen +1
			rdata.Bytes = b'\x00' + self.outbuf.build()
			
			r /= rdata
		else:
			smblog.critical('...unknown SMB Command. bailing out.')
			p.show()

		if r:
			smbh = SMB_Header()
			smbh.Command = r.smb_cmd
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
			dcep = DCERPC_Header(buf)
		else:
			dcep = buf

		global registered_calls

		outbuf = None

		if dcep.PacketType == 11: #bind
			outbuf = DCERPC_Header()/DCERPC_Bind_Ack()

			tmp = dcep.getlayer(DCERPC_CtxItem)
			c = 0
			while isinstance(tmp, DCERPC_CtxItem):
				c += 1
				ctxitem = DCERPC_Ack_CtxItem()
				for uuid in registered_calls:
					if tmp.UUID == bytes.fromhex(uuid):
						smblog.info('Found a registered UUID (%s). Accepting Bind. (%s)' % (tmp.UUID, str(uuid)))
						self.state['uuid'] = uuid
						# Copy Transfer Syntax to CtxItem
						ctxitem.AckResult = 0
						ctxitem.AckReason = 0
						ctxitem.TransferSyntax = tmp.TransItems[:20]

				outbuf /= ctxitem
				tmp = tmp.payload
		
			outbuf.NumCtxItems = c
			outbuf.FragLen = len(outbuf.build())
		elif dcep.PacketType == 0: #request
			callbacklist = []
			if 'uuid' in self.state:
				reglist = registered_calls[self.state['uuid']]
				for vuln in reglist:
					if dcep.OpNum == vuln.opnum:
						callbacklist.append(vuln.processrequest)

			resp = None
			if len(callbacklist) == 1:
				# callback wants this and is only one
				resp = callbacklist[0](dcep)
			elif len(callbacklist) > 1:
				smblog.critical('More than one registered callback wants to have request. Should not happen!')
			
			if not resp:
				self.state['stop'] = True

			outbuf = resp
		else:
			# unknown DCERPC packet -> logcrit and bail out.
			smblog.critical('unknown DCERPC packet. bailing out.')

		dcep.show()

		return outbuf

	def handle_disconnect(self):
		self.fileobj = tempfile.NamedTemporaryFile(delete=False, prefix="smb-" + self.remote.host + ":" + str(self.remote.port) + "-", suffix=".py", dir=g_dionaea.config()['bistreams']['python']['dir'])
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

		smblog.debug('packet: {0}'.format(p.summary()))

		r = self.process_dcerpc_packet(p)

		if not r:
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


from . import rpcvulns
import inspect
vulns = inspect.getmembers(rpcvulns, inspect.isclass)

for name, vulncls in vulns:
	if not name == 'RPCVULN' and issubclass(vulncls, rpcvulns.RPCVULN):
		register_dcerpc_call(vulncls)

