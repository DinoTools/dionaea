#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2010  Tan Kean Siong & Markus Koetter
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

from dionaea.core import ihandler, incident, connection, g_dionaea

import datetime
import traceback
import logging
import binascii
import os
import tempfile

from dionaea.smb.include.smbfields import *
from dionaea.smb.include.packet import Raw
from .include.tds import *

logger = logging.getLogger('MSSQL')

class mssqld(connection):
	def __init__ (self):
		connection.__init__(self,"tcp")
		self.buf = b''

	def handle_established(self):
		self.timeouts.idle = 120
		self.processors()

		
		if False:
			# FIXME SESSIONDUMP remove at some point
			# useful to dump sessions which are _large_
			self.session = tempfile.NamedTemporaryFile(delete=False, prefix='mssql_session-', dir="/tmp/")
		else:
			self.session = None

	def handle_io_in(self, data):
		l=0
		size = 0
		chunk = b''
		while len(data) > l:
#			logger.warn("len(data) {} l {}".format(len(data),l))
			p = None
			try:
				if len(data) - l  < 8: # length of TDS_Header
					logger.warn("Incomplete TDS_Header")
					return l

				p = TDS_Header(data[l:l+8])
				p.show()

				if p.Length == 0:
					logger.warn("Bad TDS Header, Length = 0")
					return l

				if len(data[l:]) < p.Length:
					return l
				
				chunk = data[l:l+p.Length]
				p = TDS_Header(chunk)
				
				l+=p.Length
				self.buf += chunk[8:]
				self.pendingPacketType = p.Type

				if p.Status != TDS_STATUS_EOM:
					# Command spans multiple packets TDS_ things
					# this is not the last packet
					continue
			except:
				t = traceback.format_exc()
				logger.critical(t)
				return l
	
			if self.pendingPacketType == TDS_TYPES_PRE_LOGIN:
				x = TDS_Prelogin_Request(self.buf)
			elif self.pendingPacketType == TDS_TYPES_TDS7_LOGIN:
				x = TDS_Login7_Request(self.buf)
			elif self.pendingPacketType == TDS_TYPES_SQL_BATCH:
				x = TDS_SQLBatchData(self.buf)
			elif self.pendingPacketType == TDS_TYPES_PRETDS7_LOGIN:
				x = TDS_PreTDS7_Login_Request(self.buf)
			elif self.pendingPacketType == TDS_TYPES_TDS5_QUERY:
				x = TDS_TDS5_Query_Request(self.buf)

			self.buf = b''
			x.show()

			r = None
			
			r = self.process( self.pendingPacketType, x, chunk)
			if r:
				mssqlheader = TDS_Header(Tokens=[])
				mssqlheader.Status = TDS_STATUS_EOM
				mssqlheader.PacketID = p.getlayer(TDS_Header).PacketID
				mssqlheader.SPID = p.getlayer(TDS_Header).SPID
				if type(r) == list:
					# I'm pretty sure only TDS_Tokens have TDS_TYPES_TABULAR_RESULT
					mssqlheader.Type = TDS_TYPES_TABULAR_RESULT
					mssqlheader.Tokens = r
					rp = mssqlheader
				else:
					mssqlheader.Type = r.tds_type
					rp = mssqlheader/r
				rp.Length = len(rp)
				rp.show()
				self.send(rp.build())
				
#		logger.warn("return len(data) {} l {}".format(len(data),l))
		return l

	def decode_password(self, password):
		decoded = ""
		for p in password:
			j = ord(p)
			j = j^0xa5
			k = ((j&0x0F) << 4)| ((j&0xF0) >> 4)
			decoded += chr(k)
		return decoded

	def process(self, PacketType, p, data):
		r =''
		rp = None
		
		if PacketType == TDS_TYPES_PRE_LOGIN:
			r = TDS_Prelogin_Response()
			#FIXME: any better way to initialise this? 
			r.VersionToken.TokenType = 0x00
			r.VersionToken.Offset = 26
			r.VersionToken.Len = 6
			r.EncryptionToken.TokenType = 0x01
			r.EncryptionToken.Offset = 32
			r.EncryptionToken.Len = 1
			r.InstanceToken.TokenType = 0x02
			r.InstanceToken.Offset = 33
			r.InstanceToken.Len = 1
			r.ThreadIDToken.TokenType = 0x03
			r.ThreadIDToken.Offset = 34
			r.ThreadIDToken.Len = 0
			r.MARSToken.TokenType = 0x04
			r.MARSToken.Offset = 34
			r.MARSToken.Len = 1

		elif PacketType == TDS_TYPES_TDS7_LOGIN:
			# another layers TDS_Token_EnvChange, TDS_Token_Info() can be added
			# example : r = TDS_Token_EnvChange()/TDS_Token_Info()/TDS_Token_LoginACK()/TDS_Token_Done()
			# for the moment, only these 2 layers have binded
			l = p.getlayer(TDS_Login7_Request)

			# we can gather some values from the client, maybe use for fingerprinting clients
			fields = {}
			for i in ["HostName","UserName", "Password","AppName","ServerName", "CltIntName", "Language", "Database"]:
				ib = 8 + l.getfieldval("ib" + i)
				cch = l.getfieldval("cch" + i)*2
				field = data[ib:ib+cch]
				xfield = field.decode('utf-16')
				if i == "Password":
					xfield = self.decode_password(xfield)
#				logger.info("Field {} {} {}".format(i,field, xfield))
				fields[i] = xfield

			i = incident("dionaea.modules.python.mssql.login")
			i.con = self
			i.username = fields['UserName']
			i.password = fields['Password']

			i.cltintname = fields['CltIntName']
			i.hostname = fields['HostName']
			i.appname = fields['AppName']

			i.report()

			r = [TDS_Token()/TDS_Token_LoginACK(),TDS_Token()/TDS_Token_Done()]

		elif PacketType == TDS_TYPES_PRETDS7_LOGIN:
			r = [TDS_Token()/TDS_Token_LoginACK(),TDS_Token()/TDS_Token_Done()]

		elif PacketType == TDS_TYPES_SQL_BATCH:
			l = p.getlayer(TDS_SQLBatchData)
			cmd = l.SQLBatchData

			if cmd[1] == 0x00:
			# we got unicode, hopefully there is a way to detect this besides using this ugly hack
				cmd = cmd.decode('utf-16')
				cmd = cmd.encode()

			# limit to 1024
			logger.debug("SQL BATCH : {:.1024s}".format(cmd))

			# FIXME SESSIONDUMP remove at some point
			if self.session != None:
				self.session.write(b"COMMAND:\n")
				self.session.write(cmd)
				self.session.write(b"\n")

			i = incident("dionaea.modules.python.mssql.cmd")
			i.con = self
			i.status = "complete"
			i.cmd = cmd
			i.report()

			# FIXME this reply is wrong too
			# proper replies require parsing the SQLBatchData into statement and compiling a TDS_Token per statement
			r = [TDS_Token()/TDS_Token_ColMetaData(),TDS_Token()/TDS_Token_Row(),TDS_Token()/TDS_Token_ReturnStatus(),TDS_Token()/TDS_Token_DoneProc()]

		elif PacketType == TDS_TYPES_TDS5_QUERY:
			# FIXME the reply is wrong, 
			# /opt/freetds/bin/tsql  -H 127.0.0.1 -p 1433 -U sa -v -D test
			# dies with
			# Msg 20020, Level 9, State -1, Server OpenClient, Line -1
			# Bad token from the server: Datastream processing out of sync
			r = [TDS_Token()/TDS_Token_ColMetaData(),TDS_Token()/TDS_Token_Row(),TDS_Token()/TDS_Token_ReturnStatus(),TDS_Token()/TDS_Token_DoneProc()]

		else:
			logger.warn("UNKNOWN PACKET TYPE FOR MSSQL {}".format(PacketType))
		
		return r
	
	def handle_timeout_idle(self):
		return False

	def handle_disconnect(self):
		# FIXME SESSIONDUMP remove at some point
		if self.session != None:
			if len(self.buf) > 0:
				if self.pendingPacketType == TDS_TYPES_PRE_LOGIN:
					x = TDS_Prelogin_Request(self.buf)
				elif self.pendingPacketType == TDS_TYPES_TDS7_LOGIN:
					x = TDS_Login7_Request(self.buf)
				elif self.pendingPacketType == TDS_TYPES_SQL_BATCH:
					x = TDS_SQLBatchData(self.buf)
				elif self.pendingPacketType == TDS_TYPES_PRETDS7_LOGIN:
					x = TDS_PreTDS7_Login_Request(self.buf)
				elif self.pendingPacketType == TDS_TYPES_TDS5_QUERY:
					x = TDS_TDS5_Query_Request(self.buf)
	
				self.buf = b''
				x.show()
	
				r = None
				
				r = self.process( self.pendingPacketType, x, self.buf[9:])
			self.session.close()
		return False

