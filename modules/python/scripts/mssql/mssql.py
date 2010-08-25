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

from dionaea.core import *

import datetime
import traceback
import logging
import binascii
import os

from dionaea.smb.include.smbfields import *
from dionaea.smb.include.packet import Raw
from .include.tds import *

mssqllog = logging.getLogger('MSSQL')

class mssqld(connection):
	def __init__ (self):
		connection.__init__(self,"tcp")
		self.bistream_prefix = 'mssql-'

	def handle_established(self):
		self.timeouts.idle = 120
		self.processors()

	def handle_io_in(self,data):
		p = None
		try:
			p = TDS_Header(data)
		
		except:
			t = traceback.format_exc()
			mssqllog.critical(t)
			return len(data)
		
		p.show()
		r = None
		r = self.process(p)
			
		if r :
			r.show()
			self.send(r.build())
			
		return len(data)

	def process(self, p):
		r =''
		rp = None
		
		mssqlh = p.getlayer(TDS_Header)
		PacketType = mssqlh.Type
		if PacketType == TDS_TYPE_PRE_LOGIN:
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
			
			r = TDS_Token_LoginACK()/TDS_Token_Done()

		elif PacketType == TDS_TYPES_SQL_BATCH:
			r = TDS_Token_ColMetaData()/TDS_Token_Row()/TDS_Token_ReturnStatus()/TDS_Token_DoneProc()

		else:
			pass
		
		if r:
			mssqlheader = TDS_Header()
			mssqlheader.Type = r.tds_type
			mssqlheader.PacketID = p.getlayer(TDS_Header).PacketID
			mssqlheader.SPID = p.getlayer(TDS_Header).SPID
			
			rp = mssqlheader/r
			rp.Length = len(rp)
		
		return rp
	
	def handle_timeout_idle(self):
		return False

	def handle_disconnect(self):
		return 0
			

