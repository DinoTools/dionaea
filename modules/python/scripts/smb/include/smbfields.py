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

import datetime

from .packet import *
from .fieldtypes import *


SMB_Commands = {
	0x25:"SMB_COM_TRANS",
	0x2E:"SMB_COM_READ",
	0x2F:"SMB_COM_WRITE",
	0x72:"SMB_COM_NEGOTIATE",
	0x73:"SMB_COM_SESSION_SETUP_ANDX",
	0x75:"SMB_COM_TREE_CONNECT_ANDX",
	0xA2:"SMB_COM_NT_CREATE_ANDX",
	0xFF:"SMB_COM_NONE",
}

DCERPC_PacketTypes = {
	11:"Bind",
	12:"Bind Ack",
	0:"Request",
}

class SMBNullField(StrField):
	def __init__(self, name, default, fmt="H", remain=0):
		StrField.__init__(self, name, default, fmt, remain)
		self.is_unicode = False
	def addfield(self, pkt, s, val):
		if pkt.firstlayer().getlayer(SMB_Header).Flags2 & 0x8000:
			return UnicodeNullField.addfield(self, pkt, s, val)
		else:
			return StrNullField.addfield(self, pkt, s, val)
	def getfield(self, pkt, s):
		smbhdr = pkt
		while not isinstance(smbhdr, SMB_Header) and smbhdr != None:
			smbhdr = smbhdr.underlayer
			
		if smbhdr and smbhdr.Flags2 & 0x8000:
			return UnicodeNullField.getfield(self, pkt, s)
		else:
			return StrNullField.getfield(self, pkt, s)

class NBTSession(Packet):
	name="NBT Session Packet"
	fields_desc= [
		ByteEnumField("TYPE",0,
			{0x00:"Session Message",
			0x81:"Session Request",
			0x82:"Positive Session Response",
			0x83:"Negative Session Response",
			0x84:"Retarget Session Response",
			0x85:"Session Keepalive"}),
		BitField("RESERVED",0x00,7),
		BitField("LENGTH",0,17)
	]

	def post_build(self, p, pay):
		self.LENGTH = len(pay)
		p = self.do_build()
		return p+pay

class NBTSession_Request(Packet):
	name="NBT Session Request"
	fields_desc= [
		StrNullField("CalledName","ALICE"),
		StrNullField("CallingName","BOB"),
	]


class SMB_Header(Packet):
	name="SMB Header"
	fields_desc = [
		StrFixedLenField("Start",b'\xffSMB',4),
		XByteEnumField("Command",0x72,SMB_Commands),
		LEIntField("Status",0),
		XByteField("Flags",0x98),
		XLEShortField("Flags2",0x1),
		LEShortField("PIDHigh",0x0000),
		LELongField("Signature",0x0),
		LEShortField("Unused",0x0),
		LEShortField("TID",0xffff),
		LEShortField("PID",0),
		LEShortField("UID",0),
		LEShortField("MID",0),
	]

class SMB_Parameters(Packet):
	name="SMB Parameters"
	fields_desc = [
		FieldLenField('Wordcount', None, fmt='B', length_of="Words"),
		StrLenField('Words', '', length_from = lambda pkt: pkt.Wordcount*2),
	]

class SMB_Data(Packet):
	name="SMB Data"
	fields_desc = [
		FieldLenField('Bytecount', None, fmt='<H', length_of="Bytes"),
		StrLenField('Bytes', '', length_from = lambda pkt: pkt.Bytecount),
	]

class SMB_Negociate_Protocol_Request_Counts(Packet):
	name = "SMB Negociate_Protocol_Request_Counts"
	fields_desc = [
		ByteField("WordCount",0),
		LEShortField("ByteCount",12),
	]

class SMB_Negociate_Protocol_Request_Tail(Packet):
	name="SMB Negociate Protocol Request Tail"
	fields_desc=[
		ByteField("BufferFormat",0x02),
		StrNullField("BufferData","NT LM 0.12"),
	]

class SMB_Negociate_Protocol_Response(Packet):
	name="SMB Negociate Response"
	smb_cmd = 0x72
	fields_desc = [
		ByteField("WordCount",17),
		LEShortField("DialectIndex",0),
		XByteField("SecurityMode",0),
		LEShortField("MaxMPXCount",1),
		LEShortField("MaxVCs",1),
		LEIntField("MaxBufferS",4096),
		LEIntField("MaxRawBuffer",65536),
		LEIntField("SessionKey",0),
		XLEIntField("Capabilities",0x20),
		NTTimeField("SystemTime",datetime.datetime.now()),
		ShortField("SystemTimeZone",0xc4ff),
		ByteField("KeyLength", 0),
		LEShortField("ByteCount", 0),
		#FieldLenField("ByteCount", None, fmt='<H', length_of="PrimaryDomain"),
		#StrLenField("PrimaryDomain", "local", length_from=lambda x:x.ByteCount),
	]

class SMB_Sessionsetup_ESEC_AndX_Request(Packet):
	name="SMB Sessionsetup ESEC AndX Request"
	fields_desc = [
		ByteField("WordCount",13),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",96),
		LEShortField("MaxBufferS",2920),
		LEShortField("MaxMPXCount",50),
		LEShortField("VCNumber",0),
		LEIntField("SessionKey",0),
		FieldLenField("SecurityBlobLength", None, fmt='<H', length_of="SecurityBlob"),
		LEIntField("Reserved2",0),
		XLEIntField("Capabilities",0x05),
		LEShortField("ByteCount",35),
		StrLenField("SecurityBlob", "Pass", length_from=lambda x:x.SecurityBlobLength),
		#ByteField("FixNullTerminated", 0),
		SMBNullField("NativeOS","Windows"),
		SMBNullField("NativeLanManager","Windows"),
		SMBNullField("PrimaryDomain","WORKGROUP")
	]

class SMB_Sessionsetup_AndX_Request(Packet):
	name="SMB Sessionsetup AndX Request"
	fields_desc = [
		ByteField("WordCount",10),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",0),
		LEShortField("MaxBufferS",2920),
		LEShortField("MaxMPXCount",50),
		LEShortField("VCNumber",0),
		LEIntField("SessionKey",0),
		FieldLenField("PasswordLength", None, fmt='<H', length_of="Password"),
		LEIntField("Reserved2",0),
		LEShortField("ByteCount",35),
		StrLenField("Password", "Pass", length_from=lambda x:x.PasswordLength),
		SMBNullField("Account", ""),
		SMBNullField("PrimaryDomain","WORKGROUP"),
		SMBNullField("NativeOS","Windows"),
		SMBNullField("NativeLanManager","Windows"),
	]

# ugly support for strange wordcount 13
# TODO: make it possible to catch both wordcounts with one class
class SMB_Sessionsetup_AndX_Request2(Packet):
	name="SMB Sessionsetup AndX Request2"
	fields_desc = [
		ByteField("WordCount",13),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",0),
		LEShortField("MaxBufferS",2920),
		LEShortField("MaxMPXCount",50),
		LEShortField("VCNumber",0),
		LEIntField("SessionKey",0),
		FieldLenField("PasswordLength", None, fmt='<H', length_of="Password"),
		LEShortField("UnicodePasswordLength",0),
		LEIntField("Reserved2",0),
		XLEIntField("Capabilities",0),
		LEShortField("ByteCount",35),
		StrLenField("Password", "Pass", length_from=lambda x:x.PasswordLength),
		SMBNullField("Account", ""),
		SMBNullField("PrimaryDomain","WORKGROUP"),
		SMBNullField("NativeOS","Windows"),
		SMBNullField("NativeLanManager","Windows"),
	]

class SMB_Sessionsetup_AndX_Response(Packet):
	name="SMB Sessionsetup AndX Response"
	smb_cmd = 0x73
	fields_desc = [
		ByteField("WordCount",4),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",0),
		XLEShortField("Action",1),
		FieldLenField("BlobLength", None, fmt='<H', length_of="Blob"),
		LEShortField("ByteCount",55),
		StrLenField("Blob", b"\xa1\x07\x30\x05\xa0\x03\x0a\x01", length_from=lambda x:x.BlobLength),
		StrNullField("NativeOS","Windows 5.1"),
		StrNullField("NativeLanManager","Windows 2000 LAN Manager"),
		StrNullField("PrimaryDomain","WORKGROUP"),
	]

class SMB_Sessionsetup_AndX_Response2(Packet):
	name="SMB Sessionsetup AndX Response"
	smb_cmd = 0x73
	fields_desc = [
		ByteField("WordCount",3),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",0),
		XLEShortField("Action",1),
		LEShortField("ByteCount",47),
		StrNullField("NativeOS","Windows 5.1"),
		StrNullField("NativeLanManager","Windows 2000 LAN Manager"),
		StrNullField("PrimaryDomain","WORKGROUP"),
	]

class SMB_Treeconnect_AndX_Request(Packet):
	name = "SMB Treeconnect AndX Request"
	fields_desc = [
		ByteField("WordCount",4),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",0),
		XLEShortField("Flags",0x2),
		FieldLenField("PasswordLength", None, fmt='<H', length_of="Password"),
		LEShortField("ByteCount",18),
		StrLenField("Password", "Pass", length_from=lambda x:x.PasswordLength),
		ByteField("FixNullTerminated", 0),
		SMBNullField("Path","\\\\WIN2K\\IPC$"),
		SMBNullField("Service","IPC")
	]

class SMB_Treeconnect_AndX_Response(Packet):
	name="SMB Treeconnect AndX Response"
	smb_cmd = 0x75
	fields_desc = [
		ByteField("WordCount",3),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",46), #windows xp gives senseless 46
		XLEShortField("OptSupport",1),
		LEShortField("ByteCount",5),
		StrNullField("Service","IPC"),
		StrNullField("NativeFilesystem",""),
	]

class SMB_NTcreate_AndX_Request(Packet):
	name = "SMB NTcreate AndX Request"
	fields_desc = [
		ByteField("WordCount",4),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",0),
		ByteField("Reserved2",0),
		LEShortField("FilenameLen",0x2),
		XLEIntField("CreateFlags",0),
		XLEIntField("RootFID",0),
		XLEIntField("AccessMask",0),
		LELongField("AllocationSize",0),
		XLEIntField("FileAttributes",0),
		XLEIntField("ShareAccess",3),
		LEIntField("Disposition",1),
		XLEIntField("CreateOptions",0),
		LEIntField("Impersonation",1),
		XByteField("SecurityFlags",0),
		LEShortField("ByteCount",0),
		FixGapField("FixGap", b'\0'),
		SMBNullField("Filename","\\lsarpc")
	]

class SMB_NTcreate_AndX_Response(Packet):
	name="SMB NTcreate AndX Response"
	smb_cmd = 0xa2
	strange_packet_tail = bytes.fromhex('000000000000000000000000000000000000000000009b0112009b0112000000')
	fields_desc = [
		ByteField("WordCount",42),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",0),
		ByteField("OplockLevel",0),
		XLEShortField("FID",0x4000),
		XLEIntField("CreateAction",1),
		NTTimeField("Created",0),
		NTTimeField("LastAccess",0),
		NTTimeField("LastModified",0),
		NTTimeField("Change",0),
		XLEIntField("FileAttributes",0x80),
		LELongField("AllocationSize",4096),
		LELongField("EndOfFile",0),
		LEShortField("FileType",2),
		XLEShortField("IPCstate",0x5ff),
		ByteField("IsDirectory",0),
		LEShortField("ByteCount",0),
		StrLenField("FixStrangeness", strange_packet_tail, length_from=lambda x:len(strange_packet_tail)),
	]


class SMB_Write_AndX_Request(Packet):
	name = "SMB Write AndX Request"
	fields_desc = [
		ByteField("WordCount",14),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",0),
		XLEShortField("FID",0),
		LEIntField("Offset",0),
		XIntField("Reserved2",0xffffffff),
		XLEShortField("WriteMode",8),
		LEShortField("Remaining",0),
		LEShortField("DataLenHigh",0), #multiply with 64k		
		LEShortField("DataLenLow",0),
		LEShortField("DataOffset",0),
		IntField("HighOffset",0),
	]

class SMB_Write_AndX_Response(Packet):
	name = "SMB Write AndX Response"
	smb_cmd = 0x2f
	fields_desc = [
		ByteField("WordCount",6),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",47),
		LEShortField("CountLow",0),
		LEShortField("Remaining",0xffff),
		LEShortField("CountHigh",0), #multiply with 64k		
		LEShortField("Reserved",0),
		LEShortField("ByteCount",0),
	]

class SMB_Read_AndX_Request(Packet):
	name = "SMB Read AndX Request"
	fields_desc = [
		ByteField("WordCount",10),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",0),
		XLEShortField("FID",0),
		LEIntField("Offset",0),
		LEShortField("MaxCountLow",0),
		LEShortField("MinCount",0),
		LEShortField("Remaining",0),
		IntField("FixGap1", 0xffffffff),
		LEShortField("ByteCount",0),
		IntField("FixGap2", 0),
	]

class SMB_Read_AndX_Response(Packet):
	name = "SMB Read AndX Response"
	smb_cmd = 0x2e
	fields_desc = [
		ByteField("WordCount",12),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("Reserved1",0),
		LEShortField("AndXOffset",0),
		LEShortField("Remaining",0),
		LEShortField("DataCompactMode",0),
		LEShortField("Reserved2",0),
		LEShortField("DataLenLow",0),
		LEShortField("DataOffset",60),
		LEIntField("DataLenHigh",0), #multiply with 64k
		StrLenField("Reserved3", b"\0"*6, length_from=lambda x:6),
	]

class SMB_Trans_Request(Packet):
	name = "SMB Trans Request"
	fields_desc = [
		ByteField("WordCount",16),
		LEShortField("TotalParamCount",0),
		LEShortField("TotalDataCount",0),
		LEShortField("MaxParamCount",0),
		LEShortField("MaxDataCount",0),
		ByteField("MaxSetupCount",0),
		ByteField("Reserved1",0),
		XLEShortField("Flags",0),
		LEIntField("Timeout",0),
		ShortField("Reserved2",0),
		LEShortField("ParamCount",0),
		LEShortField("ParamOffset",0),
		LEShortField("DataCount",0),
		LEShortField("DataOffset",0),
		ByteField("SetupCount",0),
		ByteField("Reserved3",0),
		XLEShortField("TransactFunction",0x26),
		XLEShortField("FID",0),
		LEShortField("ByteCount",0),
		ByteField("FixGap", 0),
		SMBNullField("TransactionName","\\PIPE\\"),
		FixGapField("FixGap2", b'\0\0'),
	]

class SMB_Trans_Response(Packet):
	name = "SMB Trans Response"
	smb_cmd = 0x25
	fields_desc = [
		ByteField("WordCount",10),
		LEShortField("TotalParamCount",0),
		LEShortField("TotalDataCount",0),
		LEShortField("Reserved1",0),
		LEShortField("ParamCount",0),
		LEShortField("ParamOffset",56),
		LEShortField("ParamDisplacement",0),
		LEShortField("DataCount",0),
		LEShortField("DataOffset",56),
		LEShortField("DataDisplacement",0),
		ByteField("SetupCount",0),
		ByteField("Reserved2",0),
		LEShortField("ByteCount",0),
		ByteField("Padding", 0),
	]

class DCERPC_Header(Packet):
	name = "DCERPC Header"
	fields_desc = [
		ByteField("Version",5),
		ByteField("VersionMinor",0),
		ByteEnumField("PacketType",0,DCERPC_PacketTypes),
		XByteField("PacketFlags",0x3),
		LEIntField("DataRepresentation",16),
		LEShortField("FragLen",0),
		LEShortField("AuthLen",0),
		LEIntField("CallID",0),
	]

class DCERPC_Request(Packet):
	name = "DCERPC Request"
	fields_desc = [
		FieldLenField("AllocHint", 14, fmt='<I', length_of="StubData"),
		LEShortField("ContextID",0),
		LEShortField("OpNum",0),
		StrLenField("StubData", "", length_from=lambda x:x.AllocHint),
	]

class DCERPC_Bind(Packet):
	name = "DCERPC Bind"
	fields_desc = [
		LEShortField("MaxTransmitFrag",5840),
		LEShortField("MaxReceiveFrag",5840),
		XLEIntField("AssocGroup",0),
		ByteField("NumCtxItems",1),
		StrLenField("FixGap", "\0"*3, length_from=lambda x:3),
	]

class DCERPC_CtxItem(Packet):
	name = "DCERPC CtxItem"
	fields_desc = [
		LEShortField("ContextID",0),
		FieldLenField('NumTransItems', 1, fmt='B', length_of="TransItems"),
		ByteField("FixGap", 0),
		StrLenField('UUID', '', length_from = lambda x: 16),
		LEShortField("InterfaceVer",0),
		LEShortField("InterfaceVerMinor",0),
		StrLenField('TransItems', '', length_from = lambda pkt: pkt.NumTransItems*20),
	]

class DCERPC_Bind_Ack(Packet):
	name = "DCERPC Bind Ack"
	fields_desc = [
		LEShortField("MaxTransmitFrag",4280),
		LEShortField("MaxReceiveFrag",4280),
		XLEIntField("AssocGroup",0x4ef7),
		FieldLenField("SecondAddrLen", 14, fmt='<H', length_of="SecondAddr"),
		StrLenField("SecondAddr", "\\PIPE\\browser\0", length_from=lambda x:x.SecondAddrLen),
		ByteField("NumCtxItems",1),
		StrLenField("FixGap", "\0"*3, length_from=lambda x:3),
	]

class DCERPC_Ack_CtxItem(Packet):
	name = "DCERPC CtxItem"
	fields_desc = [
		LEShortField("AckResult",2),
		LEShortField("AckReason",1),
		#Field("TransferSyntax","\0"*16, fmt="QQ"),
		StrLenField("TransferSyntax", "\0"*20, length_from=lambda x:20),
	]

bind_bottom_up(NBTSession, NBTSession_Request, TYPE = lambda x: x==0x81)
bind_bottom_up(NBTSession, SMB_Header, TYPE = lambda x: x==0)
bind_bottom_up(SMB_Header, SMB_Negociate_Protocol_Response, Command=lambda x: x==0x72, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Negociate_Protocol_Request_Counts, Command=lambda x: x==0x72, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Sessionsetup_AndX_Request, Command=lambda x: x==0x73, Flags=lambda x: not x&0x80, Flags2=lambda x: not x&2)
bind_bottom_up(SMB_Header, SMB_Sessionsetup_ESEC_AndX_Request, Command=lambda x: x==0x73, Flags=lambda x: not x&0x80, Flags2=lambda x: x&2)
bind_bottom_up(SMB_Header, SMB_Sessionsetup_AndX_Response, Command=lambda x: x==0x73, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Treeconnect_AndX_Request, Command=lambda x: x==0x75, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Treeconnect_AndX_Response, Command=lambda x: x==0x75, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_NTcreate_AndX_Request, Command=lambda x: x==0xa2, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_NTcreate_AndX_Response, Command=lambda x: x==0xa2, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Trans_Request, Command=lambda x: x==0x25, Flags=lambda x: not x&0x80)

bind_bottom_up(SMB_Header, SMB_Write_AndX_Request, Command=lambda x: x==0x2f, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Write_AndX_Response, Command=lambda x: x==0x2f, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Read_AndX_Request, Command=lambda x: x==0x2e, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Read_AndX_Response, Command=lambda x: x==0x2e, Flags=lambda x: x&0x80)

bind_bottom_up(SMB_Write_AndX_Request, SMB_Data)
bind_bottom_up(SMB_Read_AndX_Response, SMB_Data)

bind_bottom_up(SMB_Trans_Request, DCERPC_Header)
bind_bottom_up(DCERPC_Header, DCERPC_Request, PacketType=lambda x: x==0)
bind_bottom_up(DCERPC_Header, DCERPC_Bind, PacketType=lambda x: x==11)
bind_bottom_up(DCERPC_Header, DCERPC_Bind_Ack, PacketType=lambda x: x==12)
bind_bottom_up(DCERPC_Bind, DCERPC_CtxItem)
bind_bottom_up(DCERPC_CtxItem, DCERPC_CtxItem)

bind_bottom_up(SMB_Sessionsetup_AndX_Request, SMB_Treeconnect_AndX_Request, AndXCommand=lambda x: x==0x75)
bind_bottom_up(SMB_Negociate_Protocol_Request_Counts, SMB_Negociate_Protocol_Request_Tail)
bind_bottom_up(SMB_Negociate_Protocol_Request_Tail, SMB_Negociate_Protocol_Request_Tail)
bind_bottom_up(SMB_Header, SMB_Parameters)
bind_bottom_up(SMB_Parameters, SMB_Data)

bind_top_down(SMB_Header, SMB_Negociate_Protocol_Response, Command=0x72)
bind_top_down(SMB_Header, SMB_Sessionsetup_AndX_Response, Command=0x73)
bind_top_down(SMB_Header, SMB_Treeconnect_AndX_Response, Command=0x75)
bind_top_down(SMB_Header, SMB_NTcreate_AndX_Response, Command=0xa2)
bind_top_down(SMB_Header, SMB_Write_AndX_Response, Command=0x2f)
bind_top_down(SMB_Header, SMB_Read_AndX_Response, Command=0x2e)
bind_top_down(SMB_Header, SMB_Trans_Request, Command=0x25)
bind_top_down(SMB_Read_AndX_Response, SMB_Data)

bind_top_down(DCERPC_Header, DCERPC_Request, PacketType=0)
bind_top_down(DCERPC_Header, DCERPC_Bind, PacketType=11)
bind_top_down(DCERPC_Header, DCERPC_Bind_Ack, PacketType=12)


