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

# Capabilities
CAP_RAW_MODE           = 0x0001 # The server supports SMB_COM_READ_RAW and SMB_COM_WRITE_RAW (obsolescent)
CAP_MPX_MODE           = 0x0002 # The server supports	SMB_COM_READ_MPX and SMB_COM_WRITE_MPX (obsolescent)
CAP_UNICODE            = 0x0004 # The server supports UNICODE strings
CAP_LARGE_FILES        = 0x0008 # The server supports large files with 64 bit offsets
CAP_NT_SMBS            = 0x0010 # The server supports the SMBs particular to the NT LM 0.12 dialect. Implies CAP_NT_FIND.
CAP_RPC_REMOTE_APIS    = 0x0020 # The server supports remote admin API requests via DCE RPC
CAP_STATUS32           = 0x0040 # The server can respond with 32 bit status codes in Status.Status
CAP_LEVEL_II_OPLOCKS   = 0x0080 # The server supports level 2 oplocks	
								# 
CAP_LOCK_AND_READ      = 0x0100 # The server supports the SMB,SMB_COM_LOCK_AND_READ
CAP_NT_FIND            = 0x0200 # Reserved
CAP_NOT_USED		   = 0x0400
CAP_NOT_USED		   = 0x0800
CAP_DFS                = 0x1000 # The server is DFS aware
CAP_INFOLEVEL_PASSTHRU = 0x2000 # The server supports NT information level requests passing	through
CAP_LARGE_READX        = 0x4000 # The server supports large SMB_COM_READ_ANDX (up to 64k)
CAP_LARGE_WRITEX       = 0x8000 # The server supports large SMB_COM_WRITE_ANDX (up to 64k)

CAP_NOT_USED		   = 0x00010000
CAP_NOT_USED		   = 0x00020000
CAP_NOT_USED		   = 0x00040000
CAP_NOT_USED		   = 0x00080000
CAP_NOT_USED		   = 0x00100000
CAP_NOT_USED		   = 0x00200000
CAP_NOT_USED		   = 0x00400000
CAP_UNIX               = 0x00800000 # The server supports CIFS Extensions for UNIX. (See Appendix D for more detail)

CAP_NOT_USED		   = 0x01000000
CAP_RESERVED           = 0x02000000 # Reserved for future use 
CAP_NOT_USED		   = 0x04000000
CAP_NOT_USED		   = 0x08000000
CAP_NOT_USED		   = 0x10000000
CAP_BULK_TRANSFER      = 0x20000000 # The server supports SMB_BULK_READ,	SMB_BULK_WRITE (should be 0, no known implementations)
CAP_COMPRESSED_DATA    = 0x40000000 # The server supports compressed data transfer	(BULK_TRANSFER capability is required to support compressed data transfer).
CAP_EXTENDED_SECURITY  = 0x80000000 # The server supports extended security exchanges

SMB_Negotiate_Capabilities = [
	"RAW_MODE",
	"MPX_MODE",
	"UNICODE",
	"LARGE_FILES",
	"NT_SMBS",
	"RPC_REMOTE_APIS",
	"STATUS32",
	"LEVEL_II_OPLOCKS",

	"LOCK_AND_READ",
	"NT_FIND",
	"0x0400",
	"0x0800",
	"DFS",
	"INFOLEVEL_PASSTHRU",
	"LARGE_READX",
	"LARGE_WRITEX",

	"0x00010000",
	"0x00020000",
	"0x00040000",
	"0x00080000",
	"0x00100000",
	"0x00200000",
	"0x00400000",
	"UNIX",

	"0x01000000",
	"0x02000000",
	"0x04000000",
	"0x08000000",
	"0x10000000",
	"BULK_TRANSFER",
	"COMPRESSED_DATA",
	"EXTENDED_SECURITY",
]

# SMB_Header.Flags
SMB_FLAGS_LOCK_AND_READ         = (1<<0) # Reserved for obsolescent requests LOCK_AND_READ, WRITE_AND_CLOSE LANMAN1.0
SMB_FLAGS_RECEIVE_BUFFER_POSTED = (1<<1) #
SMB_FLAGS_CASES_ENSITIVITY      = (1<<3) # When on, all pathnames in this SMB must be treated as case-less. When off, the pathnames are case sensitive. LANMAN1.0
SMB_FLAGS_CANONICAL_PATHNAMES   = (1<<4) # Obsolescent \u2013 client case maps (canonicalizes) file and directory names; servers must ignore this flag.	5 Reserved for obsolescent requests \u2013 oplocks supported for SMB_COM_OPEN, SMB_COM_CREATE and SMB_COM_CREATE_NEW. Servers must ignore when processing all other SMB commands. LANMAN1.0
SMB_FLAGS_OPLOCKS               = (1<<5) #
SMB_FLAGS_NOTIFY                = (1<<6) #
SMB_FLAGS_REQUEST_RESPONSE      = (1<<7) # When on, this SMB is	being sent from the server in response to a client request. The	Command field usually contains the same value in a protocol	request from the client to the server as in the matching response from the server to the client. This bit unambiguously distinguishes the command request from the command response. 

SMB_Header_Flags = [
"LOCKANDREAD",
"RECVBUF",
"-",
"CASE",

"CANON",
"OPLOCKS",
"NOTIFY",
"REQ_RESP",
]


# SMB_Header.Flags2
SMB_FLAGS2_KNOWS_LONG_NAMES    = (1)  # If set in a request, the server may return long components in path names in the response.	LM1.2X002
SMB_FLAGS2_KNOWS_EAS           = (1<<1)  # If set, the client is aware of extended attributes (EAs).
SMB_FLAGS2_SECURITY_SIGNATURE  = (1<<2)  # If set, the SMB is integrity checked.
SMB_FLAGS2_RESERVED1           = (1<<3)  # Reserved for future use
SMB_FLAGS2_IS_LONG_NAME        = (1<<6)  # If set, any path name in the request is a long name.
SMB_FLAGS2_EXT_SEC             = (1<<11) # If set, the client is aware of Extended Security negotiation.	NT LM 0.12
SMB_FLAGS2_DFS                 = (1<<12) # If set, any request pathnames in this SMB should be resolved in the Distributed File System. NT LM 0.12
SMB_FLAGS2_PAGING_IO           = (1<<13) # If set, indicates that a read will be permitted if the client does not have read permission but does have execute permission. This flag is only useful on a read request.
SMB_FLAGS2_ERR_STATUS          = (1<<14) # If set, specifies that the returned error code is a 32 bit	error code in Status.Status. Otherwise the Status.DosError.ErrorClass and Status.DosError.Error	fields contain the DOS-style error information. When passing NT status codes is negotiated, this flag should be set for every SMB. NT LM 0.12
SMB_FLAGS2_UNICODE             = (1<<15) # If set, any fields of datatype STRING in this SMB	message are encoded as UNICODE. Otherwise, they	are in ASCII. The character encoding for Unicode fields SHOULD be UTF-16 (little endian). NT LM 0.12

SMB_Header_Flags2 = [
"KNOWS_LONG_NAMES",
"KNOWS_EAS",     
"SECURITY_SIGNATURE",
"RESERVED3",

"RESERVED4",
"RESERVED5",
"IS_LONG_NAME",
"RESERVED7",

"RESERVED8",
"RESERVED9",
"RESERVED10",
"EXT_SEC",      

"DFS",                 
"PAGING_IO",
"ERR_STATUS",         
"UNICODE",        
]

# SMB_Header.Command

SMB_COM_CLOSE              = 0x04
SMB_COM_TRANS              = 0x25
SMB_COM_READ               = 0x2E
SMB_COM_WRITE              = 0x2F
SMB_COM_TREE_DISCONNECT    = 0x71
SMB_COM_NEGOTIATE          = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_LOGOFF_ANDX        = 0x74
SMB_COM_TREE_CONNECT_ANDX  = 0x75
SMB_COM_NT_CREATE_ANDX     = 0xA2
SMB_COM_NONE               = 0xFF


SMB_Commands = {
 SMB_COM_CLOSE				:"SMB_COM_CLOSE",
 SMB_COM_TRANS              :"SMB_COM_TRANS",
 SMB_COM_READ               :"SMB_COM_READ",
 SMB_COM_WRITE              :"SMB_COM_WRITE",
 SMB_COM_TREE_DISCONNECT    :"SMB_COM_TREE_DISCONNECT",
 SMB_COM_NEGOTIATE          :"SMB_COM_NEGOTIATE",
 SMB_COM_SESSION_SETUP_ANDX :"SMB_COM_SESSION_SETUP_ANDX",
 SMB_COM_LOGOFF_ANDX        :"SMB_COM_LOGOFF_ANDX",
 SMB_COM_TREE_CONNECT_ANDX  :"SMB_COM_TREE_CONNECT_ANDX",
 SMB_COM_NT_CREATE_ANDX     :"SMB_COM_NT_CREATE_ANDX",
 SMB_COM_NONE               :"SMB_COM_NONE",
}

DCERPC_PacketTypes = {
	11:"Bind",
	12:"Bind Ack",
	0:"Request",
}

class SMBNullField(StrField):
	def __init__(self, name, default, fmt="H", remain=0, utf16=True):
		if utf16:
			UnicodeNullField.__init__(self, name, default, fmt, remain)
		else:
			StrField.__init__(self, name, default, fmt, remain)
	def addfield(self, pkt, s, val):
		if pkt.firstlayer().getlayer(SMB_Header).Flags2 & SMB_FLAGS2_UNICODE:
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
		XByteEnumField("Command",SMB_COM_NEGOTIATE,SMB_Commands),
		LEIntField("Status",0),
#		XByteField("Flags",0x98),
		FlagsField("Flags", 0x98, 8, SMB_Header_Flags),
#		XLEShortField("Flags2",SMB_FLAGS2_KNOWS_LONG_NAMES|SMB_FLAGS2_UNICODE),
		FlagsField("Flags2", SMB_FLAGS2_KNOWS_LONG_NAMES|SMB_FLAGS2_UNICODE, -16, SMB_Header_Flags2),
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
		XLEIntField("Capabilities",0x8000e3fd),
#		FlagsField("Capabilties", 0x8000e3fd, -32, SMB_Negotiate_Capabilities),
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
		ByteField("WordCount",12),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("AndXReserved",0),
		LEShortField("AndXOffset",96),
		LEShortField("MaxBufferSize",2920),
		LEShortField("MaxMPXCount",50),
		LEShortField("VCNumber",0),
		LEIntField("SessionKey",0),
		FieldLenField("SecurityBlobLength", None, fmt='<H', length_of="SecurityBlob"),
		LEIntField("Reserved",0),
#		XLEIntField("Capabilities",0x05),
		FlagsField("Capabilties", 0x8000e3fd, -32, SMB_Negotiate_Capabilities),
		LEShortField("ByteCount",35),
		StrLenField("SecurityBlob", "Pass", length_from=lambda x:x.SecurityBlobLength),
		StrFixedLenField("Padding", "\x00", length_from=lambda x:(x.SecurityBlobLength+1)%2), 
		UnicodeNullField("NativeOS","Windows"),
		UnicodeNullField("NativeLanManager","Windows"),
		UnicodeNullField("PrimaryDomain","WORKGROUP"),
	]

class SMB_Sessionsetup_ESEC_AndX_Response(Packet):
	name="SMB Sessionsetup ESEC AndX Response"
	smb_cmd = 0x73
	fields_desc = [
		ByteField("WordCount",4),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("AndXReserved",0),
		LEShortField("AndXOffset",0),
		XLEShortField("Action",1),
		FieldLenField("SecurityBlobLength", None, fmt='<H', length_of="SecurityBlob"),
		StrLenField("SecurityBlob", "", length_from=lambda x:x.SecurityBlobLength),
		LEShortField("ByteCount",75),
		StrFixedLenField("Padding", "\x00", length_from=lambda x:(len(x.SecurityBlob)+1)%2), 
		UnicodeNullField("NativeOS","Windows 5.1"),
		UnicodeNullField("NativeLanManager","Windows 2000 LAN Manager"),
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
		SMBNullField("Account", "", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
		SMBNullField("PrimaryDomain","WORKGROUP", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
		SMBNullField("NativeOS","Windows", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
		SMBNullField("NativeLanManager","Windows", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
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


# CIFS-TR-1p00_FINAL.pdf 665616b44740177c86051c961fdf6768
# page 65
# WordCount 13 is used to negotiate "NT LM 0.12" if the server does not support
# Extended Security
class SMB_Sessionsetup_AndX_Request2(Packet):
	name="SMB Sessionsetup AndX Request2"
	fields_desc = [
		ByteField("WordCount",13),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("AndXReserved",0),
		LEShortField("AndXOffset",0),
		LEShortField("MaxBufferSize",2920),
		LEShortField("MaxMPXCount",50),
		LEShortField("VCNumber",0),
		LEIntField("SessionKey",0),
		FieldLenField("PasswordLength", None, fmt='<H', length_of="Password"),
		FieldLenField("UnicodePasswordLength", None, fmt='<H', length_of="UnicodePassword"),
		LEIntField("Reserved2",0),
#		XLEIntField("Capabilities",0),
		FlagsField("Capabilties", 0x8000e3fd, -32, SMB_Negotiate_Capabilities),
		LEShortField("ByteCount",35),
		StrLenField("Password", "Pass", length_from=lambda x:x.PasswordLength),
		StrLenField("UnicodePassword", "UniPass", length_from=lambda x:x.UnicodePasswordLength),
		StrFixedLenField("Padding", "\x00", length_from=lambda x:(x.PasswordLength+1)%2), 
		SMBNullField("Account", "", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
		SMBNullField("PrimaryDomain","WORKGROUP", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
		SMBNullField("NativeOS","Windows", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
		SMBNullField("NativeLanManager","Windows", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
		StrFixedLenField("Padding2", "\x00", length_from=lambda x:(len(x.Account)+len(x.PrimaryDomain)+len(x.NativeOS)+len(x.NativeLanManager)+1)%2), 
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
		UnicodeNullField("NativeOS","Windows 5.1"),
		UnicodeNullField("NativeLanManager","Windows 2000 LAN Manager"),
		UnicodeNullField("PrimaryDomain","WORKGROUP"),
	]

# CIFS-TR-1p00_FINAL.pdf 665616b44740177c86051c961fdf6768
# page 35
# Strings that are never passed in Unicode are:
# * The service name string in the Tree_Connect_AndX SMB.
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
		FixGapField("FixGap", b'\0'),
		SMBNullField("Path","\\\\WIN2K\\IPC$", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
		StrNullField("Service","IPC")
	]

class SMB_Treedisconnect(Packet):
	name = "SMB Tree Disconnect"
	smb_cmd = 0x71
	fields_desc = [
		ByteField("WordCount",0),
		LEShortField("ByteCount",0),
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
		SMBNullField("Filename","\\lsarpc", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE)
	]


# page 77

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

# page 83
# the manual says there is a Padding Byte right after the bytecount
# wireshark disagrees
# so we swim with the fishes for now

class SMB_Write_AndX_Request(Packet):
	name = "SMB Write AndX Request"
	fields_desc = [
		ByteField("WordCount",14),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("AndXReserved",0),
		LEShortField("AndXOffset",0),
		XLEShortField("FID",0),
		LEIntField("Offset",0),
		XIntField("Reserved2",0xffffffff),
		XLEShortField("WriteMode",8),
		FieldLenField("Remaining", None, fmt='<H', length_of="Data"),
		LEShortField("DataLenHigh",0), #multiply with 64k		
		LEShortField("DataLenLow",0),
		LEShortField("DataOffset",0),
		ConditionalField(IntField("HighOffset",0), lambda x:x.WordCount==14),
		XLEShortField("ByteCount",  0),
#		StrFixedLenField("Padding", 0xEE, 1),
		StrLenField("Data", b"", length_from=lambda x:x.Remaining),
	]

class SMB_Write_AndX_Response(Packet):
	name = "SMB Write AndX Response"
	smb_cmd = 0x2f
	fields_desc = [
		ByteField("WordCount",6),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("AndXReserved",0),
		LEShortField("AndXOffset",47),
		LEShortField("CountLow",0),
		LEShortField("Remaining",0xffff),
		LEShortField("CountHigh",0), #multiply with 64k		
		LEShortField("Reserved",0),
		LEShortField("ByteCount",0),
	]

# page 82
# I have no idea why we need the FixGap's
class SMB_Read_AndX_Request(Packet):
	name = "SMB Read AndX Request"
	fields_desc = [
		ByteField("WordCount",10),
		ByteEnumField("AndXCommand",0xff,SMB_Commands),
		ByteField("AndXReserved",0),
		LEShortField("AndXOffset",0),
		XLEShortField("FID",0),
		LEIntField("Offset",0),
		LEShortField("MaxCountLow",0),
		LEShortField("MinCount",0),
		IntField("FixGap1", 0xffffffff),
		LEShortField("Remaining",0),
		ConditionalField(LEIntField("HighOffset", 0), lambda x:x.WordCount==12),
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

# page 44
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
#bind_bottom_up(SMB_Header, SMB_Sessionsetup_AndX_Request, Command=lambda x: x==0x73, Flags=lambda x: not x&0x80, Flags2=lambda x: not x&2)
bind_bottom_up(SMB_Header, SMB_Sessionsetup_AndX_Request2, Command=lambda x: x==0x73, Flags=lambda x: not x&0x80, Flags2=lambda x: not x&SMB_FLAGS2_EXT_SEC)
bind_bottom_up(SMB_Header, SMB_Sessionsetup_ESEC_AndX_Request, Command=lambda x: x==0x73, Flags=lambda x: not x&0x80, Flags2=lambda x: x&SMB_FLAGS2_EXT_SEC)
bind_bottom_up(SMB_Header, SMB_Sessionsetup_AndX_Response, Command=lambda x: x==0x73, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Treedisconnect, Command=lambda x: x==0x71)
bind_bottom_up(SMB_Header, SMB_Treeconnect_AndX_Request, Command=lambda x: x==0x75, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Treeconnect_AndX_Response, Command=lambda x: x==0x75, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_NTcreate_AndX_Request, Command=lambda x: x==0xa2, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_NTcreate_AndX_Response, Command=lambda x: x==0xa2, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Trans_Request, Command=lambda x: x==0x25, Flags=lambda x: not x&0x80)

bind_bottom_up(SMB_Header, SMB_Write_AndX_Request, Command=lambda x: x==0x2f, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Write_AndX_Response, Command=lambda x: x==0x2f, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Read_AndX_Request, Command=lambda x: x==0x2e, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Read_AndX_Response, Command=lambda x: x==0x2e, Flags=lambda x: x&0x80)

#bind_bottom_up(SMB_Write_AndX_Request, SMB_Data)
bind_bottom_up(SMB_Read_AndX_Response, SMB_Data)

bind_bottom_up(SMB_Trans_Request, DCERPC_Header)
bind_bottom_up(DCERPC_Header, DCERPC_Request, PacketType=lambda x: x==0)
bind_bottom_up(DCERPC_Header, DCERPC_Bind, PacketType=lambda x: x==11)
bind_bottom_up(DCERPC_Header, DCERPC_Bind_Ack, PacketType=lambda x: x==12)
bind_bottom_up(DCERPC_Bind, DCERPC_CtxItem)
bind_bottom_up(DCERPC_CtxItem, DCERPC_CtxItem)

bind_bottom_up(SMB_Sessionsetup_AndX_Request, SMB_Treeconnect_AndX_Request, AndXCommand=lambda x: x==0x75)
bind_bottom_up(SMB_Sessionsetup_AndX_Request2, SMB_Treeconnect_AndX_Request, AndXCommand=lambda x: x==0x75)
bind_bottom_up(SMB_Negociate_Protocol_Request_Counts, SMB_Negociate_Protocol_Request_Tail)
bind_bottom_up(SMB_Negociate_Protocol_Request_Tail, SMB_Negociate_Protocol_Request_Tail)
bind_bottom_up(SMB_Header, SMB_Parameters)
bind_bottom_up(SMB_Parameters, SMB_Data)

bind_top_down(SMB_Header, SMB_Negociate_Protocol_Response, Command=0x72)
bind_top_down(SMB_Header, SMB_Sessionsetup_AndX_Response, Command=0x73)
bind_top_down(SMB_Header, SMB_Treeconnect_AndX_Response, Command=0x75)
bind_top_down(SMB_Header, SMB_Treedisconnect, Command=0x71)
bind_top_down(SMB_Header, SMB_NTcreate_AndX_Response, Command=0xa2)
bind_top_down(SMB_Header, SMB_Write_AndX_Response, Command=0x2f)
bind_top_down(SMB_Header, SMB_Read_AndX_Response, Command=0x2e)
bind_top_down(SMB_Header, SMB_Trans_Request, Command=0x25)
bind_top_down(SMB_Read_AndX_Response, SMB_Data)

bind_top_down(DCERPC_Header, DCERPC_Request, PacketType=0)
bind_top_down(DCERPC_Header, DCERPC_Bind, PacketType=11)
bind_top_down(DCERPC_Header, DCERPC_Bind_Ack, PacketType=12)


