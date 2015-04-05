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

from dionaea.smb.include.packet import Packet, bind_bottom_up, bind_top_down
from dionaea.smb.include.fieldtypes import ByteEnumField, ShortField
from dionaea.smb.include.fieldtypes import XByteEnumField, LEShortField
from dionaea.smb.include.fieldtypes import ConditionalField, PacketField
from dionaea.smb.include.fieldtypes import XByteField, LEIntField, ByteField
from dionaea.smb.include.fieldtypes import StrFixedLenField, XLEShortField
from dionaea.smb.include.fieldtypes import XLEIntField, FlagsField, StrField
from dionaea.smb.include.fieldtypes import FieldLenField, StrLenField, IntField
from dionaea.smb.include.fieldtypes import LELongField, PacketListField

# [MS-TDS].pdf v20100711

# TDS HeaderTypes
TDS_TYPES_SQL_BATCH			= 0x01 
TDS_TYPES_PRETDS7_LOGIN		= 0x02	# only used for Pre-TDS7 Login 
TDS_TYPES_RPC				= 0x03 
TDS_TYPES_TABULAR_RESULT	= 0x04 
TDS_TYPES_ATTENTION			= 0x06
TDS_TYPES_BULK_LOAD_DATA	= 0x07
TDS_TYPES_TRANS_MANAGER_REQ	= 0x0E
TDS_TYPES_TDS5_QUERY		= 0x0f
TDS_TYPES_TDS7_LOGIN		= 0x10	# used for TDS7 or later version login
TDS_TYPES_SSPI_MESG			= 0x11
TDS_TYPES_PRE_LOGIN			= 0x12

TDS_HeaderTypes = {
	TDS_TYPES_SQL_BATCH			:"TDS_TYPES_SQL_BATCH ",
	TDS_TYPES_PRETDS7_LOGIN		:"TDS_TYPES_PRETDS7_LOGIN",
	TDS_TYPES_RPC				:"TDS_TYPES_RPC ",
	TDS_TYPES_TABULAR_RESULT	:"TDS_TYPES_TABULAR_RESULT",
	TDS_TYPES_ATTENTION			:"TDS_TYPES_ATTENTION",
	TDS_TYPES_BULK_LOAD_DATA	:"TDS_TYPES_BULK_LOAD_DATA",
	TDS_TYPES_TRANS_MANAGER_REQ	:"TDS_TYPES_TRANS_MANAGER_REQ",
	TDS_TYPES_TDS7_LOGIN		:"TDS_TYPES_TDS7_LOGIN",
	TDS_TYPES_SSPI_MESG			:"TDS_TYPES_SSPI_MESG",
	TDS_TYPES_PRE_LOGIN			:"TDS_TYPES_PRE_LOGIN",
	TDS_TYPES_TDS5_QUERY		:"TDS_TYPES_TDS5_QUERY",
}

# TDS Status
TDS_STATUS_NORMAL			= 0x00
TDS_STATUS_EOM				= 0x01
TDS_STATUS_C2S				= 0x02
TDS_STATUS_RESET_CON		= 0x08
TDS_STATUS_RESET_CON_TRAN	= 0x10

TDS_Status = {
	TDS_STATUS_NORMAL         :"Normal Message",       
	TDS_STATUS_EOM            :"End Of Message",        
	TDS_STATUS_C2S            :"From Client to Server", 
	TDS_STATUS_RESET_CON      :"RESETCONNECTION",       
	TDS_STATUS_RESET_CON_TRAN :"RESETCONNECTIONSKIPTRAN"
}

# Token Types
TDS_TOKEN_LANGUAGE 		= 0x21
TDS_TOKEN_RETURNSTATUS 	= 0x79
TDS_TOKEN_COLMETADATA 	= 0x81
TDS_TOKEN_INFO 			= 0xAB
TDS_TOKEN_LOGINACK 		= 0xAD
TDS_TOKEN_ROW 			= 0xD1
TDS_TOKEN_ENVCHANGE 	= 0xE3
TDS_TOKEN_DONE 			= 0xFD
TDS_TOKEN_DONEPROC 		= 0xFE

TDS_TokenTypes = {
	TDS_TOKEN_LANGUAGE     :"TDS_TOKEN_LANGUAGE",
	TDS_TOKEN_RETURNSTATUS :"TDS_TOKEN_RETURNSTATUS",
	TDS_TOKEN_COLMETADATA  :"TDS_TOKEN_COLMETADATA",
	TDS_TOKEN_INFO         :"TDS_TOKEN_INFO",
	TDS_TOKEN_LOGINACK     :"TDS_TOKEN_LOGINACK",
	TDS_TOKEN_ROW          :"TDS_TOKEN_ROW",
	TDS_TOKEN_ENVCHANGE    :"TDS_TOKEN_ENVCHANGE",
	TDS_TOKEN_DONE         :"TDS_TOKEN_DONE",
	TDS_TOKEN_DONEPROC     :"TDS_TOKEN_DONEPROC",
}


# page 78
# TDS Token Status
TDS_TOKEN_STATUS_DONE_FINAL		= 0x000
TDS_TOKEN_STATUS_DONE_MORE		= 0x001
TDS_TOKEN_STATUS_DONE_ERROR		= 0x002
TDS_TOKEN_STATUS_DONE_INXACT	= 0x004
TDS_TOKEN_STATUS_DONE_COUNT		= 0x010
TDS_TOKEN_STATUS_DONE_ATTN		= 0x020
TDS_TOKEN_STATUS_DONE_SRVERROR	= 0x100


TDS_Token_Status = {
	TDS_TOKEN_STATUS_DONE_FINAL    :"FINAL",
	TDS_TOKEN_STATUS_DONE_MORE     :"MORE",
	TDS_TOKEN_STATUS_DONE_ERROR    :"ERROR",
	TDS_TOKEN_STATUS_DONE_INXACT   :"INXACT",
	TDS_TOKEN_STATUS_DONE_COUNT    :"COUNT",
	TDS_TOKEN_STATUS_DONE_ATTN     :"ATTN",
	TDS_TOKEN_STATUS_DONE_SRVERROR :"SRVERROR",
}


# TDS Option Flags1
TDS_OptionFlags1 = [
	"BYTEORDER",
	"CHAR",
	"FLOAT",		# "FLOAT" flag need 2 bits
	"FLOAT",
	"DUMPLOAD",
	"USEDB",
	"DATABASE",
	"SETLANG",
]

# TDS Option Flags2
TDS_OptionFlags2 = [
	"LANGUAGE",
	"ODBC",
	"TRANSBOUNDARY",	# removed in TDS 7.2
	"CACHECONNECT",		# removed in TDS 7.2
	"USERTYPE",			# "USERTYPE" flag need 3 bits
	"USERTYPE",	
	"USERTYPE"
	"INTSECURITY",
]

# TDS Option Flags3
TDS_OptionFlags3 = [
	"CHANGEPASSWORD",		# introduced in TDS 7.2
	"SENDYUKONBINARYXML",	# introduced in TDS 7.2
	"USERINSTANCE",			# introduced in TDS 7.2
	"UNKNOWNCOLLATION"		# introduced in TDS 7.2
	"none",
	"none",
	"none",
	"none",
]


# TDS TypesFlags
TDS_TypesFlags = [
	"SQLTYPE",		# "SQLTYPE" flag need 4 bits
	"SQLTYPE",
	"SQLTYPE",
	"SQLTYPE",
	"OLEDB",		# introduced in TDS 7.2
	"none",
	"none",
	"none",
	"none",
]

# TDS ColumnFlags
TDS_ColFlags = [
	"IGNORECASE",
	"IGNOREACCENT",
	"IGNOREWIDTH",
	"BINARY",
]

# TDS Column Metadata Flags
TDS_ColMetaData_Flags = [
	"Nullable",
	"CaseSen",
	"Updateable",		# this flag 2 bit
	"None",

	"Identity",
	"Computed",			# introduced in TDS 7.2 			
	"ReservedODBC",		# 2 bits,only exists in TDS 7.3A and below 
	"ReservedODBC",

	"SparseColumnSet",	# introduce in TDS 7.3.B
	"Reserved2",		# introduce in TDS 7.3.B
	"Reserved2",
	"FixedLenCLRType",	# introduce in TDS 7.2

	"none",
	"none",
	"none",
	"none",

	"Hidden",			# introduce in TDS 7.2
	"Key",				# introduce in TDS 7.2
	"NullableUnknown",	# introduce in TDS 7.2
]

class TDS_Value(Packet):
	name = "TDS Value"
		
	fields_desc = [
		ByteEnumField("TokenType",0,
			{0x00:"Version",
			0x01:"Encryption",
			0x02:"InstanceOpt",
			0x03:"ThreadID",
			0x04:"MARS",
			0xFF:"Terminator"}), 
		ShortField("Offset",0),
		ShortField("Len",0),
	]


class TDS_Token(Packet):
	name = "TDS Token"
#	tds_type = TDS_TYPES_TABULAR_RESULT
	fields_desc = [
		XByteEnumField("TokenType",0,TDS_TokenTypes),
	]

# Page 19-22
class TDS_Header(Packet):
	name="TDS Header"
	fields_desc = [
		XByteEnumField("Type",TDS_TYPES_PRE_LOGIN,TDS_HeaderTypes),
		ByteEnumField("Status",0, TDS_Status),
		ShortField("Length",0),
		LEShortField("SPID",0),
		ByteField("PacketID",0),
		ByteField("Window",0),
		ConditionalField(PacketListField("Tokens", None, TDS_Token), lambda x: x.Type == TDS_TYPES_TABULAR_RESULT),
	]

# Page 58-61
class TDS_Prelogin_Request(Packet):
	name="TDS Prelogin Request"
	tds_type = TDS_TYPES_PRE_LOGIN
	fields_desc =[
		PacketField("VersionToken",TDS_Value(),TDS_Value),
		PacketField("EncryptionToken",TDS_Value(),TDS_Value),
		PacketField("InstanceToken",TDS_Value(),TDS_Value),
		PacketField("ThreadIDToken",TDS_Value(),TDS_Value),
		
		# Multiple Active Result Sets (MARS) has introduced in MSSQL Server 2005
		# To determine the existence of MARS TokenType
		# 0x04 is MARSToken
		# 0xFF is Terminator
		XByteField("MARSTokenOrTerminator",0),
		ConditionalField(ShortField("MARSOffset",0), lambda x: x.MARSTokenOrTerminator == 0x04),
		ConditionalField(ShortField("MARSLen",0), lambda x: x.MARSTokenOrTerminator == 0x04),
		ConditionalField(XByteField("Terminator",0), lambda x: x.MARSTokenOrTerminator == 0x04),
		
		LEIntField("Version",0),
		LEShortField("SubBuild",0x0),
		ByteField("Encryption",0),
		StrFixedLenField("InstanceOpt", b'', length_from=lambda x:x.InstanceToken.Len),
		LEIntField("ThreadID",0),
		ConditionalField(ByteField("MARS",0), lambda x: x.MARSTokenOrTerminator == 0x04),
	]

# Page 58-61
class TDS_Prelogin_Response(Packet):
	name="TDS Prelogin Response"
	tds_type = TDS_TYPES_TABULAR_RESULT
	fields_desc =[
		PacketField("VersionToken",TDS_Value(),TDS_Value),
		PacketField("EncryptionToken",TDS_Value(),TDS_Value),
		PacketField("InstanceToken",TDS_Value(),TDS_Value),
		PacketField("ThreadIDToken",TDS_Value(),TDS_Value),
		PacketField("MARSToken",TDS_Value(),TDS_Value),
		XByteField("Terminator",0xFF),
		
		# From the observation, the value for Version field
		# MS SQLServer 2005:	1996816393
		# MS SQLServer 2000:	268566536
		LEIntField("Version",268566536), 
		LEShortField("SubBuild",0x0),
		
		# For Encryption field, value 0x02 mean ENCRPYT_NOT_SUP
		# value 0x02 is needed as we may skip the SSL authentication support
		ByteField("Encryption",0x02),
			
		ByteField("InstanceOpt",0),
		#LEIntField("ThreadID",0),
		ByteField("MARS",0),
	]

# TDS_TYPES_PRETDS7_LOGIN
class TDS_PreTDS7_Login_Request(Packet):
	name="TDS Login PreTDS7 Request"
	fields_desc =[
		StrFixedLenField("ClientHostName", "", 30),
		ByteField("ClientHostNameLen", 0),
		StrFixedLenField("Username", "", 30),
		ByteField("UsernameLen", 0),
		StrFixedLenField("Password", "", 30),
		ByteField("PasswordLen", 0),
		StrFixedLenField("Junk", "", 31),
		StrFixedLenField("Magic", "", 16),
		StrFixedLenField("AppName", "", 30),
		ByteField("AppNameLen", 0),
		StrFixedLenField("ServerName", "", 30),
		ByteField("ServerNameLen", 0),
		StrFixedLenField("Password2", "", 256),
		XLEShortField("Version", 0),
		XLEShortField("UnusedProtocolField", 0),
		StrFixedLenField("LoginLibrary", "", 11),
		XLEIntField("ProgramVersion", 0),
		StrFixedLenField("Magic2", "", 3),
		StrFixedLenField("Language", "", 31),
		StrFixedLenField("Magic3", "", 3),
		StrFixedLenField("Charset", "", 31),
		StrFixedLenField("BlockSize", "", 6),
	]

# Page 51-58
class TDS_Login7_Request(Packet):
	name="TDS Login7 Request"
	fields_desc =[
		LEIntField("Length",0),
		LEIntField("TDSVersion",0),
		LEIntField("PacketSize",0),
		LEIntField("ClientProgVer",0),
		LEIntField("ClientPID",0),
		LEIntField("PID",0),
		FlagsField("OptionFlags1", 0, -8, TDS_OptionFlags1),
		FlagsField("OptionFlags2", 0, -8, TDS_OptionFlags2),
		FlagsField("TypesFlags", 0, -8, TDS_TypesFlags),
		FlagsField("OptionFlags3", 0, -8, TDS_OptionFlags3),
		LEIntField("ClientTimeZone",0),
		
		# start of ClientLCID field
		LEShortField("LCID",0x0),
		FlagsField("ColFlags", 0, -8, TDS_ColFlags),
		ByteField("Version",0x0),
		# end of ClientLCID field
		
		# start of OffsetLength field
		LEShortField("ibHostName",0),
		LEShortField("cchHostName",0),
		LEShortField("ibUserName",0),
		LEShortField("cchUserName",0),
		LEShortField("ibPassword",0),
		LEShortField("cchPassword",0),
		LEShortField("ibAppName",0),
		LEShortField("cchAppName",0),
		LEShortField("ibServerName",0),
		LEShortField("cchServerName",0),
		LEShortField("ibUnused",0),
		LEShortField("cbUnused",0),
		LEShortField("ibCltIntName",0),
		LEShortField("cchCltIntName",0),
		LEShortField("ibLanguage",0),
		LEShortField("cchLanguage",0),
		LEShortField("ibDatabase",0),
		LEShortField("cchDatabase",0),
		StrFixedLenField("ClientID", "012345", 6),
		LEShortField("ibSSPI",0),
		LEShortField("cbSSPI",0),
		LEShortField("ibAtchDBFile",0),
		LEShortField("cchAtchDBFile",0),
		#LEShortField("ibChangePassword",0),	# introduce in TDS 7.2
		#LEShortField("ibChangePassword",0),	# introduce in TDS 7.2
		#LEIntField("cbSSPILong",0),		# introduce in TDS 7.2
		# end of OffsetLength field
		
		StrField("Payload",""),
	]

# Page 82
class TDS_Token_EnvChange(Packet):
	name="TDS Token ENVCHANGE"
#	tds_type = TDS_TYPES_TABULAR_RESULT
	fields_desc =[
#		ByteField("TokenType",0xE3),
		LEShortField("Length",27),	#FIXME: make a dynamic count?
		ByteField("Type",1),		# 1 = Database
		FieldLenField("NewValueLen", 6, fmt='B', length_of="NewValue"),
		StrLenField("NewValue", "master".encode('utf16')[2:], length_from=lambda x:x.NewValueLen),
		FieldLenField("OldValueLen", 6, fmt='B', length_of="OldValue"),
		StrLenField("OldValue", "master".encode('utf16')[2:], length_from=lambda x:x.OldValueLen),
	
	]

# Page 88
class TDS_Token_Info(Packet):
	name="TDS Token INFO"
	fields_desc =[
#		ByteField("TokenType",0xAB),
		LEShortField("Length",118),	#FIXME: make a dynamic count?
		LEIntField("Number",5701),
		ByteField("State",2),
		ByteField("Class",1),
		FieldLenField("MessageTextLen", 37, fmt='<H', length_of="MessageText"),
		StrLenField("MessageText", "Changed database context to 'master'.".encode('utf16')[2:], length_from=lambda x:x.MessageTextLen),
		FieldLenField("ServerNameLen", 15, fmt='B', length_of="ServerName"),
		StrLenField("ServerName", "HOMEUSER-3AF6FE".encode('utf16')[2:], length_from=lambda x:x.ServerNameLen),
		FieldLenField("ProcNameLen", 0, fmt='B', length_of="ProcName"),
		
		#StrLenField("ProName", "", length_from=lambda x:x.ProcName),
		#LEIntField("LineNumber",1),	
	
	]

# Page 89
class TDS_Token_LoginACK(Packet):
	name="TDS Token LOGINACK"
#	tds_type = TDS_TYPES_TABULAR_RESULT
	fields_desc =[
#		ByteField("TokenType",0xad),
		LEShortField("Length",54),	#FIXME: make a dynamic count?
		ByteField("Interface",1),
		#IntField("TDSVersion",0x730a0003),
		IntField("TDSVersion",0x04020000),
		FieldLenField("ProgNameLen", 22, fmt='B', length_of="ProgName"),
		StrLenField("ProgName", "Microsoft SQL Server\0\0".encode('utf16')[2:], length_from=lambda x:x.ProgNameLen),
		ByteField("MajorVer",9),
		ByteField("MinorVer",0),
		ByteField("BuildNumHi",5),
		ByteField("BuildNumLow",119),
	]

# Page 78
class TDS_Token_Done(Packet):
	name="TDS Token DONE"
	fields_desc =[
#		ByteField("TokenType",0xfd),
		FlagsField("Status", 0, -16, TDS_Token_Status),
		LEShortField("CurCmd",0),
		LEIntField("DoneRowCount",0),
	]

# Page 32/33
class TDS_Token_AllHeader(Packet):
	name="TDS Token ALLHEADER"
	fields_desc=[
		LEIntField("TotalLength",0),
		LEIntField("HeaderLength",0),
		
		# Two HeaderType
		# 1. Query Notification Header
		# 2. Transaction Descriptor Header, apply to [MSDN-MARS]
		LEShortField("HeaderType",0),
		
		# Only support for Transaction Descriptor Header for the moment
		LELongField("TransactionDescription",0),
		LEIntField("OutstandingRequestCount",0),
	]

# Page 65
class TDS_SQLBatchData(Packet):
	name="TDS SQL Batch Data"
	fields_desc=[
#		StrLenField("SQLBatchData","", length_from=lambda x: x.underlayer.Length-8),
		StrField("SQLBatchData",""),
	]


# Page 75/76
class TDS_Token_ColMetaData(Packet):
	name="TDS Token COLMETADATA"
#	tds_type = TDS_TYPES_TABULAR_RESULT
	fields_desc=[
#		ByteField("TokenType",0x81),
		LEShortField("Count", 1),
		
		# SQL Server 2005 is LEIntField
		# SQL Server 2000 is LEShortField
		LEShortField("UserType",0),
		
		FlagsField("Status", 0x1, -16, TDS_ColMetaData_Flags),
		
		# TypeInfo section
		# the value obtained with MS SQLServer 2005 client and server
		ByteField("Type",0x38),		# 0x38 = INT4TYPE
		ByteField("ColNameLength",0),	
	]

# Page 96/97
class TDS_Token_Row(Packet):
	name="TDS Token ROW"
	fields_desc=[
#		ByteField("TokenType",0xd1),
		
		# the value obtained with MS SQLServer 2005 client and server
		LEShortField("Data",0xFFFF),
	]

# Page 93/94
class TDS_Token_ReturnStatus(Packet):
	name="TDS Token RETURNSTATUS"
	fields_desc=[
#		ByteField("TokenType",0x79),
		LEIntField("Value",0),
	]

# Page 80/81
class TDS_Token_DoneProc(Packet):
	name="TDS Token DONEPROC"
	fields_desc =[
#		ByteField("TokenType",0xfe),
		FlagsField("Status", 0, -16, TDS_Token_Status),
		LEShortField("CurCmd",0xE0),
		LEIntField("DoneRowCount",0),
	]

class TDS_Token_Language(Packet):
	name = "TDS5 Token Language"
	fields_desc = [
#		XByteField("TokenType", 0x21),
		FieldLenField("Length", None, fmt="<I", length_of="Language"),
		ByteField("Status", 0),
		StrLenField("Language", "", length_from=lambda x:x.Length),
	]


# http://web.cecs.pdx.edu/~kirkenda/tdsserver.html
class TDS_TDS5_Query_Request(Packet):
	name = "TDS5 Query Request"
	fields_desc =[
		PacketListField("Queries", None, TDS_Token)
	]


bind_bottom_up(TDS_Header, TDS_Prelogin_Request, Type=lambda x: x==0x12)
bind_bottom_up(TDS_Header, TDS_Prelogin_Response, Type=lambda x: x==0x04)
bind_bottom_up(TDS_Header, TDS_Login7_Request, Type=lambda x:x ==0x10)
bind_bottom_up(TDS_Header, TDS_PreTDS7_Login_Request, Type=lambda x:x ==0x02)
#bind_bottom_up(TDS_Header, TDS_Token_AllHeader, Type=lambda x:x == 0x01)
bind_bottom_up(TDS_Header, TDS_SQLBatchData, Type=lambda x:x == 0x01)

bind_bottom_up(TDS_Token, TDS_Token_Language, TokenType=lambda x:x == TDS_TOKEN_LANGUAGE)
bind_bottom_up(TDS_Token, TDS_Token_ReturnStatus, TokenType=lambda x:x == TDS_TOKEN_RETUNSTATUS)


bind_top_down(TDS_Header, TDS_Prelogin_Request, Type=0x12)
bind_top_down(TDS_Header, TDS_Prelogin_Response, Type=0x04)
bind_top_down(TDS_Header, TDS_Token, Status=0x01)

bind_top_down(TDS_Token, TDS_Token_Done, TokenType=TDS_TOKEN_DONE)
bind_top_down(TDS_Token, TDS_Token_Row, TokenType=TDS_TOKEN_ROW)
bind_top_down(TDS_Token, TDS_Token_ReturnStatus, TokenType=TDS_TOKEN_RETURNSTATUS)
bind_top_down(TDS_Token, TDS_Token_DoneProc, TokenType=TDS_TOKEN_DONEPROC)
bind_top_down(TDS_Token, TDS_Token_LoginACK, TokenType=TDS_TOKEN_LOGINACK)
bind_top_down(TDS_Token, TDS_Token_ColMetaData, TokenType=TDS_TOKEN_COLMETADATA)
