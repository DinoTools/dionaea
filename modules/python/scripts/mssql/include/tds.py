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

from dionaea.smb.include.packet import *
from dionaea.smb.include.fieldtypes import *

# [MS-TDS].pdf v20100711

TDS_TYPES_SQL_BATCH		= 0x01 
TDS_TYPES_PRETDS7_LOGIN		= 0x02	# only used for Pre-TDS7 Login 
TDS_TYPES_RPC			= 0x03 
TDS_TYPES_TABULAR_RESULT	= 0x04 
TDS_TYPES_ATTENTION		= 0x06
TDS_TYPES_BULK_LOAD_DATA	= 0x07
TDS_TYPES_TRANS_MANAGER_REQ	= 0x0E
TDS_TYPES_TDS7_LOGIN		= 0x10	# used for TDS7 or later version login
TDS_TYPES_SSPI_MESG		= 0x11
TDS_TYPE_PRE_LOGIN		= 0x12

TDS_HeaderTypes = {
	TDS_TYPES_SQL_BATCH		:"TDS_TYPES_SQL_BATCH ",
	TDS_TYPES_PRETDS7_LOGIN		:"TDS_TYPES_PRETDS7_LOGIN",
	TDS_TYPES_RPC			:"TDS_TYPES_RPC ",
	TDS_TYPES_TABULAR_RESULT	:"TDS_TYPES_TABULAR_RESULT",
	TDS_TYPES_ATTENTION		:"TDS_TYPES_ATTENTION",
	TDS_TYPES_BULK_LOAD_DATA	:"TDS_TYPES_BULK_LOAD_DATA",
	TDS_TYPES_TRANS_MANAGER_REQ	:"TDS_TYPES_TRANS_MANAGER_REQ",
	TDS_TYPES_TDS7_LOGIN		:"TDS_TYPES_TDS7_LOGIN",
	TDS_TYPES_SSPI_MESG		:"TDS_TYPES_SSPI_MESG",
	TDS_TYPE_PRE_LOGIN		:"TDS_TYPE_PRE_LOGIN",
}

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

TDS_OptionFlags2 = [
	"LANGUAGE",
	"ODBC",
	"TRANSBOUNDARY",	# removed in TDS 7.2
	"CACHECONNECT",		# removed in TDS 7.2
	"USERTYPE",		# "USERTYPE" flag need 3 bits
	"USERTYPE",	
	"USERTYPE"
	"INTSECURITY",
]

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

TDS_OptionFlags3 = [
	"CHANGEPASSWORD",	# introduced in TDS 7.2
	"SENDYUKONBINARYXML",	# introduced in TDS 7.2
	"USERINSTANCE",		# introduced in TDS 7.2
	"UNKNOWNCOLLATION"	# introduced in TDS 7.2
	"none",
	"none",
	"none",
	"none",
]

TDS_ColFlags = [
	"IGNORECASE",
	"IGNOREACCENT",
	"IGNOREWIDTH",
	"BINARY",
]

TDS_Status = [
	"DONE_MORE",
	"DONE_ERROR",
	"DONE_INXACT",
	"none",
	"DONE_COUNT",
	"DONE_ATTN",
	"none"
	"none",
	"DONE_SRVERROR",
		
]

TDS_ColMetaData_Flags = [
	"Nullable",
	"CaseSen",
	"Updateable",		# this flag 2 bit
	"None",
	
	"Identity",
	"Computed",		# introduced in TDS 7.2 			
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
	
	"Hidden",		# introduce in TDS 7.2
	"Key",			# introduce in TDS 7.2
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

# Page 19-22
class TDS_Header(Packet):
	name="TDS Header"
	fields_desc = [
		XByteEnumField("Type",TDS_TYPE_PRE_LOGIN,TDS_HeaderTypes),
		ByteEnumField("Status",0,
			{0x00:"Normal Message",
			0x01:"End Of Message",
			0x02:"From Client to Server",
			0x08:"RESETCONNECTION",
			0x10:"RESETCONNECTIONSKIPTRAN"}),
		ShortField("Length",0),
		LEShortField("SPID",0),
		ByteField("PacketID",0),
		ByteField("Window",0),
	]

# Page 58-61
class TDS_Prelogin_Request(Packet):
	name="TDS Prelogin Request"
	tds_type = TDS_TYPE_PRE_LOGIN
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
		ConditionalField(ByteField("Terminator",0), lambda x: x.MARSTokenOrTerminator == 0x04),
		
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
		ByteField("Terminator",0xFF),
		
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
		LEShortField("cchUerName",0),
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
		LEIntField("ClientID",0), 		# "ClientID" total 6 bytes
		LEShortField("ClientID2",0),		# FIXME: better way parse 6 bytes?
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

# PAge 82
class TDS_Token_EnvChange(Packet):
	name="TDS Token ENVCHANGE"
	tds_type = TDS_TYPES_TABULAR_RESULT
	fields_desc =[
		ByteField("TokenType",0xE3),
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
		ByteField("TokenType",0xAB),
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
	tds_type = TDS_TYPES_TABULAR_RESULT
	fields_desc =[
		ByteField("TokenType",0xad),
		LEShortField("Length",56),	#FIXME: make a dynamic count?
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
		ByteField("TokenType",0xfd),
		FlagsField("Status", 0, -16, TDS_Status),
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
		
		StrField("SQLBatchData",""),
	]

# Page 75/76
class TDS_Token_ColMetaData(Packet):
	name="TDS Token COLMETADATA"
	tds_type = TDS_TYPES_TABULAR_RESULT
	fields_desc=[
		ByteField("TokenType",0x81),
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
		ByteField("TokenType",0xd1),
		
		# the value obtained with MS SQLServer 2005 client and server
		LEShortField("Data",0xFFFF),
	]

# Page 93/94
class TDS_Token_ReturnStatus(Packet):
	name="TDS Token RETURNSTATUS"
	fields_desc=[
		ByteField("TokenType",0x79),
		LEIntField("Value",0),
	]

# Page 80/81
class TDS_Token_DoneProc(Packet):
	name="TDS Token DONEPROC"
	fields_desc =[
		ByteField("TokenType",0xfe),
		FlagsField("Status", 0, -16, TDS_Status),
		LEShortField("CurCmd",0xE0),
		LEIntField("DoneRowCount",0),
	]

bind_bottom_up(TDS_Header, TDS_Prelogin_Request, Type=lambda x: x==0x12)
bind_bottom_up(TDS_Header, TDS_Prelogin_Response, Type=lambda x: x==0x04)
bind_bottom_up(TDS_Header, TDS_Login7_Request, Type=lambda x:x ==0x10)
#bind_bottom_up(TDS_Header, TDS_Token_AllHeader, Type=lambda x:x == 0x01)
bind_bottom_up(TDS_Header, TDS_SQLBatchData, Type=lambda x:x == 0x01)

bind_top_down(TDS_Header, TDS_Prelogin_Request, Type=0x12)
bind_top_down(TDS_Header, TDS_Prelogin_Response, Type=0x04)
bind_top_down(TDS_Header, TDS_Token_LoginACK, Status=0x01)
bind_top_down(TDS_Header, TDS_Token_ColMetaData, Status=0x01)
