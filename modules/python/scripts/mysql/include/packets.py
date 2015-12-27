#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2011  Markus Koetter
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


from dionaea.smb.include.packet import Packet, bind_bottom_up
from dionaea.smb.include.fieldtypes import ByteField, StrNullField, IntField
from dionaea.smb.include.fieldtypes import StrFixedLenField, FlagsField
from dionaea.smb.include.fieldtypes import LEShortEnumField, LEIntField
from dionaea.smb.include.fieldtypes import XByteEnumField, StrField
from dionaea.smb.include.fieldtypes import LEShortField, FieldListField
from .fields import Int24Field, LengthCodedIntField, LengthCodedBinaryField

CLIENT_LONG_PASSWORD		= 0x00001	# new more secure passwords
CLIENT_FOUND_ROWS			= 0x00002	# Found instead of affected rows
CLIENT_LONG_FLAG			= 0x00004	# Get all column flags
CLIENT_CONNECT_WITH_DB		= 0x00008	# One can specify db on connect
CLIENT_NO_SCHEMA			= 0x00010	# Don't allow database.table.column
CLIENT_COMPRESS				= 0x00020	# Can use compression protocol
CLIENT_ODBC					= 0x00040	# Odbc client
CLIENT_LOCAL_FILES			= 0x00080	# Can use LOAD DATA LOCAL
CLIENT_IGNORE_SPACE			= 0x00100	# Ignore spaces before '('
CLIENT_PROTOCOL_41			= 0x00200	# New 4.1 protocol
CLIENT_INTERACTIVE			= 0x00400	# This is an interactive client
CLIENT_SSL					= 0x00800	# Switch to SSL after handshake
CLIENT_IGNORE_SIGPIPE		= 0x01000	# IGNORE sigpipes
CLIENT_TRANSACTIONS			= 0x02000	# Client knows about transactions
CLIENT_RESERVED				= 0x04000	# Old flag for 4.1 protocol
CLIENT_SECURE_CONNECTION	= 0x08000	# New 4.1 authentication

MySQL_Capabilities = {
    CLIENT_LONG_PASSWORD		: "CLIENT_LONG_PASSWORD",
    CLIENT_FOUND_ROWS			: "CLIENT_FOUND_ROWS",
    CLIENT_LONG_FLAG			: "CLIENT_LONG_FLAG",
    CLIENT_CONNECT_WITH_DB		: "CLIENT_CONNECT_WITH_DB",
    CLIENT_NO_SCHEMA			: "CLIENT_NO_SCHEMA",
    CLIENT_COMPRESS				: "CLIENT_COMPRESS",
    CLIENT_ODBC					: "CLIENT_ODBC",
    CLIENT_LOCAL_FILES			: "CLIENT_LOCAL_FILES",
    CLIENT_IGNORE_SPACE			: "CLIENT_IGNORE_SPACE",
    CLIENT_PROTOCOL_41			: "CLIENT_PROTOCOL_41",
    CLIENT_INTERACTIVE			: "CLIENT_INTERACTIVE",
    CLIENT_SSL					: "CLIENT_SSL",
    CLIENT_IGNORE_SIGPIPE		: "CLIENT_IGNORE_SIGPIPE",
    CLIENT_TRANSACTIONS			: "CLIENT_TRANSACTIONS",
    CLIENT_RESERVED				: "CLIENT_RESERVED",
    CLIENT_SECURE_CONNECTION	: "CLIENT_SECURE_CONNECTION",
}

CLIENT_MULTI_STATEMENTS		= 0x01	# Enable/disable multi-stmt support
CLIENT_MULTI_RESULTS		= 0x02	# Enable/disable multi-results

MySQL_Extended_Capabilities = {
    CLIENT_MULTI_STATEMENTS		: "CLIENT_MULTI_STATEMENTS",
    CLIENT_MULTI_RESULTS		: "CLIENT_MULTI_RESULTS"
}

COM_SLEEP				= 0x00	# (none, this is an internal thread state)
COM_QUIT				= 0x01	# mysql_close
COM_INIT_DB				= 0x02	# mysql_select_db
COM_QUERY				= 0x03	# mysql_real_query
COM_FIELD_LIST			= 0x04	# mysql_list_fields
COM_CREATE_DB			= 0x05	# mysql_create_db (deprecated)
COM_DROP_DB				= 0x06	# mysql_drop_db (deprecated)
COM_REFRESH				= 0x07	# mysql_refresh
COM_SHUTDOWN			= 0x08	# mysql_shutdown
COM_STATISTICS			= 0x09	# mysql_stat
COM_PROCESS_INFO		= 0x0a	# mysql_list_processes
COM_CONNECT				= 0x0b	# (none, this is an internal thread state)
COM_PROCESS_KILL		= 0x0c	# mysql_kill
COM_DEBUG				= 0x0d	# mysql_dump_debug_info
COM_PING				= 0x0e	# mysql_ping
COM_TIME				= 0x0f	# (none, this is an internal thread state)
COM_DELAYED_INSERT		= 0x10	# (none, this is an internal thread state)
COM_CHANGE_USER			= 0x11	# mysql_change_user
COM_BINLOG_DUMP			= 0x12	# sent by the slave IO thread to request a binlog
COM_TABLE_DUMP			= 0x13	# LOAD TABLE ... FROM MASTER (deprecated)
COM_CONNECT_OUT			= 0x14	# (none, this is an internal thread state)
# sent by the slave to register with the master (optional)
COM_REGISTER_SLAVE		= 0x15
COM_STMT_PREPARE		= 0x16	# mysql_stmt_prepare
COM_STMT_EXECUTE		= 0x17	# mysql_stmt_execute
COM_STMT_SEND_LONG_DATA	= 0x18	# mysql_stmt_send_long_data
COM_STMT_CLOSE			= 0x19	# mysql_stmt_close
COM_STMT_RESET			= 0x1a	# mysql_stmt_reset
COM_SET_OPTION			= 0x1b	# mysql_set_server_option
COM_STMT_FETCH			= 0x1c	# mysql_stmt_fetch

MySQL_Commands	=	{
    COM_SLEEP				: "COM_SLEEP",
    COM_QUIT				: "COM_QUIT",
    COM_INIT_DB				: "COM_INIT_DB",
    COM_QUERY				: "COM_QUERY",
    COM_FIELD_LIST			: "COM_FIELD_LIST",
    COM_CREATE_DB			: "COM_CREATE_DB",
    COM_DROP_DB				: "COM_DROP_DB",
    COM_REFRESH				: "COM_REFRESH",
    COM_SHUTDOWN			: "COM_SHUTDOWN",
    COM_STATISTICS			: "COM_STATISTICS",
    COM_PROCESS_INFO		: "COM_PROCESS_INFO",
    COM_CONNECT				: "COM_CONNECT",
    COM_PROCESS_KILL		: "COM_PROCESS_KILL",
    COM_DEBUG				: "COM_DEBUG",
    COM_PING				: "COM_PING",
    COM_TIME				: "COM_TIME",
    COM_DELAYED_INSERT		: "COM_DELAYED_INSERT",
    COM_CHANGE_USER			: "COM_CHANGE_USER",
    COM_BINLOG_DUMP			: "COM_BINLOG_DUMP",
    COM_TABLE_DUMP			: "COM_TABLE_DUMP",
    COM_CONNECT_OUT			: "COM_CONNECT_OUT",
    COM_REGISTER_SLAVE		: "COM_REGISTER_SLAVE",
    COM_STMT_PREPARE		: "COM_STMT_PREPARE",
    COM_STMT_EXECUTE		: "COM_STMT_EXECUTE",
    COM_STMT_SEND_LONG_DATA	: "COM_STMT_SEND_LONG_DATA",
    COM_STMT_CLOSE			: "COM_STMT_CLOSE",
    COM_STMT_RESET			: "COM_STMT_RESET",
    COM_SET_OPTION			: "COM_SET_OPTION",
    COM_STMT_FETCH			: "COM_STMT_FETCH"
}

# mysql-5.5.12/include/mysql_com.h
SERVER_STATUS_IN_TRANS				= 0x0001	#
SERVER_STATUS_AUTOCOMMIT			= 0x0002	# Server in auto_commit mode
SERVER_MORE_RESULTS_EXISTS			= 0x0008	# Multi query - next query exists
SERVER_QUERY_NO_GOOD_INDEX_USED		= 0x0010	#
SERVER_QUERY_NO_INDEX_USED			= 0x0020	#
SERVER_STATUS_CURSOR_EXISTS			= 0x0040	#
SERVER_STATUS_LAST_ROW_SENT			= 0x0080	#
SERVER_STATUS_DB_DROPPED			= 0x0100	# A database was dropped
SERVER_STATUS_NO_BACKSLASH_ESCAPES	= 0x0200	#
SERVER_STATUS_METADATA_CHANGED		= 0x0400	#
SERVER_QUERY_WAS_SLOW				= 0x0800	#
SERVER_PS_OUT_PARAMS				= 0x1000	#

MySQL_Server_Status = {
    SERVER_STATUS_IN_TRANS				: "SERVER_STATUS_IN_TRANS",
    SERVER_STATUS_AUTOCOMMIT			: "SERVER_STATUS_AUTOCOMMIT",
    SERVER_MORE_RESULTS_EXISTS			: "SERVER_MORE_RESULTS_EXISTS",
    SERVER_QUERY_NO_GOOD_INDEX_USED		: "SERVER_QUERY_NO_GOOD_INDEX_USED",
    SERVER_QUERY_NO_INDEX_USED			: "SERVER_QUERY_NO_INDEX_USED",
    SERVER_STATUS_CURSOR_EXISTS			: "SERVER_STATUS_CURSOR_EXISTS",
    SERVER_STATUS_LAST_ROW_SENT			: "SERVER_STATUS_LAST_ROW_SENT",
    SERVER_STATUS_DB_DROPPED			: "SERVER_STATUS_DB_DROPPED",
    SERVER_STATUS_NO_BACKSLASH_ESCAPES	: "SERVER_STATUS_NO_BACKSLASH_ESCAPES",
    SERVER_STATUS_METADATA_CHANGED		: "SERVER_STATUS_METADATA_CHANGED",
    SERVER_QUERY_WAS_SLOW				: "SERVER_QUERY_WAS_SLOW",
    SERVER_PS_OUT_PARAMS				: "SERVER_PS_OUT_PARAMS"
}


FIELD_TYPE_DECIMAL		= 0x00
FIELD_TYPE_TINY			= 0x01
FIELD_TYPE_SHORT		= 0x02
FIELD_TYPE_LONG			= 0x03
FIELD_TYPE_FLOAT		= 0x04
FIELD_TYPE_DOUBLE		= 0x05
FIELD_TYPE_NULL			= 0x06
FIELD_TYPE_TIMESTAMP	= 0x07
FIELD_TYPE_LONGLONG		= 0x08
FIELD_TYPE_INT24		= 0x09
FIELD_TYPE_DATE			= 0x0a
FIELD_TYPE_TIME			= 0x0b
FIELD_TYPE_DATETIME		= 0x0c
FIELD_TYPE_YEAR			= 0x0d
FIELD_TYPE_NEWDATE		= 0x0e
FIELD_TYPE_VARCHAR		= 0x0f # (new in MySQL 5.0)
FIELD_TYPE_BIT			= 0x10 # (new in MySQL 5.0)
FIELD_TYPE_NEWDECIMAL	= 0xf6 # (new in MYSQL 5.0)
FIELD_TYPE_ENUM			= 0xf7
FIELD_TYPE_SET			= 0xf8
FIELD_TYPE_TINY_BLOB	= 0xf9
FIELD_TYPE_MEDIUM_BLOB	= 0xfa
FIELD_TYPE_LONG_BLOB	= 0xfb
FIELD_TYPE_BLOB			= 0xfc
FIELD_TYPE_VAR_STRING	= 0xfd
FIELD_TYPE_STRING		= 0xfe
FIELD_TYPE_GEOMETRY		= 0xff

MySQL_Field_Types = {
    FIELD_TYPE_DECIMAL		:"FIELD_TYPE_DECIMAL",
    FIELD_TYPE_TINY			:"FIELD_TYPE_TINY",
    FIELD_TYPE_SHORT		:"FIELD_TYPE_SHORT",
    FIELD_TYPE_LONG			:"FIELD_TYPE_LONG",
    FIELD_TYPE_FLOAT		:"FIELD_TYPE_FLOAT",
    FIELD_TYPE_DOUBLE		:"FIELD_TYPE_DOUBLE",
    FIELD_TYPE_NULL			:"FIELD_TYPE_NULL",
    FIELD_TYPE_TIMESTAMP	:"FIELD_TYPE_TIMESTAMP",
    FIELD_TYPE_LONGLONG		:"FIELD_TYPE_LONGLONG",
    FIELD_TYPE_INT24		:"FIELD_TYPE_INT24",
    FIELD_TYPE_DATE			:"FIELD_TYPE_DATE",
    FIELD_TYPE_TIME			:"FIELD_TYPE_TIME",
    FIELD_TYPE_DATETIME		:"FIELD_TYPE_DATETIME",
    FIELD_TYPE_YEAR			:"FIELD_TYPE_YEAR",
    FIELD_TYPE_NEWDATE		:"FIELD_TYPE_NEWDATE",
    FIELD_TYPE_VARCHAR		:"FIELD_TYPE_VARCHAR",
    FIELD_TYPE_BIT			:"FIELD_TYPE_BIT",
    FIELD_TYPE_NEWDECIMAL	:"FIELD_TYPE_NEWDECIMAL",
    FIELD_TYPE_ENUM			:"FIELD_TYPE_ENUM",
    FIELD_TYPE_SET			:"FIELD_TYPE_SET",
    FIELD_TYPE_TINY_BLOB	:"FIELD_TYPE_TINY_BLOB",
    FIELD_TYPE_MEDIUM_BLOB	:"FIELD_TYPE_MEDIUM_BLOB",
    FIELD_TYPE_LONG_BLOB	:"FIELD_TYPE_LONG_BLOB",
    FIELD_TYPE_BLOB			:"FIELD_TYPE_BLOB",
    FIELD_TYPE_VAR_STRING	:"FIELD_TYPE_VAR_STRING",
    FIELD_TYPE_STRING		:"FIELD_TYPE_STRING",
    FIELD_TYPE_GEOMETRY		:"FIELD_TYPE_GEOMETRY",
}

FLAG_NOT_NULL   	= 0x0001
FLAG_PRI_KEY		= 0x0002
FLAG_UNIQUE_KEY		= 0x0004
FLAG_MULTIPLE_KEY	= 0x0008
FLAG_BLOB			= 0x0010
FLAG_UNSIGNED		= 0x0020
FLAG_ZEROFILL   	= 0x0040
FLAG_BINARY			= 0x0080
FLAG_ENUM			= 0x0100
FLAG_AUTO_INCREMENT = 0x0200
FLAG_TIMESTAMP  	= 0x0400
FLAG_SET			= 0x0800

MySQL_Field_Flags = {
    FLAG_NOT_NULL		:"FLAG_NOT_NULL",
    FLAG_PRI_KEY		:"FLAG_PRI_KEY",
    FLAG_UNIQUE_KEY		:"FLAG_UNIQUE_KEY",
    FLAG_MULTIPLE_KEY	:"FLAG_MULTIPLE_KEY",
    FLAG_BLOB			:"FLAG_BLOB",
    FLAG_UNSIGNED		:"FLAG_UNSIGNED",
    FLAG_ZEROFILL		:"FLAG_ZEROFILL",
    FLAG_BINARY			:"FLAG_BINARY",
    FLAG_ENUM			:"FLAG_ENUM",
    FLAG_AUTO_INCREMENT	:"FLAG_AUTO_INCREMENT",
    FLAG_TIMESTAMP		:"FLAG_TIMESTAMP",
    FLAG_SET			:"FLAG_SET",
}

class MySQL_Packet_Header(Packet):
    name="MySQL Packet Header"
    fields_desc = [
        Int24Field("Length",0),
        ByteField("Number",0)
    ]
    def post_build(self, p, pay):
        self.Length = len(pay)
        p = self.do_build()
        return p+pay

class MySQL_Server_Greeting(Packet):
    name="MySQL Server Greeting"
    fields_desc = [
        ByteField("ProtocolVersion",10),
        StrNullField("ServerVersion","5.0.54"),
        IntField("ThreadID",4711),
        StrFixedLenField("ScrambleBuffer","a"*8,8),
        ByteField("Filler0",0),
        FlagsField("ServerCapabilities",
                   CLIENT_LONG_FLAG|CLIENT_CONNECT_WITH_DB|CLIENT_COMPRESS|CLIENT_PROTOCOL_41|CLIENT_TRANSACTIONS|CLIENT_SECURE_CONNECTION,
                   -16, MySQL_Capabilities),
        ByteField("ServerLanguage",33),
        LEShortEnumField(
            "ServerStatus", SERVER_STATUS_AUTOCOMMIT, MySQL_Server_Status),
        StrFixedLenField("Unused",b"",13),
        StrNullField("Salt"," "*12)
    ]

class MySQL_Client_Authentication(Packet):
    name="MySQL Client Authentication"
    fields_desc = [
        FlagsField("ClientCapabilities", 0, -16, MySQL_Capabilities),
        FlagsField(
            "ClientExCapabilities", 0, -16, MySQL_Extended_Capabilities),
        LEIntField("MaxPacketSize",0),
        ByteField("CharSetNumber",0),
        StrFixedLenField("Filler",b"",23),
        StrNullField("User","bob"),
        LengthCodedBinaryField("ScrambleBuffer",b""),
        StrNullField("DatabaseName",b"")
    ]

class MySQL_Command_Header(Packet):
    name="MySQL Command Header"
    fields_desc = [
        XByteEnumField("Command",0,MySQL_Commands),
    ]

class MySQL_COM_QUERY(Packet):
    name="MySQL Command QUERY"
    fields_desc = [
        StrNullField("Query",b"")
    ]

class MySQL_COM_INIT_DB(Packet):
    name="MySQL Command INIT DB"
    fields_desc = [
        StrField("Database",b"")
    ]

class MySQL_COM_FIELD_LIST(Packet):
    name="MySQL Command FIELD LIST"
    fields_desc = [
        StrNullField("Table",b""),
        StrField("Column",b"")
    ]

bind_bottom_up(
    MySQL_Command_Header, MySQL_COM_QUERY, Command=lambda x: x==COM_QUERY)
bind_bottom_up(
    MySQL_Command_Header, MySQL_COM_INIT_DB, Command=lambda x: x==COM_INIT_DB)
bind_bottom_up(MySQL_Command_Header, MySQL_COM_FIELD_LIST,
               Command=lambda x: x==COM_FIELD_LIST)

class MySQL_Result_OK(Packet):
    name="MySQL Result OK"
    fields_desc = [
        ByteField("ResultMarker", 0x00),
        LengthCodedIntField("AffectedRows",0),
        LengthCodedIntField("InsertID",0),
        LEShortEnumField(
            "ServerStatus", SERVER_STATUS_AUTOCOMMIT, MySQL_Server_Status),
        LEShortField("WarningCount",0),
        StrField("Message",b'')
    ]

class MySQL_Result_Error(Packet):
    name="MySQL Result Error"
    fields_desc = [
        ByteField("ResultMarker", 0xff),
        LEShortField("Errno",0),
        StrFixedLenField("SQLStateMarker",b'#',1),
        StrFixedLenField("SQLState",b' '*5,5),
        StrField("Message",b'')
    ]

class MySQL_Result_Header(Packet):
    name="MySQL Result Header"
    fields_desc = [
        LengthCodedIntField("FieldCount",0),
        #		LengthCodedIntField("Extra",0)
    ]

class MySQL_Result_Field(Packet):
    name="MySQL Result Field"
    fields_desc = [
        LengthCodedBinaryField("Catalog",None),
        LengthCodedBinaryField("Database",None),
        LengthCodedBinaryField("Table",None),
        LengthCodedBinaryField("ORGTable",None),
        LengthCodedBinaryField("Name",None),
        LengthCodedBinaryField("ORGName",None),
        ByteField("Filler", 0xc),
        LEShortField("CharSet", 0),
        LEIntField("Length", 0),
        XByteEnumField("Type",0,MySQL_Field_Types),
        FlagsField("Flags", 0, -16, MySQL_Field_Flags),
        ByteField("Decimals", 0),
        LEShortField("Filler2",0),
        LengthCodedBinaryField("Default",None),
    ]

class MySQL_Result_EOF(Packet):
    name="MySQL Result EOF"
    fields_desc = [
        ByteField("ResultMarker", 0xfe),
        LEShortField("WarningCount",0),
        LEShortEnumField(
            "ServerStatus", SERVER_STATUS_AUTOCOMMIT, MySQL_Server_Status),
    ]

class MySQL_Result_Row_Data(Packet):
    name="MySQL Result Row Data"
    fields_desc = [
        FieldListField(
            "ColumnValues",None,LengthCodedBinaryField("ColumnValue",b'')),
    ]

# >>> from dionaea.mysql.include.packets import *
# >>> a = MySQL_Client_Authentication()
# >>> b = MySQL_Server_Greeting()
# >>> b.show()
# >>> d = MySQL_Server_Greeting(bytes.fromhex('0a352e302e3534005e0000003e7e24347574682c002ca2210200000000000000000000000000003e36313249575a3e6668575800'))
# >>> d.show()
# >>> from dionaea.mysql.include.packets import *
# >>> a = MySQL_Handshake_Packet_Header() / MySQL_Server_Greeting(bytes.fromhex('0a352e302e3534005e0000003e7e24347574682c002ca2210200000000000000000000000000003e36313249575a3e6668575800'))
# >>> a.show()
# >>> from dionaea.mysql.include.packets import *
# >>> a = MySQL_Client_Authentication(bytes.fromhex('85a603000000000121000000000000000000000000000000000000000000000074666f65727374650014eefd6d5562851bc5966a0b41236ae3f2315efcc4'))
# >>> a.show()

# >>> from dionaea.mysql.include.packets import *
# >>> a = MySQL_Client_Authentication()
# >>> a.ScrambleBuffer.Data = '\0' * 300
# >>> a.show()
# >>> MySQL_Client_Authentication(a.build()).show()

# >>> from dionaea.mysql.include.packets import *
# >>> a = MySQL_Client_Authentication()
# >>> a.ScrambleBuffer = b'\0' * 300
# >>> a.show()
# >>> MySQL_Client_Authentication(a.build()).show()

# >>> from dionaea.mysql.include.packets import *
# >>> a = MySQL_Client_Authentication(bytes.fromhex('85a603000000000121000000000000000000000000000000000000000000000074666f65727374650014eefd6d5562851bc5966a0b41236ae3f2315efcc4'))
# >>> a.show()
# >>> MySQL_Client_Authentication(a.build()).show()


# >>> from dionaea.mysql.include.packets import *
# >>> a = MySQL_Command_Packet_Header(bytes.fromhex('0700000200000002000000'))
# >>> a.show()
