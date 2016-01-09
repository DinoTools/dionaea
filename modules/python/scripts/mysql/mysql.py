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

import re

from dionaea.core import incident, connection, g_dionaea
from .include.packets import *
import logging
import sqlite3

logger = logging.getLogger('mysqld')
class mysqld(connection):
    def __init__ (self):
        connection.__init__(self,"tcp")

    def handle_established(self):
        self.config = g_dionaea.config()['modules']['python'][
            'mysql']['databases']

        self.state = 'greeting'
        a = MySQL_Packet_Header(Number=0) / MySQL_Server_Greeting()
        a.show()
        self.send(a.build())
        self._open_db('information_schema')

    def _open_db(self, Database):
        logger.warn("DATABASE opening %s" % Database)
        try:
            p = self.config[Database]['path']
            logger.warn("open db %s -> %s" % (Database, p))
            self.dbh = sqlite3.connect(p)
            self.cursor = self.dbh.cursor()
            self.database = Database
            return True
        except:
            return False

    def _handle_COM_INIT_DB(self, p):
        Database = p.Database.decode('utf-8')
        if self._open_db(Database) == True:
            return MySQL_Result_OK()
        else:
            return MySQL_Result_Error(Message="No such database")

    def _handle_COM_FIELD_LIST(self, p):
        r = []
        query = "PRAGMA table_info(%s);" % p.Table.decode('ascii')[:-1]
        # FIXME sqlite does not allow ? for PRAGMA? I'm not afraid of SQLi here
        # though.
        result = self.cursor.execute(query)
        names = [result.description[x][0]
                 for x in range(len(result.description))]
        result = [dict(zip(names, i)) for i in result]
        for res in result:
            x = MySQL_Result_Field(Catalog='def',
                                   Database=self.database,
                                   Table=p.Table[:-1],
                                   ORGTable=p.Table[:-1],
                                   Name=res['name'].encode('ascii'),
                                   ORGName=res['name'].encode('ascii'),
                                   CharSet=33,
                                   Length=20,
                                   Type=FIELD_TYPE_VAR_STRING,
                                   Flags=0, #0x4203,
                                   Decimals=0,
                                   Default='0')
            r.append(x)
        r.append(MySQL_Result_EOF(ServerStatus=0x002))
        return r

    def _handle_COM_QUERY(self, p):
        r = None
        if re.match(b'SET ', p.Query, re.I):
            r = MySQL_Result_OK(Message="#2")
        elif re.match(b'select @@version_comment limit 1$', p.Query, re.I) or re.match(b'select version\(\)$', p.Query, re.I):
            r = [MySQL_Result_Header(FieldCount=1),
                 MySQL_Result_Field(Catalog='def',
                                    Name='@@version_comment',
                                    CharSet=33,
                                    Length=75,
                                    Type=FIELD_TYPE_VAR_STRING,
                                    Flags=FLAG_NOT_NULL,
                                    Decimals=0),
                 MySQL_Result_EOF(ServerStatus=0x002),
                 MySQL_Result_Row_Data(
                     ColumnValues=['Gentoo Linux mysql-5.0.54\0']),
                 MySQL_Result_EOF(ServerStatus=0x002)]

        elif p.Query == re.match(b'SELECT DATABASE\(\)$', p.Query, re.I):
            r = [MySQL_Result_Header(FieldCount=1),
                 MySQL_Result_Field(Catalog='def',
                                    Name=b'DATABASE()',
                                    CharSet=33,
                                    Length=75,
                                    Type=FIELD_TYPE_VAR_STRING,
                                    Flags=FLAG_NOT_NULL,
                                    Decimals=0),
                 MySQL_Result_EOF(ServerStatus=0x002),
                 MySQL_Result_Row_Data(ColumnValues=[self.database]),
                 MySQL_Result_EOF(ServerStatus=0x002)]
        elif p.Query == re.match(b'show databases$', p.Query, re.I):
            r = [MySQL_Result_Header(FieldCount=1),
                 MySQL_Result_Field(Catalog='def',
                                    Table=b'SCHEMATA',
                                    Name=b'Database',
                                    CharSet=33,
                                    Length=192,
                                    Type=FIELD_TYPE_VAR_STRING,
                                    Flags=FLAG_NOT_NULL,
                                    Decimals=0),
                 MySQL_Result_EOF(ServerStatus=0x002)]

            for i in self.config.keys():
                r.append(MySQL_Result_Row_Data(ColumnValues=[i]))

#			r.append(MySQL_Result_Row_Data(ColumnValues=['information_schema']))
            r.append(MySQL_Result_EOF(ServerStatus=0x002))
        elif p.Query == re.match(b'show tables$', p.Query, re.I):
            r = [MySQL_Result_Header(FieldCount=1),
                 MySQL_Result_Field(Catalog='def',
                                    Table=b'TABLE_NAMES',
                                    Name=b'Tables_in_test',
                                    CharSet=33,
                                    Length=192,
                                    Type=FIELD_TYPE_VAR_STRING,
                                    Flags=FLAG_NOT_NULL,
                                    Decimals=0),
                 MySQL_Result_EOF(ServerStatus=0x002)]

            result = self.cursor.execute(
                "select tbl_name from sqlite_master where type = 'table'")
            names = [result.description[x][0]
                     for x in range(len(result.description))]
            result = [dict(zip(names, i)) for i in result]
            for res in result:
                x = MySQL_Result_Row_Data(
                    ColumnValues=[res[name] for name in names])
                r.append(x)
            r.append(MySQL_Result_EOF(ServerStatus=0x002))
        else:
            p.show()
            try:
                query = p.Query.decode('utf-8')
                print(query)
                result = self.cursor.execute(query)
                print(result)
                if result.description is None:
                    r = MySQL_Result_OK()
                else:
                    names = [result.description[x][0]
                             for x in range(len(result.description))]
                    print(result)
                    result = [dict(zip(names, i)) for i in result]
                    r = [MySQL_Result_Header(FieldCount=len(names))]
                    for name in names:
                        r.append(MySQL_Result_Field(#Catalog='def',
                            Table=b'',
                            ORGTable=b"",
                            Database=b"",
                            Name=name,
                            CharSet=33,
                            Length=255,
                            Type=FIELD_TYPE_VAR_STRING,
                            Flags=FLAG_NOT_NULL,
                            Decimals=0))
                    r.append(MySQL_Result_EOF(ServerStatus=0x002))
                    for res in result:
                        x = MySQL_Result_Row_Data(
                            ColumnValues=[res[name] for name in names])
#						x.show()
                        r.append(x),
                    r.append(MySQL_Result_EOF(ServerStatus=0x002))
            except Exception as e:
                logger.warn("SQL ERROR %s" % e)
                logger.warn("SQL ERROR in %s" % p.Query)
                r = MySQL_Result_Error(Message="Learn SQL!")
        return r

    def handle_io_in(self,data):
        offset = 0
        while len(data) - offset >= 4:
            h = MySQL_Packet_Header(data[offset:offset+4])
            r = p = None
            if len(data)-offset < h.Length+4:
                break

            if self.state == 'greeting':
                self.state = 'online'
                p = MySQL_Client_Authentication(
                    data[offset+4:offset+4+h.Length])
                if p.DatabaseName != b'\x00':
                    Database = p.DatabaseName[:-1]
                    if type(Database) == str:
                        Database = Database.encode('ascii')
                    if self._open_db(Database) == True:
                        r = MySQL_Result_Error(
                            Message="Could not open Database %s" % Database)
                    else:
                        r = MySQL_Result_OK()
                else:
                    r = MySQL_Result_OK()

                i = incident("dionaea.modules.python.mysql.login")
                i.con = self
                i.username = p.User
                i.password = ""
                i.report()

            elif self.state == 'online':
                p = MySQL_Command_Header(data[offset+4:offset+4+h.Length])
                cmd = MySQL_Commands[p.Command]
                m = getattr(self, "_handle_" + cmd, None)
                args = None
                if m is not None:
                    args = []
                    for f in p.payload.fields_desc:
                        if f.name in p.payload.fields:
                            args.append(p.payload.fields[f.name])
                    r = m(p.payload)

                i = incident("dionaea.modules.python.mysql.command")
                i.con = self
                i.command = p.Command
                if args is not None:
                    i.args = args
                i.dump()
                i.report()

            if p is not None:
                h = h / p
            h.show()

            if r is not None:
                if type(r) is not list:
                    r = [r]
                buf = b''
                for i in range(len(r)):
                    rp = r[i]
                    rp = MySQL_Packet_Header(Number=h.Number+1+i) / rp
                    rp.show()
                    buf += rp.build()
                self.send(buf)
            offset += 4 + h.Length
        return offset

