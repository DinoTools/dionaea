# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import IHandlerLoader
from dionaea.core import ihandler

import logging
import json
import sqlite3
import time

logger = logging.getLogger('log_sqlite')
logger.setLevel(logging.DEBUG)


class LogSQLHandlerLoader(IHandlerLoader):
    name = "log_sqlite"

    @classmethod
    def start(cls, config=None):
        return logsqlhandler("*", config=config)


class logsqlhandler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
        self.path = path
        self.filename = config.get("file")

    def start(self):
        ihandler.__init__(self, self.path)
        # mapping socket -> attackid
        self.attacks = {}

        self.pending = {}

#       self.dbh = sqlite3.connect(user = g_dionaea.config()['modules']['python']['logsql']['file'])
        self.dbh = sqlite3.connect(self.filename)
        self.cursor = self.dbh.cursor()
        update = False

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            connections (
                connection INTEGER PRIMARY KEY,
                connection_type TEXT,
                connection_transport TEXT,
                connection_protocol TEXT,
                connection_timestamp INTEGER,
                connection_root INTEGER,
                connection_parent INTEGER,
                local_host TEXT,
                local_port INTEGER,
                remote_host TEXT,
                remote_hostname TEXT,
                remote_port INTEGER
            )""")

        self.cursor.execute("""CREATE TRIGGER IF NOT EXISTS connections_INSERT_update_connection_root_trg
            AFTER INSERT ON connections
            FOR EACH ROW
            WHEN
                new.connection_root IS NULL
            BEGIN
                UPDATE connections SET connection_root = connection WHERE connection = new.connection AND new.connection_root IS NULL;
            END""")

        for idx in ["type","timestamp","root","parent"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS connections_%s_idx
            ON connections (connection_%s)""" % (idx, idx))

        for idx in ["local_host","local_port","remote_host"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS connections_%s_idx
            ON connections (%s)""" % (idx, idx))


#         self.cursor.execute("""CREATE TABLE IF NOT EXISTS
#            bistreams (
#                bistream INTEGER PRIMARY KEY,
#                connection INTEGER,
#                bistream_data TEXT
#            )""")
#
#        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
#            smbs (
#                smb INTEGER PRIMARY KEY,
#                connection INTEGER,
#                smb_direction TEXT,
#                smb_action TEXT,
#                CONSTRAINT smb_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
#            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            dcerpcbinds (
                dcerpcbind INTEGER PRIMARY KEY,
                connection INTEGER,
                dcerpcbind_uuid TEXT,
                dcerpcbind_transfersyntax TEXT
                -- CONSTRAINT dcerpcs_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["uuid","transfersyntax"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS dcerpcbinds_%s_idx
            ON dcerpcbinds (dcerpcbind_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            dcerpcrequests (
                dcerpcrequest INTEGER PRIMARY KEY,
                connection INTEGER,
                dcerpcrequest_uuid TEXT,
                dcerpcrequest_opnum INTEGER
                -- CONSTRAINT dcerpcs_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["uuid","opnum"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS dcerpcrequests_%s_idx
            ON dcerpcrequests (dcerpcrequest_%s)""" % (idx, idx))


        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            dcerpcservices (
                dcerpcservice INTEGER PRIMARY KEY,
                dcerpcservice_uuid TEXT,
                dcerpcservice_name TEXT,
                CONSTRAINT dcerpcservice_uuid_uniq UNIQUE (dcerpcservice_uuid)
            )""")

        from uuid import UUID
        from dionaea.smb import rpcservices
        import inspect
        services = inspect.getmembers(rpcservices, inspect.isclass)
        for name, servicecls in services:
            if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
                try:
                    self.cursor.execute("INSERT INTO dcerpcservices (dcerpcservice_name, dcerpcservice_uuid) VALUES (?,?)",
                                        (name, str(UUID(hex=servicecls.uuid))) )
                except Exception as e:
                    #                    print("dcerpcservice %s existed %s " % (servicecls.uuid, e) )
                    pass


        logger.info("Getting RPC Services")
        r = self.cursor.execute("SELECT * FROM dcerpcservices")
#        print(r)
        names = [r.description[x][0] for x in range(len(r.description))]
        r = [ dict(zip(names, i)) for i in r]
#        print(r)
        r = dict([(UUID(i['dcerpcservice_uuid']).hex,i['dcerpcservice'])
                  for i in r])
#        print(r)


        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            dcerpcserviceops (
                dcerpcserviceop INTEGER PRIMARY KEY,
                dcerpcservice INTEGER,
                dcerpcserviceop_opnum INTEGER,
                dcerpcserviceop_name TEXT,
                dcerpcserviceop_vuln TEXT,
                CONSTRAINT dcerpcop_service_opnum_uniq UNIQUE (dcerpcservice, dcerpcserviceop_opnum)
            )""")

        logger.info("Setting RPC ServiceOps")
        for name, servicecls in services:
            if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
                for opnum in servicecls.ops:
                    op = servicecls.ops[opnum]
                    uuid = servicecls.uuid
                    vuln = ''
                    dcerpcservice = r[uuid]
                    if opnum in servicecls.vulns:
                        vuln = servicecls.vulns[opnum]
                    try:
                        self.cursor.execute("INSERT INTO dcerpcserviceops (dcerpcservice, dcerpcserviceop_opnum, dcerpcserviceop_name, dcerpcserviceop_vuln) VALUES (?,?,?,?)",
                                            (dcerpcservice, opnum, op, vuln))
                    except:
                        #                        print("%s %s %s %s %s existed" % (dcerpcservice, uuid, name, op, vuln))
                        pass

        # NetPathCompare was called NetCompare in dcerpcserviceops
        try:
            logger.debug("Trying to update table: dcerpcserviceops")
            x = self.cursor.execute(
                """SELECT * FROM dcerpcserviceops WHERE dcerpcserviceop_name = 'NetCompare'""").fetchall()
            if len(x) > 0:
                self.cursor.execute(
                    """UPDATE dcerpcserviceops SET dcerpcserviceop_name = 'NetPathCompare' WHERE dcerpcserviceop_name = 'NetCompare'""")
                logger.debug("... done")
            else:
                logger.debug("... not required")
        except Exception as e:
            print(e)
            logger.debug("... not required")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            emu_profiles (
                emu_profile INTEGER PRIMARY KEY,
                connection INTEGER,
                emu_profile_json TEXT
                -- CONSTRAINT emu_profiles_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")


        # fix a typo on emu_services table definition
        # emu_services.emu_serive is wrong, should be emu_services.emu_service
        # 1) rename table, create the proper table
        try:
            logger.debug("Trying to update table: emu_services")
            self.cursor.execute("""SELECT emu_serivce FROM emu_services LIMIT 1""")
            self.cursor.execute("""ALTER TABLE emu_services RENAME TO emu_services_old""")
            update = True
        except Exception as e:
            logger.debug("... not required")
            update = False

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            emu_services (
                emu_serivce INTEGER PRIMARY KEY,
                connection INTEGER,
                emu_service_url TEXT
                -- CONSTRAINT emu_services_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        # 2) copy all values to proper table, drop old table
        try:
            if update == True:
                self.cursor.execute("""
                    INSERT INTO
                        emu_services (emu_service, connection, emu_service_url)
                    SELECT
                        emu_serivce, connection, emu_service_url
                    FROM emu_services_old""")
                self.cursor.execute("""DROP TABLE emu_services_old""")
                logger.debug("... done")
        except Exception as e:
            logger.debug(
                "Updating emu_services failed, copying old table failed (%s)" % e)

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            offers (
                offer INTEGER PRIMARY KEY,
                connection INTEGER,
                offer_url TEXT
                -- CONSTRAINT offers_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        self.cursor.execute(
            """CREATE INDEX IF NOT EXISTS offers_url_idx ON offers (offer_url)""")

        # fix a typo on downloads table definition
        # downloads.downloads is wrong, should be downloads.download
        # 1) rename table, create the proper table
        try:
            logger.debug("Trying to update table (fix typo): downloads")
            self.cursor.execute("""SELECT downloads FROM downloads LIMIT 1""")
            self.cursor.execute("""ALTER TABLE downloads RENAME TO downloads_old""")
            update = True
        except Exception as e:
            #print(e)
            logger.debug("... not required")
            update = False
        
        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            downloads (
                download_timestamp INTEGER NOT NULL,
                download INTEGER PRIMARY KEY,
                connection INTEGER,
                download_url TEXT,
                download_md5_hash TEXT
                -- CONSTRAINT downloads_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")
        
	# 2) copy all values to proper table, drop old table
        try:
            if update == True:
                self.cursor.execute("""
                    INSERT INTO
                        downloads (download, connection, download_url, download_md5_hash)
                    SELECT
                        downloads, connection, download_url, download_md5_hash
                    FROM downloads_old""")
                self.cursor.execute("""DROP TABLE downloads_old""")
                logger.debug("... done")
        except Exeption as e:
            logger.debug(
                "Updating downloads failed, copying old table failed (%s)" % e)

        for idx in ["url", "md5_hash"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS downloads_%s_idx
            ON downloads (download_%s)""" % (idx, idx))

        # 3) add new column 'download_timestamp'
        try:
            logger.debug("Trying to update table (add column): downloads")
            self.cursor.execute("""SELECT download_timestamp FROM downloads LIMIT 1""")
            logger.debug("... not required")
        except Exception as e:
            self.cursor.execute("""ALTER TABLE downloads ADD COLUMN download_timestamp INTEGER""")
            logger.debug("... done")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            resolves (
                resolve INTEGER PRIMARY KEY,
                connection INTEGER,
                resolve_hostname TEXT,
                resolve_type TEXT,
                resolve_result TEXT
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            p0fs (
                p0f INTEGER PRIMARY KEY,
                connection INTEGER,
                p0f_genre TEXT,
                p0f_link TEXT,
                p0f_detail TEXT,
                p0f_uptime INTEGER,
                p0f_tos TEXT,
                p0f_dist INTEGER,
                p0f_nat INTEGER,
                p0f_fw INTEGER
                -- CONSTRAINT p0fs_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["genre","detail","uptime"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS p0fs_%s_idx
            ON p0fs (p0f_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            logins (
                login INTEGER PRIMARY KEY,
                connection INTEGER,
                login_username TEXT,
                login_password TEXT
                -- CONSTRAINT logins_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["username","password"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS logins_%s_idx
            ON logins (login_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mssql_fingerprints (
                mssql_fingerprint INTEGER PRIMARY KEY,
                connection INTEGER,
                mssql_fingerprint_hostname TEXT,
                mssql_fingerprint_appname TEXT,
                mssql_fingerprint_cltintname TEXT
                -- CONSTRAINT mssql_fingerprints_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["hostname","appname","cltintname"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS mssql_fingerprints_%s_idx
            ON mssql_fingerprints (mssql_fingerprint_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mssql_commands (
                mssql_command INTEGER PRIMARY KEY,
                connection INTEGER,
                mssql_command_status TEXT,
                mssql_command_cmd TEXT
                -- CONSTRAINT mssql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["status"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS mssql_commands_%s_idx
            ON mssql_commands (mssql_command_%s)""" % (idx, idx))
        
        self.cursor.execute("""CREATE TABLE IF NOT EXISTS virustotals (
                virustotal INTEGER PRIMARY KEY,
                virustotal_md5_hash TEXT NOT NULL,
                virustotal_sha1_hash TEXT NOT NULL,
                virustotal_sha256_hash TEXT NOT NULL,
                virustotal_positives INTEGER NOT NULL,
                virustotal_total INTEGER NOT NULL,
                virustotal_timestamp INTEGER NOT NULL,
                virustotal_permalink TEXT NOT NULL
            )""")

	# add new columns about sha1, sha256 and positives/total 
        try:
            logger.debug("Trying to update table: virustotals")
            self.cursor.execute("""
               SELECT virustotal_sha1_hash,virustotal_sha256_hash,virustotal_positives,virustotal_total FROM virustotals LIMIT 1
            """)
            logger.debug("... not required")
        except Exception as e:
            self.cursor.execute("""ALTER TABLE virustotals ADD COLUMN virustotal_sha1_hash TEXT""")
            self.cursor.execute("""ALTER TABLE virustotals ADD COLUMN virustotal_sha256_hash TEXT""")
            self.cursor.execute("""ALTER TABLE virustotals ADD COLUMN virustotal_positives INTEGER""")
            self.cursor.execute("""ALTER TABLE virustotals ADD COLUMN virustotal_total INTEGER""")
            logger.debug("... done")

        for idx in ["md5_hash"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS virustotals_%s_idx
            ON virustotals (virustotal_%s)""" % (idx, idx))
        
        for idx in ["sha1_hash"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS virustotals_%s_idx
            ON virustotals (virustotal_%s)""" % (idx, idx))
        
        for idx in ["sha256_hash"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS virustotals_%s_idx
            ON virustotals (virustotal_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS virustotalscans (
            virustotalscan INTEGER PRIMARY KEY,
            virustotal INTEGER NOT NULL,
            virustotalscan_scanner TEXT NOT NULL,
            virustotalscan_result TEXT
        )""")

        for idx in ["scanner","result"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS virustotalscans_%s_idx
            ON virustotalscans (virustotalscan_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE INDEX IF NOT EXISTS virustotalscans_virustotal_idx
            ON virustotalscans (virustotal)""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mysql_commands (
                mysql_command INTEGER PRIMARY KEY,
                connection INTEGER,
                mysql_command_cmd NUMBER NOT NULL
                -- CONSTRAINT mysql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mysql_command_args (
                mysql_command_arg INTEGER PRIMARY KEY,
                mysql_command INTEGER,
                mysql_command_arg_index NUMBER NOT NULL,
                mysql_command_arg_data TEXT NOT NULL
                -- CONSTRAINT mysql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["command"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS mysql_command_args_%s_idx
            ON mysql_command_args (mysql_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mysql_command_ops (
                mysql_command_op INTEGER PRIMARY KEY,
                mysql_command_cmd INTEGER NOT NULL,
                mysql_command_op_name TEXT NOT NULL,
                CONSTRAINT mysql_command_cmd_uniq UNIQUE (mysql_command_cmd)
            )""")

        from dionaea.mysql.include.packets import MySQL_Commands
        logger.info("Setting MySQL Command Ops")
        for num,name in MySQL_Commands.items():
            try:
                self.cursor.execute("INSERT INTO mysql_command_ops (mysql_command_cmd, mysql_command_op_name) VALUES (?,?)",
                                    (num, name))
            except:
                pass

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_commands (
                sip_command INTEGER PRIMARY KEY,
                connection INTEGER,
                sip_command_method ,
                sip_command_call_id ,
                sip_command_user_agent ,
                sip_command_allow INTEGER
            -- CONSTRAINT sip_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
        )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_addrs (
                sip_addr INTEGER PRIMARY KEY,
                sip_command INTEGER,
                sip_addr_type ,
                sip_addr_display_name,
                sip_addr_uri_scheme,
                sip_addr_uri_user,
                sip_addr_uri_password,
                sip_addr_uri_host,
                sip_addr_uri_port
                -- CONSTRAINT sip_addrs_command_fkey FOREIGN KEY (sip_command) REFERENCES sip_commands (sip_command)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_vias (
                sip_via INTEGER PRIMARY KEY,
                sip_command INTEGER,
                sip_via_protocol,
                sip_via_address,
                sip_via_port
                -- CONSTRAINT sip_vias_command_fkey FOREIGN KEY (sip_command) REFERENCES sip_commands (sip_command)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_sdp_origins (
                sip_sdp_origin INTEGER PRIMARY KEY,
                sip_command INTEGER,
                sip_sdp_origin_username,
                sip_sdp_origin_sess_id,
                sip_sdp_origin_sess_version,
                sip_sdp_origin_nettype,
                sip_sdp_origin_addrtype,
                sip_sdp_origin_unicast_address
                -- CONSTRAINT sip_sdp_origins_fkey FOREIGN KEY (sip_command) REFERENCES sip_commands (sip_command)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_sdp_connectiondatas (
                sip_sdp_connectiondata INTEGER PRIMARY KEY,
                sip_command INTEGER,
                sip_sdp_connectiondata_nettype,
                sip_sdp_connectiondata_addrtype,
                sip_sdp_connectiondata_connection_address,
                sip_sdp_connectiondata_ttl,
                sip_sdp_connectiondata_number_of_addresses
                -- CONSTRAINT sip_sdp_connectiondatas_fkey FOREIGN KEY (sip_command) REFERENCES sip_commands (sip_command)
            )""")

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            sip_sdp_medias (
                sip_sdp_media INTEGER PRIMARY KEY,
                sip_command INTEGER,
                sip_sdp_media_media,
                sip_sdp_media_port,
                sip_sdp_media_number_of_ports,
                sip_sdp_media_proto
--                sip_sdp_media_fmt,
--                sip_sdp_media_attributes
                -- CONSTRAINT sip_sdp_medias_fkey FOREIGN KEY (sip_command) REFERENCES sip_commands (sip_command)
            )""")

#        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
#            httpheaders (
#                httpheader INTEGER PRIMARY KEY,
#                connection INTEGER,
#                http_headerkey TEXT,
#                http_headervalue TEXT,
#                -- CONSTRAINT httpheaders_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
#            )""")
#
#        for idx in ["headerkey","headervalue"]:
#            self.cursor.execute("""CREATE INDEX IF NOT EXISTS httpheaders_%s_idx
#            ON httpheaders (httpheader_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mqtt_fingerprints (
                mqtt_fingerprint INTEGER PRIMARY KEY,
                connection INTEGER,
                mqtt_fingerprint_clientid TEXT,
                mqtt_fingerprint_willtopic TEXT,
                mqtt_fingerprint_willmessage TEXT,
                mqtt_fingerprint_username TEXT,
                mqtt_fingerprint_password TEXT
                -- CONSTRAINT mqtt_fingerprints_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["clientid","willtopic","willmessage", "username", "password"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS mqtt_fingerprints_%s_idx
            ON mqtt_fingerprints (mqtt_fingerprint_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mqtt_publish_commands (
                mqtt_publish_command INTEGER PRIMARY KEY,
                connection INTEGER,
                mqtt_publish_command_topic TEXT,
                mqtt_publish_command_message TEXT
                -- CONSTRAINT mqtt_publish_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["topic", "message"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS mqtt_publish_commands_%s_idx
            ON mqtt_publish_commands (mqtt_publish_command_%s)""" % (idx, idx))

        self.cursor.execute("""CREATE TABLE IF NOT EXISTS
            mqtt_subscribe_commands (
                mqtt_subscribe_command INTEGER PRIMARY KEY,
                connection INTEGER,
                mqtt_subscribe_command_messageid TEXT,
                mqtt_subscribe_command_topic TEXT
                -- CONSTRAINT mqtt_subscribe_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
            )""")

        for idx in ["messageid", "topic"]:
            self.cursor.execute("""CREATE INDEX IF NOT EXISTS mqtt_subscribe_commands_%s_idx
            ON mqtt_subscribe_commands (mqtt_subscribe_command_%s)""" % (idx, idx))

        # connection index for all
        for idx in ["dcerpcbinds", "dcerpcrequests", "emu_profiles", "emu_services", "offers", "downloads", "p0fs", "logins", "mssql_fingerprints", "mssql_commands","mysql_commands","sip_commands", "mqtt_fingerprints", "mqtt_publish_commands", "mqtt_subscribe_commands"]:
            self.cursor.execute(
                """CREATE INDEX IF NOT EXISTS %s_connection_idx    ON %s (connection)""" % (idx, idx)
            )


        self.dbh.commit()


        # updates, database schema corrections for old versions

        # svn rev 2143 removed the table dcerpcs
        # and created the table dcerpcrequests
        #
        # copy the data to the new table dcerpcrequests
        # drop the old table
        try:
            logger.debug("Updating Table dcerpcs")
            self.cursor.execute("""INSERT INTO
                                    dcerpcrequests (connection, dcerpcrequest_uuid, dcerpcrequest_opnum)
                                SELECT
                                    connection, dcerpc_uuid, dcerpc_opnum
                                FROM
                                    dcerpcs""")
            self.cursor.execute("""DROP TABLE dcerpcs""")
            logger.debug("... done")
        except Exception as e:
            #            print(e)
            logger.debug("... not required")

    def __del__(self):
        logger.info("Closing sqlite handle")
        self.cursor.close()
        self.cursor = None
        self.dbh.close()
        self.dbh = None

    def _handle_credentials(self, icd):
        """
        Insert credentials into the logins table.

        :param icd: Incident
        """
        con = icd.con
        if con in self.attacks:
            attack_id = self.attacks[con][1]
            self.cursor.execute(
                "INSERT INTO logins (connection, login_username, login_password) VALUES (?,?,?)",
                (attack_id, icd.username, icd.password)
            )
            self.dbh.commit()

    def handle_incident(self, icd):
        #        print("unknown")
        pass

    def connection_insert(self, icd, connection_type):
        con=icd.con
        r = self.cursor.execute("INSERT INTO connections (connection_timestamp, connection_type, connection_transport, connection_protocol, local_host, local_port, remote_host, remote_hostname, remote_port) VALUES (?,?,?,?,?,?,?,?,?)",
                                (time.time(), connection_type, con.transport, con.protocol, con.local.host, con.local.port, con.remote.host, con.remote.hostname, con.remote.port) )
        attackid = self.cursor.lastrowid
        self.attacks[con] = (attackid, attackid)
        self.dbh.commit()

        # maybe this was a early connection?
        if con in self.pending:
            # the connection was linked before we knew it
            # that means we have to
            # - update the connection_root and connection_parent for all connections which had the pending
            # - update the connection_root for all connections which had the 'childid' as connection_root
            for i in self.pending[con]:
                print("%s %s %s" % (attackid, attackid, i))
                self.cursor.execute("UPDATE connections SET connection_root = ?, connection_parent = ? WHERE connection = ?",
                                    (attackid, attackid, i ) )
                self.cursor.execute("UPDATE connections SET connection_root = ? WHERE connection_root = ?",
                                    (attackid, i ) )
            self.dbh.commit()

        return attackid


    def handle_incident_dionaea_connection_tcp_listen(self, icd):
        attackid = self.connection_insert( icd, 'listen')
        con=icd.con
        logger.info("listen connection on %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, attackid))

    def handle_incident_dionaea_connection_tls_listen(self, icd):
        attackid = self.connection_insert( icd, 'listen')
        con=icd.con
        logger.info("listen connection on %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, attackid))

    def handle_incident_dionaea_connection_tcp_connect(self, icd):
        attackid = self.connection_insert( icd, 'connect')
        con=icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" %
                    (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tls_connect(self, icd):
        attackid = self.connection_insert( icd, 'connect')
        con=icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" %
                    (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_udp_connect(self, icd):
        attackid = self.connection_insert( icd, 'connect')
        con=icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" %
                    (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tcp_accept(self, icd):
        attackid = self.connection_insert( icd, 'accept')
        con=icd.con
        logger.info("accepted connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tls_accept(self, icd):
        attackid = self.connection_insert( icd, 'accept')
        con=icd.con
        logger.info("accepted connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))


    def handle_incident_dionaea_connection_tcp_reject(self, icd):
        attackid = self.connection_insert(icd, 'reject')
        con=icd.con
        logger.info("reject connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_tcp_pending(self, icd):
        attackid = self.connection_insert(icd, 'pending')
        con=icd.con
        logger.info("pending connection from %s:%i to %s:%i (id=%i)" %
                    (con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

    def handle_incident_dionaea_connection_link_early(self, icd):
        # if we have to link a connection with a connection we do not know yet,
        # we store the unknown connection in self.pending and associate the
        # childs id with it
        if icd.parent not in self.attacks:
            if icd.parent not in self.pending:
                self.pending[icd.parent] = {self.attacks[icd.child][1]: True}
            else:
                if icd.child not in self.pending[icd.parent]:
                    self.pending[icd.parent][self.attacks[icd.child][1]] = True

    def handle_incident_dionaea_connection_link(self, icd):
        if icd.parent in self.attacks:
            logger.info("parent ids %s" % str(self.attacks[icd.parent]))
            parentroot, parentid = self.attacks[icd.parent]
            if icd.child in self.attacks:
                logger.info("child had ids %s" % str(self.attacks[icd.child]))
                childroot, childid = self.attacks[icd.child]
            else:
                childid = parentid
            self.attacks[icd.child] = (parentroot, childid)
            logger.info("child has ids %s" % str(self.attacks[icd.child]))
            logger.info("child %i parent %i root %i" %
                        (childid, parentid, parentroot) )
            r = self.cursor.execute("UPDATE connections SET connection_root = ?, connection_parent = ? WHERE connection = ?",
                                    (parentroot, parentid, childid) )
            self.dbh.commit()

        if icd.child in self.pending:
            # if the new accepted connection was pending
            # assign the connection_root to all connections which have been
            # waiting for this connection
            parentroot, parentid = self.attacks[icd.parent]
            if icd.child in self.attacks:
                childroot, childid = self.attacks[icd.child]
            else:
                childid = parentid

            self.cursor.execute("UPDATE connections SET connection_root = ? WHERE connection_root = ?",
                                (parentroot, childid) )
            self.dbh.commit()

    def handle_incident_dionaea_connection_free(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            del self.attacks[con]
            logger.info("attackid %i is done" % attackid)
        else:
            logger.warn("no attackid for %s:%s" %
                        (con.local.host, con.local.port) )
        if con in self.pending:
            del self.pending[con]


    def handle_incident_dionaea_module_emu_profile(self, icd):
        con = icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("emu profile for attackid %i" % attackid)
        self.cursor.execute("INSERT INTO emu_profiles (connection, emu_profile_json) VALUES (?,?)",
                            (attackid, icd.profile) )
        self.dbh.commit()


    def handle_incident_dionaea_download_offer(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("offer for attackid %i" % attackid)
        self.cursor.execute("INSERT INTO offers (connection, offer_url) VALUES (?,?)",
                            (attackid, icd.url) )
        self.dbh.commit()

    def handle_incident_dionaea_download_complete_hash(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("complete for attackid %i" % attackid)
        self.cursor.execute("INSERT INTO downloads (download_timestamp, connection, download_url, download_md5_hash) VALUES (?,?,?,?)",
                            (time.time(), attackid, icd.url, icd.md5hash) )
        self.dbh.commit()

    def handle_incident_dionaea_service_shell_listen(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("listen shell for attackid %i" % attackid)
        self.cursor.execute("INSERT INTO emu_services (connection, emu_service_url) VALUES (?,?)",
                            (attackid, "bindshell://"+str(icd.port)) )
        self.dbh.commit()

    def handle_incident_dionaea_service_shell_connect(self, icd):
        con=icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("connect shell for attackid %i" % attackid)
        self.cursor.execute("INSERT INTO emu_services (connection, emu_service_url) VALUES (?,?)",
                            (attackid, "connectbackshell://"+str(icd.host)+":"+str(icd.port)) )
        self.dbh.commit()

    def handle_incident_dionaea_modules_python_p0f(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO p0fs (connection, p0f_genre, p0f_link, p0f_detail, p0f_uptime, p0f_tos, p0f_dist, p0f_nat, p0f_fw) VALUES (?,?,?,?,?,?,?,?,?)",
                                ( attackid, icd.genre, icd.link, icd.detail, icd.uptime, icd.tos, icd.dist, icd.nat, icd.fw))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_ftp_login(self, icd):
        self._handle_credentials(icd)

    def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO dcerpcrequests (connection, dcerpcrequest_uuid, dcerpcrequest_opnum) VALUES (?,?,?)",
                                (attackid, icd.uuid, icd.opnum))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_smb_dcerpc_bind(self, icd):
        con=icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO dcerpcbinds (connection, dcerpcbind_uuid, dcerpcbind_transfersyntax) VALUES (?,?,?)",
                                (attackid, icd.uuid, icd.transfersyntax))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_mssql_login(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO logins (connection, login_username, login_password) VALUES (?,?,?)",
                                (attackid, icd.username, icd.password))
            self.cursor.execute("INSERT INTO mssql_fingerprints (connection, mssql_fingerprint_hostname, mssql_fingerprint_appname, mssql_fingerprint_cltintname) VALUES (?,?,?,?)",
                                (attackid, icd.hostname, icd.appname, icd.cltintname))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO mssql_commands (connection, mssql_command_status, mssql_command_cmd) VALUES (?,?,?)",
                                (attackid, icd.status, icd.cmd))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_virustotal_report(self, icd):
        md5 = icd.md5hash
        f = open(icd.path, mode='r')
        j = json.load(f)

        if j['response_code'] == 1: # file was known to virustotal
            permalink = j['permalink']
            scan_date = j['scan_date']
            sha1 = j['sha1']
            sha256 = j['sha256']
            positives = j['positives']
            total = j['total']

            logger.debug("Trying to update table: virustotals (%s)", md5)

            self.cursor.execute("INSERT INTO virustotals (virustotal_md5_hash, virustotal_sha1_hash, virustotal_sha256_hash, virustotal_positives,      virustotal_total, virustotal_permalink, virustotal_timestamp) VALUES (?,?,?,?,?,?,strftime('%s',?))",
                                (md5, sha1, sha256, positives, total, permalink, scan_date))            
            self.dbh.commit()

            virustotal = self.cursor.lastrowid

            scans = j['scans']
            for av, val in scans.items():
                res = val['result']
                # not detected = '' -> NULL
                if res == '':
                    res = None

                self.cursor.execute("""INSERT INTO virustotalscans (virustotal, virustotalscan_scanner, virustotalscan_result) VALUES (?,?,?)""",
                                    (virustotal, av, res))
#                logger.debug("scanner {} result {}".format(av,scans[av]))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_mysql_login(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO logins (connection, login_username, login_password) VALUES (?,?,?)",
                                (attackid, icd.username, icd.password))
            self.dbh.commit()


    def handle_incident_dionaea_modules_python_mysql_command(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO mysql_commands (connection, mysql_command_cmd) VALUES (?,?)",
                                (attackid, icd.command))
            cmdid = self.cursor.lastrowid

            if hasattr(icd, 'args'):
                args = icd.args
                for i in range(len(args)):
                    arg = args[i]
                    self.cursor.execute("INSERT INTO mysql_command_args (mysql_command, mysql_command_arg_index, mysql_command_arg_data) VALUES (?,?,?)",
                                        (cmdid, i, arg))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_sip_command(self, icd):
        con = icd.con
        if con not in self.attacks:
            return

        def calc_allow(a):
            b={ b'UNKNOWN'  :(1<<0),
                'ACK'       :(1<<1),
                'BYE'       :(1<<2),
                'CANCEL'    :(1<<3),
                'INFO'      :(1<<4),
                'INVITE'    :(1<<5),
                'MESSAGE'   :(1<<6),
                'NOTIFY'    :(1<<7),
                'OPTIONS'   :(1<<8),
                'PRACK'     :(1<<9),
                'PUBLISH'   :(1<<10),
                'REFER'     :(1<<11),
                'REGISTER'  :(1<<12),
                'SUBSCRIBE' :(1<<13),
                'UPDATE'    :(1<<14)
                }
            allow=0
            for i in a:
                if i in b:
                    allow |= b[i]
                else:
                    allow |= b[b'UNKNOWN']
            return allow

        attackid = self.attacks[con][1]
        self.cursor.execute("""INSERT INTO sip_commands
            (connection, sip_command_method, sip_command_call_id,
            sip_command_user_agent, sip_command_allow) VALUES (?,?,?,?,?)""",
                            (attackid, icd.method, icd.call_id, icd.user_agent, calc_allow(icd.allow)))
        cmdid = self.cursor.lastrowid

        def add_addr(cmd, _type, addr):
            self.cursor.execute("""INSERT INTO sip_addrs
                (sip_command, sip_addr_type, sip_addr_display_name,
                sip_addr_uri_scheme, sip_addr_uri_user, sip_addr_uri_password,
                sip_addr_uri_host, sip_addr_uri_port) VALUES (?,?,?,?,?,?,?,?)""",
                                (
                                    cmd, _type, addr['display_name'],
                                    addr['uri']['scheme'], addr['uri'][
                                        'user'], addr['uri']['password'],
                                    addr['uri']['host'], addr['uri']['port']
                                ))
        add_addr(cmdid,'addr',icd.get('addr'))
        add_addr(cmdid,'to',icd.get('to'))
        add_addr(cmdid,'contact',icd.get('contact'))
        for i in icd.get('from'):
            add_addr(cmdid,'from',i)

        def add_via(cmd, via):
            self.cursor.execute("""INSERT INTO sip_vias
                (sip_command, sip_via_protocol, sip_via_address, sip_via_port)
                VALUES (?,?,?,?)""",
                                (
                                    cmd, via['protocol'],
                                    via['address'], via['port']

                                ))

        for i in icd.get('via'):
            add_via(cmdid, i)

        def add_sdp(cmd, sdp):
            def add_origin(cmd, o):
                self.cursor.execute("""INSERT INTO sip_sdp_origins
                    (sip_command, sip_sdp_origin_username,
                    sip_sdp_origin_sess_id, sip_sdp_origin_sess_version,
                    sip_sdp_origin_nettype, sip_sdp_origin_addrtype,
                    sip_sdp_origin_unicast_address)
                    VALUES (?,?,?,?,?,?,?)""",
                                    (
                                        cmd, o['username'],
                                        o['sess_id'], o['sess_version'],
                                        o['nettype'], o['addrtype'],
                                        o['unicast_address']
                                    ))
            def add_condata(cmd, c):
                self.cursor.execute("""INSERT INTO sip_sdp_connectiondatas
                    (sip_command, sip_sdp_connectiondata_nettype,
                    sip_sdp_connectiondata_addrtype, sip_sdp_connectiondata_connection_address,
                    sip_sdp_connectiondata_ttl, sip_sdp_connectiondata_number_of_addresses)
                    VALUES (?,?,?,?,?,?)""",
                                    (
                                        cmd, c['nettype'],
                                        c['addrtype'], c['connection_address'],
                                        c['ttl'], c['number_of_addresses']
                                    ))
            def add_media(cmd, c):
                self.cursor.execute("""INSERT INTO sip_sdp_medias
                    (sip_command, sip_sdp_media_media,
                    sip_sdp_media_port, sip_sdp_media_number_of_ports,
                    sip_sdp_media_proto)
                    VALUES (?,?,?,?,?)""",
                                    (
                                        cmd, c['media'],
                                        c['port'], c['number_of_ports'],
                                        c['proto']
                                    ))
            if 'o' in sdp:
                add_origin(cmd, sdp['o'])
            if 'c' in sdp:
                add_condata(cmd, sdp['c'])
            if 'm' in sdp:
                for i in sdp['m']:
                    add_media(cmd, i)

        if hasattr(icd,'sdp') and icd.sdp is not None:
            add_sdp(cmdid,icd.sdp)

        self.dbh.commit()

    def handle_incident_dionaea_modules_python_mqtt_connect(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            #self.cursor.execute("INSERT INTO logins (connection, login_username, login_password) VALUES (?,?,?)",
            #    (attackid, icd.username, icd.password))
            self.cursor.execute("INSERT INTO mqtt_fingerprints (connection, mqtt_fingerprint_clientid, mqtt_fingerprint_willtopic, mqtt_fingerprint_willmessage,mqtt_fingerprint_username,mqtt_fingerprint_password) VALUES (?,?,?,?,?,?)",
                (attackid, icd.clientid, icd.willtopic, icd.willmessage, icd.username, icd.password))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_mqtt_publish(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO mqtt_publish_commands (connection, mqtt_publish_command_topic, mqtt_publish_command_message) VALUES (?,?,?)",
                (attackid, icd.publishtopic, icd.publishmessage))
            self.dbh.commit()

    def handle_incident_dionaea_modules_python_mqtt_subscribe(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.cursor.execute("INSERT INTO mqtt_subscribe_commands (connection, mqtt_subscribe_command_messageid, mqtt_subscribe_command_topic) VALUES (?,?,?)",
                (attackid, icd.subscribemessageid, icd.subscribetopic))
            self.dbh.commit()
