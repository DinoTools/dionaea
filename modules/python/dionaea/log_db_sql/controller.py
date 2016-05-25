import datetime
import json
import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from dionaea.core import ihandler
from dionaea.log_db_sql import model

logger = logging.getLogger('log_db_sql')
logger.setLevel(logging.DEBUG)


class LogSQLHandler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
        self.path = path
        self._config = config
        self.db_session = None

        self.attacks = {}
        self.pending = {}

    def start(self):
        ihandler.__init__(self, self.path)
        # mapping socket -> attackid

        engine = create_engine(self._config.get("url"), echo=False, convert_unicode=True)
        self.db_session = scoped_session(
            sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=engine
            )
        )
        model.Base.query = self.db_session.query_property()
        model.Base.metadata.create_all(bind=engine)

    def handle_incident(self, icd):
        #        print("unknown")
        pass

    def connection_insert(self, icd, connection_type):
        con = icd.con
        connection = model.Connection(
            timestamp=datetime.datetime.now(),
            type=connection_type,
            transport=con.transport,
            protocol=con.protocol,
            local_host=con.local.host,
            local_port=con.local.port,
            remote_host=con.remote.host,
            remote_port=con.remote.port,
            remote_hostname=con.remote.hostname
        )
        connection.root = connection.id

        self.db_session.add(connection)
        self.db_session.commit()

        # Old trigger
        self.db_session.query(
            model.Connection
        ).filter(
            model.Connection.id == connection.id and model.Connection.root is None
        ).update({
            "root": connection.id
        })
        self.db_session.commit()

        attackid = connection.id
        self.attacks[con] = (attackid, attackid)

        # maybe this was a early connection?
        if con in self.pending:
            # the connection was linked before we knew it
            # that means we have to
            # - update the connection_root and connection_parent for all connections which had the pending
            # - update the connection_root for all connections which had the 'childid' as connection_root
            for i in self.pending[con]:
                print("%s %s %s" % (attackid, attackid, i))
                self.db_session.query(
                    model.Connection
                ).filter(
                    model.Connection.id == i
                ).update({
                    "root": attackid,
                    "parent": attackid
                })
                self.db_session.query(
                    model.Connection
                ).filter(
                    model.Connection.root == i
                ).update({
                    "root": attackid
                })
            self.db_session.commit()
        return attackid

    def handle_incident_dionaea_connection_tcp_listen(self, icd):
        attackid = self.connection_insert(icd, 'listen')
        con = icd.con
        logger.info("listen connection on %s:%i (id=%i)", con.remote.host, con.remote.port, attackid)

    def handle_incident_dionaea_connection_tls_listen(self, icd):
        attackid = self.connection_insert(icd, 'listen')
        con = icd.con
        logger.info("listen connection on %s:%i (id=%i)", con.remote.host, con.remote.port, attackid)

    def handle_incident_dionaea_connection_tcp_connect(self, icd):
        attackid = self.connection_insert(icd, 'connect')
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)", con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid)

    def handle_incident_dionaea_connection_tls_connect(self, icd):
        attackid = self.connection_insert(icd, 'connect')
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)", con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid)

    def handle_incident_dionaea_connection_udp_connect(self, icd):
        attackid = self.connection_insert(icd, 'connect')
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)", con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid)

    def handle_incident_dionaea_connection_tcp_accept(self, icd):
        attackid = self.connection_insert(icd, 'accept')
        con = icd.con
        logger.info("accepted connection from %s:%i to %s:%i (id=%i)", con.remote.host, con.remote.port, con.local.host, con.local.port, attackid)

    def handle_incident_dionaea_connection_tls_accept(self, icd):
        attackid = self.connection_insert(icd, 'accept')
        con = icd.con
        logger.info("accepted connection from %s:%i to %s:%i (id=%i)", con.remote.host, con.remote.port, con.local.host, con.local.port, attackid)

    def handle_incident_dionaea_connection_tcp_reject(self, icd):
        attackid = self.connection_insert(icd, 'reject')
        con = icd.con
        logger.info("reject connection from %s:%i to %s:%i (id=%i)", con.remote.host, con.remote.port, con.local.host, con.local.port, attackid)

    def handle_incident_dionaea_connection_tcp_pending(self, icd):
        attackid = self.connection_insert(icd, 'pending')
        con = icd.con
        logger.info("pending connection from %s:%i to %s:%i (id=%i)", con.remote.host, con.remote.port, con.local.host, con.local.port, attackid)

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
            logger.info("parent ids %s", str(self.attacks[icd.parent]))
            parentroot, parentid = self.attacks[icd.parent]
            if icd.child in self.attacks:
                logger.info("child had ids %s", str(self.attacks[icd.child]))
                childroot, childid = self.attacks[icd.child]
            else:
                childid = parentid
            self.attacks[icd.child] = (parentroot, childid)
            logger.info("child has ids %s", str(self.attacks[icd.child]))
            logger.info("child %i parent %i root %i", childid, parentid, parentroot)
            self.db_session.query(
                model.Connection
            ).filter(
                model.Connection.id == childid
            ).update({
                "root": parentroot,
                "parent": parentid
            })
            self.db_session.commit()

        if icd.child in self.pending:
            # if the new accepted connection was pending
            # assign the connection_root to all connections which have been
            # waiting for this connection
            parentroot, parentid = self.attacks[icd.parent]
            if icd.child in self.attacks:
                childroot, childid = self.attacks[icd.child]
            else:
                childid = parentid

            self.db_session.query(
                model.Connection
            ).filter(
                model.Connection.root == childid
            ).update({
                "root": parentroot
            })
            self.db_session.commit()

    def handle_incident_dionaea_connection_free(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            del self.attacks[con]
            logger.info("attackid %i is done", attackid)
        else:
            logger.warn("no attackid for %s:%s", con.local.host, con.local.port)
        if con in self.pending:
            del self.pending[con]

    def handle_incident_dionaea_module_emu_profile(self, icd):
        con = icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("emu profile for attackid %i", attackid)
        self.db_session.add(
            model.EmuProfile(
                connection_id=attackid,
                json_data=icd.profile
            )
        )
        self.db_session.commit()

    def handle_incident_dionaea_download_offer(self, icd):
        con = icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("offer for attackid %i", attackid)
        self.db_session.add(
            model.DownloadOffer(
                connection_id=attackid,
                url=icd.url
            )
        )
        self.db_session.commit()

    def handle_incident_dionaea_download_complete_hash(self, icd):
        con = icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("complete for attackid %i", attackid)
        self.db_session.add(
            model.DownloadData(
                connection_id=attackid,
                url=icd.url,
                md5_hash=icd.md5hash
            )
        )
        self.db_session.commit()

    def handle_incident_dionaea_service_shell_listen(self, icd):
        con = icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("listen shell for attackid %i", attackid)
        self.db_session.add(
            model.EmuService(
                connection_id=attackid,
                url="bindshell://{}".format(str(icd.port))
            )
        )
        self.db_session.commit()

    def handle_incident_dionaea_service_shell_connect(self, icd):
        con = icd.con
        if con not in self.attacks:
            return
        attackid = self.attacks[con][1]
        logger.info("connect shell for attackid %i", attackid)
        self.db_session.add(
            model.EmuService(
                connection_id=attackid,
                url="connectbackshell://" + str(icd.host) + ":" + str(icd.port)
            )
        )
        self.db_session.commit()

    def handle_incident_dionaea_modules_python_p0f(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.db_session.add(
                model.P0F(
                    connection_id=attackid,
                    genre=icd.genre,
                    link=icd.link,
                    detail=icd.detail,
                    uptime=icd.uptime,
                    tos=icd.tos,
                    dist=icd.dist,
                    nat=icd.nat,
                    fw=icd.fw
                )
            )
            self.db_session.commit()

    def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.db_session.add(
                model.SmbDCERPCRequest(
                    connection_id=attackid,
                    uuid=icd.uuid,
                    opnum=icd.opnum
                )
            )
            self.db_session.commit()

    def handle_incident_dionaea_modules_python_smb_dcerpc_bind(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.db_session.add(
                model.SmbDCERPCBind(
                    connection_id=attackid,
                    uuid=icd.uuid,
                    transfer_syntax=icd.transfer_syntax
                )
            )
            self.db_session.commit()

    def handle_incident_dionaea_modules_python_mssql_login(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.db_session.add(
                model.MSSQLLogin(
                    connection_id=attackid,
                    username=icd.username,
                    password=icd.password
                )
            )
            self.db_session.add(
                model.MSSQLFingerprint(
                    connection_id=attackid,
                    hostname=icd.hostname,
                    appname=icd.appname,
                    cltintname=icd.cltintname
                )
            )
            self.db_session.commit()

    def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.db_session.add(
                model.MSSQLCommand(
                    connection_id=attackid,
                    command=icd.cmd,
                    status=icd.status
                )
            )
            self.db_session.commit()

    def handle_incident_dionaea_modules_python_virustotal_report(self, icd):
        md5 = icd.md5hash
        f = open(icd.path, mode='r')
        j = json.load(f)

        # file was known to virustotal
        if j['response_code'] == 1:
            permalink = j['permalink']
            date = j['scan_date']
            db_virustotal_scan = model.VirusTotalScan(
                md5_hash=md5,
                permalink=permalink,
                timestamp=date
            )
            self.db_session.add(db_virustotal_scan)

            scans = j['scans']
            for av, val in scans.items():
                res = val['result']
                # not detected = '' -> NULL
                if res == '':
                    res = None

                self.db_session.add(
                    model.VirusTotalResult(
                        scan=db_virustotal_scan,
                        result=res,
                        status=av
                    )
                )
            self.db_session.commit()

    def handle_incident_dionaea_modules_python_mysql_login(self, icd):
        con = icd.con
        if con in self.attacks:
            attackid = self.attacks[con][1]
            self.db_session.add(
                model.MySQLLogin(
                    connection_id=attackid,
                    username=icd.username,
                    password=icd.password
                )
            )
            self.db_session.commit()

    def handle_incident_dionaea_modules_python_mysql_command(self, icd):
        con = icd.con
        if con not in self.attacks:
            return

        attackid = self.attacks[con][1]

        db_mysql_command = model.MySQLCommand(
            connection_id=attackid,
            command=icd.command
        )
        self.db_session.add(db_mysql_command)

        if hasattr(icd, 'args'):
            args = icd.args
            for i in range(len(args)):
                arg = args[i]
                self.db_session.add(
                    model.MySQLCommandArgument(
                        command=db_mysql_command,
                        index=i,
                        value=arg
                    )
                )

        self.db_session.commit()

    def handle_incident_dionaea_modules_python_mqtt_connect(self, icd):
        con = icd.con
        if con not in self.attacks:
            return

        attackid = self.attacks[con][1]
        self.db_session.add(
            model.MQTTFingerprint(
                connection_id=attackid,
                username=icd.username,
                password=icd.password,
                clientid=icd.clientid,
                will_topic=icd.willtopic,
                will_message=icd.willmessage
            )
        )
        self.db_session.commit()

    def handle_incident_dionaea_modules_python_mqtt_publish(self, icd):
        con = icd.con
        if con not in self.attacks:
            return

        attackid = self.attacks[con][1]
        self.db_session.add(
            model.MQTTPublishCommand(
                connection_id=attackid,
                topic=icd.publishtopic,
                message=icd.publishmessage
            )
        )
        self.db_session.commit()

    def handle_incident_dionaea_modules_python_mqtt_subscribe(self, icd):
        con = icd.con
        if con not in self.attacks:
            return

        attackid = self.attacks[con][1]
        self.db_session.add(
            model.MQTTSubscribeCommand(
                connection_id=attackid,
                messageid=icd.subscribemessageid,
                topic=icd.subscribetopic
            )
        )
        self.db_session.commit()

    def handle_incident_dionaea_modules_python_sip_command(self, icd):
        def add_addr(_type, addr):
            self.db_session.add(
                model.SipAddress(
                    command=db_sip_command,
                    type=_type,
                    display_name=addr["display_name"],
                    uri_scheme=addr["uri"]["scheme"],
                    uri_username=addr["uri"]["user"],
                    uri_password=addr["uri"]["password"],
                    uri_host=addr["uri"]["host"],
                    uri_port=addr["uri"]["port"]
                )
            )

        def add_sdp_condata(c):
            self.db_session.add(
                model.SipSdpConnection(
                    sip_command=db_sip_command,
                    network_type=c["nettype"],
                    address_type=c["addrtype"],
                    connection_address=c["connection_address"],
                    ttl=c["ttl"],
                    number_of_address=c["number_of_addresses"]
                )
            )

        def add_sdp_media(c):
            self.db_session.add(
                model.SipSdpMedia(
                    sip_command=db_sip_command,
                    media=c["media"],
                    port=c["port"],
                    number_of_ports=c["number_of_ports"],
                    protocol=c["proto"]
                )
            )

        def add_sdp_origin(o):
            self.db_session.add(
                model.SipSdpOrigin(
                    sip_command=db_sip_command,
                    username=o["username"],
                    session_id=o["sess_id"],
                    session_version=o["sess_version"],
                    network_type=o["nettype"],
                    address_type=o["addrtype"],
                    unicast_address=o["unicast_address"]
                )
            )

        def calc_allow(a):
            b = { b'UNKNOWN'  :(1<<0),
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
            allow = 0
            for i in a:
                if i in b:
                    allow |= b[i]
                else:
                    allow |= b[b'UNKNOWN']
            return allow

        con = icd.con
        if con not in self.attacks:
            return

        attackid = self.attacks[con][1]
        db_sip_command = model.SipCommand(
            connection_id=attackid,
            method=icd.method,
            call_id=icd.call_id,
            user_agent=icd.user_agent,
            allow=calc_allow(icd.allow)
        )
        self.db_session.add(db_sip_command)

        for name in ("addr", "to", "contact"):
            add_addr(name, icd.get(name))

        for i in icd.get('from'):
            add_addr('from', i)

        for via in icd.get('via'):
            self.db_session.add(
                model.SipVia(
                    command=db_sip_command,
                    protocol=via["protocol"],
                    address=via["address"],
                    port=via["port"]
                )
            )

        sdp_data = icd.get("sdp")
        if sdp_data is not None:
            if 'o' in sdp_data:
                add_sdp_origin(sdp_data['o'])
            if 'c' in sdp_data:
                add_sdp_condata(sdp_data['c'])
            if 'm' in sdp_data:
                for i in sdp_data['m']:
                    add_sdp_media(i)

        self.db_session.commit()
