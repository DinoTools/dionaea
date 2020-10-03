#!/usr/bin/python -u
#
# aptitude install python-pyxmpp python-pgsql
#
# with db
# ./pg_backend.py -U USER@sensors.carnivore.it -P XMPPPASS -M dionaea.sensors.carnivore.it -C anon-files -C anon-events -s DBHOST -u DBUSER -d xmpp -p DBPASS -f /tmp/
#
# without db
# ./pg_backend.py -U USER@sensors.carnivore.it -P XMPPPASS -M dionaea.sensors.carnivore.it -C anon-files -C anon-events -f /tmp/

import sys
import logging
import locale
import codecs
import base64
import md5
import optparse
import io
import os
from pyPgSQL import PgSQL

from pyxmpp.all import JID
from pyxmpp.jabber.client import JabberClient
from pyxmpp.jabber.muc import MucRoomManager, MucRoomHandler
from pyxmpp.xmlextra import replace_ns, common_doc


# PyXMPP uses `logging` module for its debug output
# applications should set it up as needed
logger=logging.getLogger()
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO) # change to DEBUG for higher verbosity

dionaea_ns = {  "default" : "http://pyxmpp.jajcus.net/xmlns/common",
                "dionaea" : "http://dionaea.carnivore.it"}

# libxml2 is cruel
def xpath_eval(xmlnode,expr,namespaces=None):
    ctxt = common_doc.xpathNewContext()
    ctxt.setContextNode(xmlnode)
    if namespaces:
        for prefix,uri in namespaces.items():
            ctxt.xpathRegisterNs(unicode(prefix),uri)
    ret=ctxt.xpathEval(unicode(expr))
    ctxt.xpathFreeContext()
    return ret

class RoomHandler(MucRoomHandler):
    def __init__(self):
        MucRoomHandler.__init__(self)
        self.setns = False

    def user_joined(self, user, stanza):
        print('User %s joined room' % user.room_jid.as_unicode())
        user.attacks = {}

    def user_left(self, user, stanza):
        print('User %s left room' % user.room_jid.as_unicode())
        user.attacks = None
        user = None

    def subject_changed(self, user, stanza):
        print('subject: %s' % stanza)

    def message_received(self, user, stanza):

        if not hasattr(user, 'attacks'):
            print("invalid message, maybe history")
            return
        # check if we have dionaea entries in the message
        # provide a namespace ...
        # I love xml namespaces ...

        # dionaea

        r = stanza.xpath_eval("/default:message/default:body/dionaea:dionaea",
                              namespaces = dionaea_ns)

        for d in r:
            # rename the namespace for the dionaea entries
            o = d.ns()
            n = d.newNs("http://dionaea.carnivore.it", "dionaea")
            d.setNs(n)
            replace_ns(d,o,n)

            # get the incident
            p = d.hasProp('incident')
            mname = p.content
            mname = mname.replace(".","_")

            # use the incidents name to get the appropriate handler
            method = getattr(self, "handle_incident_" + mname, None)
#			method = self.handle_incident_debug
            if method is not None:
                c = d.children
                while c is not None:
                    #					print("c: '%s'" % c)
                    if c.isText():
                        c = c.next
                        continue
                    # call the handler with the object
#				   print(mname)
                    method(user, c)
                    c = c.next
#			else:
#				print("method %s is not implemented" % mname)
#				self.handle_incident_not_implemented(user, stanza)

        # kippo

        r = stanza.xpath_eval("/default:message/default:body/kippo:kippo",
                              namespaces = {  "default" : "http://pyxmpp.jajcus.net/xmlns/common",
                                              "kippo" : "http://code.google.com/p/kippo/"})

        for d in r:
            o = d.ns()
            n = d.newNs("http://code.google.com/p/kippo/", "kippo")
            d.setNs(n)
            replace_ns(d,o,n)
#			print(d)
            p = d.hasProp('type')
            mname = p.content
            method = getattr(self, "handle_kippo_" + mname, None)
            if method is not None:
                for c in d.children:
                    if c.isText():
                        continue
                    method(user, c)
            else:
                print("method %s is not implemented" % mname)
#				self.handle_incident_not_implemented(user, stanza)

    def handle_kippo_createsession(self, user, xmlobj):
        try:
            local_host = xmlobj.hasProp('local_host').content
            remote_host = xmlobj.hasProp('remote_host').content
            session = xmlobj.hasProp('session').content
        except Exception as e:
            print(e)
            return
        if dbh is not None:
            r = cursor.execute(
                """INSERT INTO
			kippo.sessions
					(session_start, session_stop, local_host, remote_host)
	VALUES (NOW(),NOW(),%s,%s)""" ,
                (local_host, remote_host))
            r = cursor.execute(
                """SELECT CURRVAL('kippo.sessions_session_seq')""")
            attackid = cursor.fetchall()[0][0]
            user.attacks[session] = (attackid,attackid)
        print("[%s] createsession: %s %s %s" %
              (user.room_jid.as_unicode(), local_host, remote_host, session))


    def handle_kippo_connectionlost(self, user, xmlobj):
        try:
            session = xmlobj.hasProp('session').content
        except Exception as e:
            print(e)
            return
        if dbh is not None:
            if session in user.attacks:
                attackid = user.attacks[session][0]
                r = cursor.execute(
                    """UPDATE kippo.sessions SET session_stop = NOW() WHERE session = %s""" , (attackid, ))
                del user.attacks[session]
        print("[%s] connectionlost: %s" %
              (user.room_jid.as_unicode(), session))

    def _handle_kippo_login(self, user, xmlobj, success):
        try:
            session = xmlobj.hasProp('session').content
            username = xmlobj.hasProp('username').content
            password = xmlobj.hasProp('password').content
        except Exception as e:
            print(e)
            return
        if dbh is not None:
            if session in user.attacks:
                attackid = user.attacks[session][0]
                r = cursor.execute(
                    """INSERT INTO
				kippo.auths
						(auth_timestamp, session, auth_username, auth_password, auth_success)
		VALUES (NOW(),%s,%s,%s,%s::boolean)""",
                    (attackid, username, password, success))
        print("[%s] : login %s %s %s %s" %
              (user.room_jid.as_unicode(), success, username, password, session))


    def handle_kippo_loginfailed(self, user, xmlobj):
        self._handle_kippo_login(user, xmlobj, False)

    def handle_kippo_loginsucceeded(self, user, xmlobj):
        self._handle_kippo_login(user, xmlobj, True)

    def _handle_kippo_input(self, user, xmlobj, realm, success):
        try:
            session = xmlobj.hasProp('session').content
            command = xmlobj.content
        except Exception as e:
            print(e)
            return
        if dbh is not None:
            if session in user.attacks:
                attackid = user.attacks[session][0]
                cursor.execute("""INSERT INTO kippo.inputs
					(session, input_timestamp, input_realm, input_success, input_data)
					VALUES (%s,NOW(),%s,%s,%s)""",
                               (attackid, realm, success, command) )
        print("[%s] command %s %s" %
              (user.room_jid.as_unicode(), command, session))


    def handle_kippo_command(self, user, xmlobj):
        try:
            if xmlobj.hasProp('command').content == 'known':
                success = True
            else:
                success = False
            self._handle_kippo_input(user, xmlobj,"",success)
        except Exception as e:
            print(e)
            return

    def handle_kippo_input(self, user, xmlobj):
        try:
            realm =  xmlobj.hasProp('realm').content
            self._handle_kippo_input(user, xmlobj,realm,True)
        except Exception as e:
            print(e)
            return


    def handle_kippo_clientversion(self, user, xmlobj):
        try:
            session = xmlobj.hasProp('session').content
            ver = xmlobj.hasProp('version').content
        except Exception as e:
            print(e)
            return
        if dbh is not None:
            if session in user.attacks:
                attackid = user.attacks[session][0]
                cursor.execute("""INSERT INTO kippo.clients
					(session, version)
					VALUES (%s,%s)""",
                               (attackid, ver) )
        print("[%s] version %s %s" %
              (user.room_jid.as_unicode(), ver, session))



    # dionaea
    def handle_incident_not_implemented(self, user, xmlobj):
        print("USER %s xmlobj '%s'" %
              (user.room_jid.as_unicode(), xmlobj.serialize()))

    def _handle_incident_connection_new(self, user, xmlobj):
        try:
            ctype = xmlobj.hasProp('type').content
            protocol = xmlobj.hasProp('protocol').content
            transport = xmlobj.hasProp('transport').content
            local_host = xmlobj.hasProp('local_host').content
            remote_host = xmlobj.hasProp('remote_host').content
            remote_hostname = xmlobj.hasProp('remote_hostname').content
            local_port = xmlobj.hasProp('local_port').content
            remote_port = xmlobj.hasProp('remote_port').content
            ref = xmlobj.hasProp('ref').content
            ref = int(ref)
        except Exception as e:
            print(e)
            return
        if remote_hostname == "":
            remote_hostname = None
        if remote_host == "" or remote_host is None:
            remote_host = "0.0.0.0"
        if dbh is not None:
            r = cursor.execute(
                """INSERT INTO
			dionaea.connections
					(connection_timestamp, connection_type, connection_transport, connection_protocol, local_host, local_port, remote_host, remote_hostname, remote_port)
	VALUES (NOW(),%s,%s,%s,%s,
			%s,%s,%s,%s)""" ,
                (ctype, transport, protocol, local_host,
                 local_port, remote_host, remote_hostname, remote_port))
            r = cursor.execute(
                """SELECT CURRVAL('dionaea.connections_connection_seq')""")
            attackid = cursor.fetchall()[0][0]
            user.attacks[ref] = (attackid,attackid)
        print("[%s] %s %s %s %s:%s %s/%s:%s %s" % (user.room_jid.as_unicode(), ctype, protocol,
                                                   transport, local_host, local_port, remote_hostname, remote_host, remote_port, ref))


    def handle_incident_dionaea_connection_tcp_listen(self, user, xmlobj):
        self._handle_incident_connection_new(user,xmlobj)

    def handle_incident_dionaea_connection_tls_listen(self, user, xmlobj):
        self._handle_incident_connection_new(user,xmlobj)

    def handle_incident_dionaea_connection_tcp_connect(self, user, xmlobj):
        self._handle_incident_connection_new(user,xmlobj)

    def handle_incident_dionaea_connection_tls_connect(self, user, xmlobj):
        self._handle_incident_connection_new(user,xmlobj)

    def handle_incident_dionaea_connection_udp_connect(self, user, xmlobj):
        self._handle_incident_connection_new(user,xmlobj)

    def handle_incident_dionaea_connection_tcp_accept(self, user, xmlobj):
        self._handle_incident_connection_new(user,xmlobj)

    def handle_incident_dionaea_connection_tls_accept(self, user, xmlobj):
        self._handle_incident_connection_new(user,xmlobj)

    def handle_incident_dionaea_connection_tcp_reject(self, user, xmlobj):
        self._handle_incident_connection_new(user,xmlobj)

    def handle_incident_dionaea_connection_link(self, user, xmlobj):
        try:
            parent = int(xmlobj.hasProp('parent').content)
            child = int(xmlobj.hasProp('child').content)
        except Exception as e:
            print(e)
            return
        if dbh is not None and parent in user.attacks:
            parentroot, parentid = user.attacks[parent]
            if child in user.attacks:
                childroot, childid = user.attacks[child]
            else:
                childid = parentid
            user.attacks[child] = (parentroot, childid)
            cursor.execute("UPDATE dionaea.connections SET connection_root = %s, connection_parent = %s WHERE connection = %s",
                           (parentroot, parentid, childid) )
        print("[%s] link %s %s" % (user.room_jid.as_unicode(), parent, child))

    def handle_incident_dionaea_connection_free(self, user, xmlobj):
        try:
            ref = xmlobj.hasProp('ref').content
            ref = int(ref)
        except Exception as e:
            print(e)
            return

        if dbh is not None and ref in user.attacks:
            del user.attacks[ref]
        print("[%s] free %i" % (user.room_jid.as_unicode(), ref))


    def handle_incident_dionaea_module_emu_profile(self, user, xmlobj):
        try:
            ref = xmlobj.hasProp('ref').content
            profile = xmlobj.content
            ref = int(ref)
        except Exception as e:
            print(e)
            return
        if dbh is not None and ref in user.attacks:
            attackid = user.attacks[ref][1]
            cursor.execute("INSERT INTO dionaea.emu_profiles (connection, emu_profile_json) VALUES (%s,%s)",
                           (attackid, profile) )
        print("[%s] profile ref %s: %s" %
              (user.room_jid.as_unicode(), profile, ref))

    def handle_incident_dionaea_download_offer(self, user, xmlobj):
        try:
            ref = xmlobj.hasProp('ref').content
            url = xmlobj.hasProp('url').content
            ref = int(ref)
        except Exception as e:
            print(e)
            return
        if dbh is not None and ref in user.attacks:
            attackid = user.attacks[ref][1]
            cursor.execute("INSERT INTO dionaea.offers (connection, offer_url) VALUES (%s,%s)",
                           (attackid, url) )
        print("[%s] offer ref %i: %s" % (user.room_jid.as_unicode(), ref, url))

    def handle_incident_dionaea_download_complete_hash(self, user, xmlobj):
        try:
            ref = xmlobj.hasProp('ref').content
            md5_hash = xmlobj.hasProp('md5_hash').content
            url = xmlobj.hasProp('url').content
            ref = int(ref)
        except Exception as e:
            print(e)
            return
        if dbh is not None and ref in user.attacks:
            attackid = user.attacks[ref][1]
            cursor.execute("INSERT INTO dionaea.downloads (connection, download_url, download_md5_hash) VALUES (%s,%s,%s)",
                           (attackid, url, md5_hash) )
        print("[%s] complete ref %s: %s %s" %
              (user.room_jid.as_unicode(), ref, url, md5_hash))

    def handle_incident_dionaea_download_complete_unique(self, user, xmlobj):
        try:
            md5_hash = xmlobj.hasProp('md5_hash').content
            f = base64.b64decode(xmlobj.content)
            my_hash = md5.new(f).hexdigest()
        except Exception as e:
            print(e)
            return
        if options.files is not None:
            p = os.path.join(options.files, my_hash)
            h = io.open(p, "wb+")
            h.write(f)
            h.close()
        print("[%s] file %s <-> %s" %
              (user.room_jid.as_unicode(), md5_hash, my_hash))

    def handle_incident_dionaea_service_shell_listen(self, user, xmlobj):
        pass

    def handle_incident_dionaea_service_shell_connect(self, user, xmlobj):
        pass

    def handle_incident_dionaea_modules_python_p0f(self, user, xmlobj):
        try:
            genre = xmlobj.hasProp('genre').content
            link = xmlobj.hasProp('link').content
            detail = xmlobj.hasProp('detail').content
            uptime = xmlobj.hasProp('uptime').content
            tos = xmlobj.hasProp('tos').content
            dist = xmlobj.hasProp('dist').content
            nat = xmlobj.hasProp('nat').content
            fw = xmlobj.hasProp('fw').content
            ref = xmlobj.hasProp('ref').content
            ref = int(ref)
        except Exception as e:
            print(e)
            return

        if ref in user.attacks:
            attackid = user.attacks[ref][1]
            cursor.execute("INSERT INTO dionaea.p0fs (connection, p0f_genre, p0f_link, p0f_detail, p0f_uptime, p0f_tos, p0f_dist, p0f_nat, p0f_fw) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                           (attackid, genre, link, detail, uptime, tos, dist, nat, fw))
        print("[%s] p0f ref %i: %s" % (user.room_jid.as_unicode(), ref, genre))

    def handle_incident_dionaea_modules_python_virustotal_report(self, user, xmlobj):
        try:
            md5_hash = xmlobj.hasProp('md5_hash').content
            permalink = xmlobj.hasProp('permalink').content
            date = xmlobj.hasProp('date').content
            date = int(date)
        except Exception as e:
            print(e)
            return
        try:
            cursor.execute(
                "INSERT INTO dionaea.virustotals (virustotal_md5_hash, virustotal_timestamp, virustotal_permalink) VALUES (%s,to_timestamp(%s),%s)",(md5_hash, date, permalink))
            cursor.execute(
                """SELECT CURRVAL('dionaea.virustotals_virustotal_seq')""")
            print("[%s] virustotal %s" %
                  (user.room_jid.as_unicode(), md5_hash))
        except Exception as e:
            print(e)
            return
        r = cursor.fetchall()[0][0]
        c = xmlobj.children
        while c is not None:
            if c.name != 'scan':
                c = c.next
                continue
            try:
                scanner = c.hasProp('scanner').content
                result = c.hasProp('result').content
            except Exception as e:
                print(e)
            else:
                cursor.execute(
                    "INSERT INTO dionaea.virustotalscans (virustotal, virustotalscan_scanner, virustotalscan_result) VALUES (%s, %s,%s)",(r, scanner, result))
                print("[%s]\t %s %s" %
                      (user.room_jid.as_unicode(), scanner, result))
            c = c.next

    def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, user, xmlobj):
        try:
            uuid = xmlobj.hasProp('uuid').content
            opnum = xmlobj.hasProp('opnum').content
            ref = xmlobj.hasProp('ref').content
            ref = int(ref)
        except Exception as e:
            print(e)
            return
        if ref in user.attacks:
            attackid = user.attacks[ref][1]
            cursor.execute("INSERT INTO dionaea.dcerpcrequests (connection, dcerpcrequest_uuid, dcerpcrequest_opnum) VALUES (%s,%s,%s)",
                           (attackid, uuid, opnum))
        print("[%s] dcerpcrequest ref %i: %s %s" %
              (user.room_jid.as_unicode(), ref, uuid, opnum))

    def handle_incident_dionaea_modules_python_smb_dcerpc_bind(self, user, xmlobj):
        try:
            uuid = xmlobj.hasProp('uuid').content
            ref = xmlobj.hasProp('ref').content
            transfersyntax = xmlobj.hasProp('transfersyntax').content
            ref = int(ref)
        except Exception as e:
            print(e)
            return
        if dbh is not None and ref in user.attacks:
            attackid = user.attacks[ref][1]
            cursor.execute("INSERT INTO dionaea.dcerpcbinds (connection, dcerpcbind_uuid, dcerpcbind_transfersyntax) VALUES (%s,%s,%s)",
                           (attackid, uuid, transfersyntax))
        print("[%s] dcerpcbind ref %i: %s %s" %
              (user.room_jid.as_unicode(), ref, uuid, transfersyntax))

    def handle_incident_dionaea_modules_python_mysql_login(self, user, xmlobj):
        try:
            ref = xmlobj.hasProp('ref').content
            ref = int(ref)
            username = xmlobj.hasProp('username').content
            password = xmlobj.hasProp('password').content
        except Exception as e:
            print(e)
            return
        if dbh is not None and ref in user.attacks:
            attackid = user.attacks[ref][1]
            cursor.execute("INSERT INTO dionaea.logins (connection, login_username, login_password) VALUES (%s,%s,%s)",
                           (attackid, username, password))
        print("[%s] mysqllogin ref %i: %s %s" %
              (user.room_jid.as_unicode(), ref, username, password))

    def handle_incident_dionaea_modules_python_mysql_command(self, user, xmlobj):
        try:
            ref = xmlobj.hasProp('ref').content
            ref = int(ref)
            cmd = int(xmlobj.hasProp('cmd').content)
            args = []
            r = xpath_eval(
                xmlobj, './dionaea:args/dionaea:arg', namespaces=dionaea_ns)
            for i in r:
                args.append((i.hasProp('index').content, i.content))
        except Exception as e:
            print(e)
            return
        if dbh is not None and ref in user.attacks:
            attackid = user.attacks[ref][1]
            cursor.execute("INSERT INTO dionaea.mysql_commands (connection, mysql_command_cmd) VALUES (%s,%s)",
                           (attackid, cmd))
            r = cursor.execute(
                """SELECT CURRVAL('dionaea.mysql_commands_mysql_command_seq')""")
            command = cursor.fetchall()[0][0]

            for i in args:
                cursor.execute("INSERT INTO dionaea.mysql_command_args (mysql_command, mysql_command_arg_data, mysql_command_arg_index) VALUES (%s,%s,%s)",
                               (command, i[1], i[0]))

        print("[%s] mysqlcommand ref %i: %i %s" %
              (user.room_jid.as_unicode(), ref, cmd, args))

    def handle_incident_dionaea_modules_python_sip_command(self, user, xmlobj):
        def address_from_xml(e):
            address = {}
            display_name = e.hasProp('display_name')
            if display_name is not None:
                display_name = display_name.content
            address['display_name'] = display_name
            c = e.children
            while c is not None:
                if c.name == 'uri':
                    address['uri'] = uri_from_xml(c)
                c = c.next
            return address
        def uri_from_xml(e):
            d={}
            for u in ['scheme','user','password','port','host']:
                p = e.hasProp(u)
                if p is not None:
                    p = p.content
                d[u] = p
            return d
        def via_from_xml(e):
            via={}
            for u in ['address','port','protocol','port','host']:
                p = e.hasProp(u)
                if p is not None:
                    p = p.content
                via[u] = p
            return via

        def allow_from_xml(e):
            return e.content

        def sdp_from_xml(e):
            def media_from_xml(e):
                d = {}
                for u in ['proto','port','media','number_of_ports']:
                    p = e.hasProp(u)
                    if p is not None:
                        p = p.content
                    d[u] = p
                return d
            def connectiondata_from_xml(e):
                d={}
                for u in ['connection_address','number_of_addresses','addrtype','nettype','ttl']:
                    p = e.hasProp(u)
                    if p is not None:
                        p = p.content
                    d[u] = p
                return d
            def origin_from_xml(e):
                d={}
                for u in ['username','unicast_address','nettype','addrtype','sess_id','sess_version']:
                    p = e.hasProp(u)
                    if p is not None:
                        p = p.content
                    d[u] = p
                return d

            sdp = {}
            r = xpath_eval(
                xmlobj, './dionaea:sdp/dionaea:medialist/dionaea:media', namespaces=dionaea_ns)
            if len(r) > 0:
                medias = []
                for i in r:
                    medias.append(media_from_xml(i))
                sdp['m'] = medias

            r = xpath_eval(
                xmlobj, './dionaea:sdp/dionaea:origin', namespaces=dionaea_ns)
            if len(r) > 0:
                sdp['o'] = origin_from_xml(r[0])

            r = xpath_eval(
                xmlobj, './dionaea:sdp/dionaea:connectiondata', namespaces=dionaea_ns)
            if len(r) > 0:
                sdp['c'] = connectiondata_from_xml(r[0])
            return sdp


        try:
            ref = int(xmlobj.hasProp('ref').content)
            method = xmlobj.hasProp('method').content
            call_id = user_agent = addr = _from = to = contact = via = allow = sdp = None
            call_id = xmlobj.hasProp('call_id')
            if call_id is not None:
                call_id = call_id.content
            user_agent = xmlobj.hasProp('user_agent')
            if user_agent is not None:
                user_agent = user_agent.content

            r = xpath_eval(
                xmlobj, './dionaea:to/dionaea:addr', namespaces=dionaea_ns)
            if len(r) > 0:
                addr = address_from_xml(r[0])
#			print(addr)
            r = xpath_eval(
                xmlobj, './dionaea:from/dionaea:addr', namespaces=dionaea_ns)
            if len(r) > 0:
                _from = []
                for i in r:
                    _from.append(address_from_xml(i))
#			print(_from)

            r = xpath_eval(
                xmlobj, './dionaea:to/dionaea:addr', namespaces=dionaea_ns)
            if len(r) > 0:
                to = address_from_xml(r[0])
#			print(to)

            r = xpath_eval(
                xmlobj, './dionaea:vias/dionaea:via', namespaces=dionaea_ns)
            if len(r) > 0:
                via = []
                for i in r:
                    via.append(via_from_xml(i))
#			print(via)

            r = xpath_eval(
                xmlobj, './dionaea:allowlist/dionaea:allow', namespaces=dionaea_ns)
            if len(r) > 0:
                allow = []
                for i in r:
                    allow.append(allow_from_xml(i))
            print(allow)

            r = xpath_eval(xmlobj, './dionaea:sdp', namespaces=dionaea_ns)
            if len(r) > 0:
                sdp = sdp_from_xml(r[0])

#			print(sdp)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return
        if dbh is not None and ref in user.attacks:
            def calc_allow(a):
                if a is None:
                    return 0
                b={	b'UNKNOWN'	:(1<<0),
                    'ACK'		:(1<<1),
                    'BYE'		:(1<<2),
                    'CANCEL'	:(1<<3),
                    'INFO'		:(1<<4),
                    'INVITE'	:(1<<5),
                    'MESSAGE'	:(1<<6),
                    'NOTIFY'	:(1<<7),
                    'OPTIONS'	:(1<<8),
                    'PRACK'		:(1<<9),
                    'PUBLISH'	:(1<<10),
                    'REFER'		:(1<<11),
                    'REGISTER'	:(1<<12),
                    'SUBSCRIBE'	:(1<<13),
                    'UPDATE'	:(1<<14)
                    }
                allow=0
                for i in a:
                    if i in b:
                        allow |= b[i]
                    else:
                        allow |= b[b'UNKNOWN']
                return allow

            def add_addr(cmd, _type, addr):
                if addr is None:
                    return
                host = None
                from socket import inet_pton,AF_INET,AF_INET6
                try:
                    inet_pton(AF_INET, addr['uri']['host'])
                    host = addr['uri']['host']
                except:
                    pass
                try:
                    inet_pton(AF_INET6, addr['uri']['host'])
                    host = addr['uri']['host']
                except:
                    pass

                cursor.execute("""INSERT INTO dionaea.sip_addrs
					(sip_command, sip_addr_type, sip_addr_display_name,
					sip_addr_uri_scheme, sip_addr_uri_user, sip_addr_uri_password,
					sip_addr_uri_hostname, sip_addr_uri_host, sip_addr_uri_port) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                               (
                                   cmd, _type, addr['display_name'],
                                   addr['uri']['scheme'], addr['uri'][
                                       'user'], addr['uri']['password'],
                                   addr['uri']['host'], host, addr[
                                       'uri']['port']
                               ))

            def add_via(cmd, via):
                cursor.execute("""INSERT INTO dionaea.sip_vias
					(sip_command, sip_via_protocol, sip_via_address, sip_via_port)
					VALUES (%s,%s,%s,%s)""",
                               (
                                   cmd, via['protocol'],
                                   via['address'], via['port']

                               ))

            def add_sdp(cmd, sdp):
                def add_origin(cmd, o):
                    cursor.execute("""INSERT INTO dionaea.sip_sdp_origins
						(sip_command, sip_sdp_origin_username,
						sip_sdp_origin_sess_id, sip_sdp_origin_sess_version,
						sip_sdp_origin_nettype, sip_sdp_origin_addrtype,
						sip_sdp_origin_unicast_address)
						VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                                   (
                                       cmd, o['username'],
                                       o['sess_id'], o['sess_version'],
                                       o['nettype'], o['addrtype'],
                                       o['unicast_address']
                                   ))

                def add_condata(cmd, c):
                    cursor.execute("""INSERT INTO dionaea.sip_sdp_connectiondatas
						(sip_command, sip_sdp_connectiondata_nettype,
						sip_sdp_connectiondata_addrtype, sip_sdp_connectiondata_connection_address,
						sip_sdp_connectiondata_ttl, sip_sdp_connectiondata_number_of_addresses)
						VALUES (%s,%s,%s,%s,%s,%s)""",
                                   (
                                       cmd, c['nettype'],
                                       c['addrtype'], c['connection_address'],
                                       c['ttl'], c['number_of_addresses']
                                   ))

                def add_media(cmd, c):
                    cursor.execute("""INSERT INTO dionaea.sip_sdp_medias
						(sip_command, sip_sdp_media_media,
						sip_sdp_media_port, sip_sdp_media_number_of_ports,
						sip_sdp_media_proto)
						VALUES (%s,%s,%s,%s,%s)""",
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

            attackid = user.attacks[ref][1]
            cursor.execute("""INSERT INTO dionaea.sip_commands
				(connection, sip_command_method, sip_command_call_id,
				sip_command_user_agent, sip_command_allow) VALUES (%s,%s,%s,%s,%s)""",
                           (attackid, method, call_id, user_agent, calc_allow(allow)))

            r = cursor.execute(
                """SELECT CURRVAL('dionaea.sip_commands_sip_command_seq')""")
            cmdid = cursor.fetchall()[0][0]


            add_addr(cmdid,'addr',addr)
            add_addr(cmdid,'to',to)
            add_addr(cmdid,'contact',contact)
            for i in _from:
                add_addr(cmdid,'from',i)

            for i in via:
                add_via(cmdid, i)

            if sdp is not None:
                add_sdp(cmdid,sdp)

        print("[%s] sipcommand ref %i: %s %s" %
              (user.room_jid.as_unicode(), ref, method, addr))



class Client(JabberClient):
    """Simple bot (client) example. Uses `pyxmpp.jabber.client.JabberClient`
    class as base. That class provides basic stream setup (including
    authentication) and Service Discovery server. It also does server address
    and port discovery based on the JID provided."""

    def __init__(self, jid, password):

        # if bare JID is provided add a resource -- it is required
        if not jid.resource:
            print(jid.resource)
            jid=JID(jid.node, jid.domain, "Echobot")

        # setup client with provided connection information
        # and identity data
        JabberClient.__init__(self, jid, password,
                              disco_name="PyXMPP example: echo bot", disco_type="bot", keepalive=10)

        # register features to be announced via Service Discovery
        self.disco_info.add_feature("jabber:iq:version")
        self.muc = []

    def stream_state_changed(self,state,arg):
        """This one is called when the state of stream connecting the component
        to a server changes. This will usually be used to let the user
        know what is going on."""
        print("*** State changed: %s %r ***" % (state,arg))

    def session_started(self):
        """This is called when the IM session is successfully started
        (after all the neccessery negotiations, authentication and
        authorizasion).
        That is the best place to setup various handlers for the stream.
        Do not forget about calling the session_started() method of the base
        class!"""
        JabberClient.session_started(self)

        # set up handlers for supported <iq/> queries
        self.stream.set_iq_get_handler(
            "query","jabber:iq:version",self.get_version)

        # set up handlers for <presence/> stanzas
        self.stream.set_presence_handler("available",self.presence)
        self.stream.set_presence_handler("subscribe",self.presence_control)
        self.stream.set_presence_handler("subscribed",self.presence_control)
        self.stream.set_presence_handler("unsubscribe",self.presence_control)
        self.stream.set_presence_handler("unsubscribed",self.presence_control)

        # set up handler for <message stanza>
        self.stream.set_message_handler("normal",self.message)
        print(self.stream)

        print(u"joining...")
        self.roommgr = MucRoomManager(self.stream)
        self.roommgr.set_handlers()
        nick = self.jid.node + '-' + self.jid.resource
        #['anon-events@dionaea.sensors.carnivore.it','anon-files@dionaea.sensors.carnivore.it']:
        for loc in options.channels:
            roomjid = JID(loc, options.muc)
            print("\t %s" % roomjid.as_unicode())
            h = RoomHandler()
            self.muc.append(h)
            mucstate = self.roommgr.join(roomjid, nick, h)
            h.assign_state(mucstate)


    def get_version(self,iq):
        """Handler for jabber:iq:version queries.

        jabber:iq:version queries are not supported directly by PyXMPP, so the
        XML node is accessed directly through the libxml2 API.  This should be
        used very carefully!"""
        iq=iq.make_result_response()
        q=iq.new_query("jabber:iq:version")
        q.newTextChild(q.ns(),"name","Echo component")
        q.newTextChild(q.ns(),"version","1.0")
        self.stream.send(iq)
        return True

    def message(self,stanza):
        """Message handler for the component.

        Echoes the message back if its type is not 'error' or
        'headline', also sets own presence status to the message body. Please
        note that all message types but 'error' will be passed to the handler
        for 'normal' message unless some dedicated handler process them.

        :returns: `True` to indicate, that the stanza should not be processed
        any further."""
        subject=stanza.get_subject()
        body=stanza.get_body()
        t=stanza.get_type()
        print(u'Message from %s received.' % (unicode(stanza.get_from(),)))
        return True

    def presence(self,stanza):
        """Handle 'available' (without 'type') and 'unavailable' <presence/>."""
        msg=u"%s has become " % (stanza.get_from())
        t=stanza.get_type()
        if t=="unavailable":
            msg+=u"unavailable"
        else:
            msg+=u"available"

        show=stanza.get_show()
        if show:
            msg+=u"(%s)" % (show,)

        status=stanza.get_status()
        if status:
            msg+=u": "+status
        print(msg)

    def presence_control(self,stanza):
        """Handle subscription control <presence/> stanzas -- acknowledge
        them."""
        msg=unicode(stanza.get_from())
        t=stanza.get_type()
        if t=="subscribe":
            msg+=u" has requested presence subscription."
        elif t=="subscribed":
            msg+=u" has accepted our presence subscription request."
        elif t=="unsubscribe":
            msg+=u" has canceled his subscription of our."
        elif t=="unsubscribed":
            msg+=u" has canceled our subscription of his presence."

        print(msg)
        p=stanza.make_accept_response()
        self.stream.send(p)
        return True

    def print_roster_item(self,item):
        if item.name:
            name=item.name
        else:
            name=u""
        print(u'%s "%s" subscription=%s groups=%s'
               % (unicode(item.jid), name, item.subscription,
                  u",".join(item.groups)) )

    def roster_updated(self,item=None):
        if not item:
            print(u"My roster:")
            for item in self.roster.get_items():
                self.print_roster_item(item)
            return
        print(u"Roster item updated:")
        self.print_roster_item(item)

# XMPP protocol is Unicode-based to properly display data received
# _must_ convert it to local encoding or UnicodeException may be raised
locale.setlocale(locale.LC_CTYPE,"")
encoding=locale.getlocale()[1]
if not encoding:
    encoding="us-ascii"
sys.stdout=codecs.getwriter(encoding)(sys.stdout,errors="replace")
sys.stderr=codecs.getwriter(encoding)(sys.stderr,errors="replace")

p = optparse.OptionParser()
p.add_option('-U', '--username', dest='username',
             help='user e.g. user@example.com', type="string", action="store")
p.add_option('-R', '--resource', dest='resource', default="backend",
             help='e.g. backend', type="string", action="store")
p.add_option('-P', '--password', dest='password',
             help='e.g. secret', type="string", action="store")
p.add_option('-M', '--muc', dest='muc',
             help='conference.example.com', type="string", action="store")
p.add_option('-C', '--channel', dest='channels',
             help='conference.example.com', type="string", action="append")
p.add_option('-s', '--database-host', dest='database_host',
             help='localhost:5432', type="string", action="store")
p.add_option('-d', '--database', dest='database',
             help='for example xmpp', type="string", action="store")
p.add_option('-u', '--database-user', dest='database_user',
             help='for example xmpp', type="string", action="store")
p.add_option('-p', '--database-password', dest='database_password',
             help='the database users password', type="string", action="store")
p.add_option('-f', '--files-destination', dest='files',
             help='where to store new files', type="string", action="store")
(options, args) = p.parse_args()

if not options.username or not options.resource or not options.password:
    print("Missing credentials")

if options.database_host and options.database and options.database_user and options.database_password:
    print("Connecting to the database")
    dbh = PgSQL.connect(host=options.database_host,
                        user=options.database_user, password=options.database_password)
    dbh.autocommit = 1
    cursor = dbh.cursor()
else:
    print("Not connecting to the database, are you sure?")
    dbh = None

if not options.files:
    print("Not storing files, are you sure?")

while True:
    print(u"creating client... %s" % options.resource)
    c=Client(JID(options.username + '/' + options.resource),options.password)

    print(u"connecting...")
    c.connect()

    print(u"looping...")
    try:
        # Component class provides basic "main loop" for the applitation
        # Though, most applications would need to have their own loop and call
        # component.stream.loop_iter() from it whenever an event on
        # component.stream.fileno() occurs.
        c.loop(1)
        c.idle()
    except KeyboardInterrupt:
        print(u"disconnecting...")
        c.disconnect()
        print(u"exiting...")
        break
    except Exception as e:
        import traceback
        traceback.print_exc()
        continue


# vi: sts=4 et sw=4
