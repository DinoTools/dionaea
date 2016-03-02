#################################################################################
#                                Dionaea
#                            - catches bugs -
#
#  Copyright (c) 2016 PhiBo (DinoTools)
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
################################################################################

from datetime import datetime
import json
import logging
from urllib.parse import urlparse

from dionaea import IHandlerLoader
from dionaea.core import ihandler

logger = logging.getLogger("log_json")
logger.setLevel(logging.DEBUG)


class FileHandler(object):
    handle_schemes = ["file"]

    def __init__(self, url):
        self.url = url
        url = urlparse(url)
        self.fp = open(url.path, "a")

    def submit(self, data):
        data = json.dumps(data)
        self.fp.write(data)
        self.fp.write("\n")
        self.fp.flush()


class HTTPHandler(object):
    handle_schemes = ["http", "https"]

    def __init__(self, url):
        self.url = url

    def submit(self, data):
        from urllib.request import Request, urlopen
        data = json.dumps(data)
        data = data.encode("ASCII")
        req = Request(
            self.url,
            data=data,
            headers={
                "Content-Type": "application/json"
            }
        )
        # ToDo: parse response
        response = urlopen(req)
        # Debug:
        #from pprint import pprint
        #pprint(response)


class LogJsonHandlerLoader(IHandlerLoader):
    name = "log_json"

    @classmethod
    def start(cls):
        from dionaea.core import g_dionaea
        conf_mod_py = g_dionaea.config()["modules"]["python"]
        config = conf_mod_py.get("log_json")
        handlers = [LogJsonHandler("*", config=config)]
        return handlers


class LogJsonHandler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!", self.__class__.__name__)
        ihandler.__init__(self, path)
        self.path = path
        self._config = config
        self.db_session = None

        self.attacks = {}
        self.handlers = []
        handlers = config.get("handlers")
        if not isinstance(handlers, list) or len(handlers) == 0:
            logger.warning("No handlers specified")
            # Set empty list on error
            handlers = []

        for handler in handlers:
            url = urlparse(handler)
            for h in (FileHandler, HTTPHandler,):
                if url.scheme in h.handle_schemes:
                    self.handlers.append(h(url=handler))
                    break

    def handle_incident(self, icd):
        #        print("unknown")
        pass

    def _append_credentials(self, icd):
        con = icd.con
        data = self.attacks.get(con)
        if not data:
            # ToDo: warning
            return

        credentials = {
            "password": icd.password,
            "username": icd.username
        }

        if "credentials" not in data:
            data["credentials"] = []
        data["credentials"].append(credentials)

    def _serialize_connection(self, icd, connection_type):
        con = icd.con

        data = {
            "connection": {
                "protocol": con.protocol,
                "transport": con.transport,
                "type": connection_type
            },
            "dst_ip": con.local.host,
            "dst_port": con.local.port,
            "src_hostname": con.remote.hostname,
            "src_ip": con.remote.host,
            "src_port": con.remote.port,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.attacks[con] = data

    def handle_incident_dionaea_connection_tcp_listen(self, icd):
        self._serialize_connection(icd, "listen")
        con = icd.con
        logger.info("listen connection on %s:%i" % (con.remote.host, con.remote.port))

    def handle_incident_dionaea_connection_tls_listen(self, icd):
        self._serialize_connection(icd, "listen")
        con = icd.con
        logger.info("listen connection on %s:%i" % (con.remote.host, con.remote.port))

    def handle_incident_dionaea_connection_tcp_connect(self, icd):
        self._serialize_connection(icd, "connect")
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i" % (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port))

    def handle_incident_dionaea_connection_tls_connect(self, icd):
        self._serialize_connection(icd, "connect")
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i" % (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port))

    def handle_incident_dionaea_connection_udp_connect(self, icd):
        self._serialize_connection(icd, "connect")
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i" % (con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port))

    def handle_incident_dionaea_connection_tcp_accept(self, icd):
        self._serialize_connection(icd, "accept")
        con = icd.con
        logger.info("accepted connection from %s:%i to %s:%i" % (con.remote.host, con.remote.port, con.local.host, con.local.port))

    def handle_incident_dionaea_connection_tls_accept(self, icd):
        self._serialize_connection(icd, "accept")
        con = icd.con
        logger.info("accepted connection from %s:%i to %s:%i" % (con.remote.host, con.remote.port, con.local.host, con.local.port))

    def handle_incident_dionaea_connection_tcp_reject(self, icd):
        self._serialize_connection(icd, "reject")
        con = icd.con
        logger.info("reject connection from %s:%i to %s:%i" % (con.remote.host, con.remote.port, con.local.host, con.local.port))

    def handle_incident_dionaea_connection_free(self, icd):
        con = icd.con
        if con in self.attacks:
            data = self.attacks.get(con)
            if data:
                for handler in self.handlers:
                    handler.submit(data)
            del self.attacks[con]
        else:
            logger.warn("no attack data for %s:%s" % (con.local.host, con.local.port))

    def handle_incident_dionaea_modules_python_ftp_login(self, icd):
        self._append_credentials(icd)

    def handle_incident_dionaea_modules_python_mssql_login(self, icd):
        self._append_credentials(icd)

    def handle_incident_dionaea_modules_python_mysql_login(self, icd):
        self._append_credentials(icd)

    def handle_incident_dionaea_modules_python_p0f(self, icd):
        con = icd.con
        data = self.attacks.get(con)
        if data:
            data["p0f"] = {
                "detail": icd.detail,
                "dist": icd.dist,
                "fw": icd.fw,
                "genre": icd.genre,
                "link": icd.link,
                "nat": icd.nat,
                "tos": icd.tos,
                "uptime": icd.uptime
            }
