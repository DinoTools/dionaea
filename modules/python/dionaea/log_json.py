# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from datetime import datetime
import json
import logging
from urllib.parse import urlparse

from dionaea import IHandlerLoader
from dionaea.core import ihandler
from dionaea.exception import LoaderError


logger = logging.getLogger("log_json")
logger.setLevel(logging.DEBUG)


class FileHandler(object):
    handle_schemes = ["file"]

    def __init__(self, url):
        self.url = url
        url = urlparse(url)
        try:
            self.fp = open(url.path, "a")
        except OSError as e:
            raise LoaderError("Unable to open file %s Error message '%s'", url.path, e.strerror)

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
    def start(cls, config=None):
        try:
            return LogJsonHandler("*", config=config)
        except LoaderError as e:
            logger.error(e.msg, *e.args)


class LogJsonHandler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!", self.__class__.__name__)
        ihandler.__init__(self, path)
        self.path = path
        self._config = config
        self.db_session = None

        self.attacks = {}
        self.handlers = []
        self.flat_data = config.get("flat_data", False)
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
            "password": self._prepare_value(icd.password),
            "username": self._prepare_value(icd.username)
        }

        if "credentials" not in data:
            data["credentials"] = []
        data["credentials"].append(credentials)

    def _flatten_data(self, data):
        # Add more if needed
        for k in [
            "credentials",
            "ftp.commands"
        ]:
            d = None
            d2 = data
            k2 = ""
            for k2 in k.split("."):
                d = d2
                d2 = d.get(k2)
                if d2 is None:
                    break
            if d is None or d2 is None:
                continue
            d[k2] = self._flatten_list(d2)
        return data

    def _flatten_list(self, objs):
        result = {}
        keys = set()
        for obj in objs:
            keys = keys | set(obj.keys())
        for key in keys:
            result[key] = []
        for obj in objs:
            for key in keys:
                v = obj.get(key)
                # eleasticsearch can not handle arrays that contain arrays
                # flatten the arrays by joining the subarrays
                if isinstance(v, (tuple, list)):
                    v = " ".join(v)
                result[key].append(v)
        return result

    def _prepare_value(self, v):
        """
        Prepare value to be JSON compatible.

        :param v: The value to prepare.
        :return: The prepared value
        """
        if isinstance(v, bytes):
            return v.decode(encoding="utf-8", errors="replace")
        return v

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
            "src_hostname": self._prepare_value(con.remote.hostname),
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
                if self.flat_data:
                    data = self._flatten_data(data)
                for handler in self.handlers:
                    handler.submit(data)
            del self.attacks[con]
        else:
            logger.warn("no attack data for %s:%s" % (con.local.host, con.local.port))

    def handle_incident_dionaea_modules_python_ftp_command(self, icd):
        con = icd.con
        data = self.attacks.get(con)
        if not data:
            # ToDo: warning
            return

        if "ftp" not in data:
            data["ftp"] = {}
        if "commands" not in data["ftp"]:
            data["ftp"]["commands"] = []

        data["ftp"]["commands"].append({
            "command": self._prepare_value(icd.command),
            "arguments": self._prepare_value(icd.arguments)
        })

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
