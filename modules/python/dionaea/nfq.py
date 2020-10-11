# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from socket import AF_INET, AF_INET6
from time import time
from dionaea import IHandlerLoader
from dionaea.core import ihandler, incident, connection, g_dionaea

import logging

logger = logging.getLogger('nfq')
logger.setLevel(logging.DEBUG)


class NFQHandlerLoader(IHandlerLoader):
    name = "nfq"

    @classmethod
    def start(cls, config=None):
        return nfqhandler(config=config)


def is_local_addr(addr):
    # sanatize addr, maybe IPv4 mapped
    # I think it is impossible to connect yourself via
    # IPv4 mapped IPv6 sockets, but ...
    if addr.startswith('::ffff:'):
        addr = addr[7:]

    # getifaddrs and compile a dict of addrs assigned to the host
    ifaddrs = g_dionaea.getifaddrs()

    vX = {}
    for iface in ifaddrs:
        for family in ifaddrs[iface]:
            if family != AF_INET and family != AF_INET6:
                continue
            for i in ifaddrs[iface][family]:
                if 'addr' in i:
                    vX[i['addr']] = iface


    if addr in vX:
        return True
    return False


class nfqmirrorc(connection):
    def __init__(self, peer=None):
        logger.debug("nfqmirror connection %s %s" %
                     ( peer.remote.host, peer.local.host))
        connection.__init__(self,peer.transport)
        self.bind(peer.local.host,0)
        self.connect(peer.remote.host,peer.local.port)
        self.peer = peer

    def handle_established(self):
        self.peer.peer = self

    def handle_io_in(self, data):
        if self.peer:
            self.peer.send(data)
        return len(data)

    def handle_error(self, err):
        if self.peer:
            self.peer.peer = None
            self.peer.close()

    def handle_disconnect(self):
        if self.peer:
            self.peer.close()
        if self.peer:
            self.peer.peer = None
        return 0

class nfqmirrord(connection):
    def __init__(self, proto=None):
        connection.__init__(self,proto)
        self.peer=None

    def handle_established(self):
        self.processors()

        self.timeouts.sustain = 60
        self._in.accounting.limit  = 200*1024
        self._out.accounting.limit = 200*1024

        if is_local_addr(self.remote.host) == False:
            self.peer=nfqmirrorc(self)
            # problem:
            # the parent connection just got accepted
            # we are in the established callback for this connection
            # this connection did not report its dionaea.connection.tcp.accept incident yet
            # therefore this connection is not 'known' to logsql yet
            # but we want to associate the incoming mirror connection with the outgoing mirror connection
            # therefore we claim this is an 'early' link
            # so logsql can notice this connection has a parent, but the parent is not known yet
            # once the parent is known, we logsql will update the parent record
            # for this connection
            i = incident('dionaea.connection.link.early')
            i.parent = self
            i.child = self.peer
            i.report()
        else:
            logger.warning("closing local connection from %s" %
                           self.remote.host)
            self.close()


    def handle_io_in(self, data):
        if self.peer:
            self.peer.send(data)
        return len(data)

    def handle_error(self, err):
        logger.debug("mirrord connection error?, should not happen")
        if self.peer:
            self.peer.peer = None

    def handle_disconnect(self):
        if self.peer:
            self.peer.close()
        if self.peer:
            self.peer.peer = None
        return 0

class nfqhandler(ihandler):
    def __init__(self, config=None):
        logger.debug("nfqhandler")
        ihandler.__init__(self, 'dionaea.connection.tcp.pending')

        if config is None:
            config = {}

        config_throttle = config.get("throttle", {})
        self.throttle_window = config_throttle.get("window", 30)
        self.window = [[0, 0] for x in range(self.throttle_window)]

        self.throttle_nfaction = config.get("nfaction", 0)
        config_throttle_limits = config_throttle.get("limits", {})
        self.throttle_total = config_throttle_limits.get("total", 30)
        self.throttle_slot = config_throttle_limits.get("slot", 30)

        config_timeouts = config.get("timeouts", {})
        config_timeouts_client = config_timeouts.get("client", {})
        self.mirror_client_timeout_idle = config_timeouts_client.get("idel", 10)
        self.mirror_client_timeout_sustain = config_timeouts_client.get("sustain", 240)
        config_timeouts_server = config_timeouts.get("server", {})
        self.mirror_server_timeout_listen = config_timeouts_server.get("listen", 5)

    def handle_incident(self, icd):
        if icd.origin == 'dionaea.connection.tcp.pending':
            con = icd.con

            lhost = con.local.host
            rhost = con.remote.host

            # avoid connecting yourself
            if False and is_local_addr(rhost):
                logger.warn("avoid self connect")
                return

            # throttle incoming SYN's
            # else port scans will consume *many* sockets
            # and things go wild&bad


            now = int(time())
            nmt = now % self.throttle_window

            if self.window[nmt][0] != now:
                #				logger.debug("New Tick")
                # we got a new tick
                for i in range(self.throttle_window):
                    # for all other ticks
                    # check the tick is 'up2date'
                    # replace outdated ticks with 0
                    nmx = (now-i)%self.throttle_window
                    if self.window[nmx][0] != now-i:
                        #						logger.debug("Reset window {:d} (was {:d}".format(i,self.window[nmx][1]))
                        self.window[nmx] = [now-i,0]

            total = sum([ x[1] for x in self.window])
            if total > self.throttle_total:
                logger.warn("throttle total %i %s" % (total,rhost))
                icd.nfaction = self.throttle_nfaction
                return
            if self.window[nmt][1] > self.throttle_slot:
                logger.warn("throttle slot %i %s" %
                            (self.window[nmt][1], rhost) )
                icd.nfaction = self.throttle_nfaction
                return

            # finally, start a service on the port
            m = nfqmirrord('tcp')
            m.timeouts.listen = self.mirror_server_timeout_listen
            m.timeouts.idle = self.mirror_client_timeout_idle
            m.timeouts.sustain = self.mirror_client_timeout_sustain

            m.bind(lhost, con.local.port)
            if m.listen() != True:
                m.close()
                return

            logger.info("doing nfq on port %i" % con.local.port)
            self.window[nmt] = [now,self.window[nmt][1]+1]


            i = incident('dionaea.connection.link')
            i.parent = con
            i.child = m
            i.report()
