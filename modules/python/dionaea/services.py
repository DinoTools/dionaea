# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009  Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import fnmatch

from dionaea.core import g_dionaea, ihandler
from dionaea import ServiceLoader, load_config_from_files, load_submodules


logger = logging.getLogger('services')

# global slave
# keeps track of running services (daemons)
# able to restart them
g_slave = None

g_service_configs = []


class slave():
    def __init__(self, addresses=None):
        self.addresses = addresses
        self.services = []
        self.daemons = {}

    def start(self):
        for iface in self.addresses:
            logger.info("Starting services on interface %s ...", iface)
            for addr in self.addresses[iface]:
                logger.info("Bind interfaces to address '%s' ...", addr)
                self.daemons[addr] = {}
                for srv in g_service_configs:
                    for service in ServiceLoader:
                        if srv.get("name") != service.name:
                            continue
                        if service not in self.daemons[addr]:
                            self.daemons[addr][service] = []

                        try:
                            daemons = service.start(addr, iface=iface, config=srv.get("config", {}))
                        except Exception as e:
                            logger.warning("Unable to start service", exc_info=True)
                            continue
                        if isinstance(daemons, (list, tuple)):
                            self.daemons[addr][service] += daemons
                        elif daemons is not None:
                            self.daemons[addr][service].append(daemons)


# for netlink,
# allows listening on new addrs
# and discarding listeners on closed addrs
class nlslave(ihandler):
    def __init__(self, ifaces=None):
        ihandler.__init__(self, "dionaea.*.addr.*")
        self.ifaces = ifaces
        self.services = []
        self.daemons = {}

    def handle_incident(self, icd):
        print("SERVANT!\n")
        addr = icd.get("addr")
        iface = icd.get("iface")
        for i in self.ifaces:
            print("iface:{} pattern:{}".format(iface, i))
            if fnmatch.fnmatch(iface, i):
                if icd.origin == "dionaea.module.nl.addr.new" or "dionaea.module.nl.addr.hup":
                    self.daemons[addr] = {}
                    for srv in g_service_configs:
                        for service in ServiceLoader:
                            if srv.get("name") != service.name:
                                continue
                            if service not in self.daemons[addr]:
                                self.daemons[addr][service] = []
                            print(service)
                            try:
                                daemons = service.start(addr, iface=iface, config=srv.get("config", {}))
                            except Exception as e:
                                logger.warning("Unable to start service", exc_info=True)
                                continue
                            if isinstance(daemons, (list, tuple)):
                                self.daemons[addr][service] += daemons
                            else:
                                self.daemons[addr][service].append(daemons)

                if icd.origin == "dionaea.module.nl.addr.del":
                    print(icd.origin)
                    for s in self.daemons[addr]:
                        for d in self.daemons[addr][s]:
                            s.stop(s, d)
                break

    def start(self):
        pass


#mode = 'getifaddrs'
#mode = 'manual'
#addrs = { 'eth0' : ['127.0.0.1', '192.168.47.11'] }
#def start():
#    global g_slave, mode, addrs
#    global addrs
#    g_slave.start(addrs)


def new():
    global g_slave
    global g_service_configs

    logger.info("Initializing services ...")
    dionaea_config = g_dionaea.config().get("dionaea")

    mode = dionaea_config.get("listen.mode")
    interface_names = dionaea_config.get("listen.interfaces")

    if mode == 'manual':
        addrs = {}
        whildcard_addresses = {'0.0.0.0', '::'}

        addresses = dionaea_config.get("listen.addresses")
        ifaces = g_dionaea.getifaddrs()
        if whildcard_addresses.intersection(addresses):
            listen_ifaces = dionaea_config.get("listen.interfaces")
            if listen_ifaces is not None:
                for iface in listen_ifaces:
                    if iface not in addrs:
                        addrs[iface] = []
                    for whildcard_address in whildcard_addresses.intersection(addresses):
                        addrs[iface].append(whildcard_address)
            else:
                for iface in ifaces.keys():
                    if iface not in addrs:
                        addrs[iface] = []
                    for whildcard_address in whildcard_addresses.intersection(addresses):
                        addrs[iface].append(whildcard_address)

        for iface in ifaces.keys():
            afs = ifaces[iface]
            for af in afs.keys():
                if af == 2 or af == 10:
                    configs = afs[af]
                    if iface not in addrs:
                        addrs[iface] = []
                    for config in configs:
                        if config["addr"] in addresses:
                            addrs[iface].append(config['addr'])
        g_slave = slave(addresses=addrs)
    elif mode == 'getifaddrs':
        ifaces = g_dionaea.getifaddrs()
        addrs = {}
        for iface in ifaces.keys():
            if interface_names is not None and iface not in interface_names:
                logger.debug("Skipping interface %s. Not in interface list.", iface)
                continue
            afs = ifaces[iface]
            for af in afs.keys():
                if af == 2 or af == 10:
                    configs = afs[af]
                    for config in configs:
                        if iface not in addrs:
                            addrs[iface] = []
                        addrs[iface].append(config['addr'])
        g_slave = slave(addresses=addrs)
    elif mode == 'nl':
        # ToDo: handle error if ifaces is None
        g_slave = nlslave(ifaces=interface_names)

    load_submodules()

    module_config = g_dionaea.config().get("module")
    filename_patterns = module_config.get("service_configs", [])
    g_service_configs = load_config_from_files(filename_patterns)


def start():
    logger.info("Starting services ...")
    g_slave.start()


def stop():
    logger.info("Stopping services ...")
    global g_slave
    for addr in g_slave.daemons:
        for s in g_slave.daemons[addr]:
            for d in g_slave.daemons[addr][s]:
                s.stop(d)
    del g_slave
