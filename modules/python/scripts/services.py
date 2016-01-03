#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter
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


import logging
import fnmatch

from dionaea.core import g_dionaea, ihandler
from dionaea import ServiceLoader, load_submodules


logger = logging.getLogger('services')

# global slave
# keeps track of running services (daemons)
# able to restart them
global g_slave
global addrs


class slave():
    def __init__(self):
        self.services = []
        self.daemons = {}

    def start(self, addrs):
        print("STARTING SERVICES")
        try:
            for iface in addrs:
                print(iface)
                for addr in addrs[iface]:
                    print(addr)
                    self.daemons[addr] = {}
                    for service in ServiceLoader:
                        if service.name not in g_dionaea.config()['modules']['python']['services']['serve']:
                            continue
                        if service not in self.daemons[addr]:
                            self.daemons[addr][service] = []
                        print(service)
                        daemons = service.start(addr, iface=iface)
                        if isinstance(daemons, (list, tuple)):
                            self.daemons[addr][service] += daemons
                        else:
                            self.daemons[addr][service].append(daemons)
        except Exception as e:
            raise e
        print(self.daemons)


# for netlink,
# allows listening on new addrs
# and discarding listeners on closed addrs
class nlslave(ihandler):
    def __init__(self):
        ihandler.__init__(self, "dionaea.*.addr.*")
        self.services = []
        self.daemons = {}
    def handle_incident(self, icd):
        print("SERVANT!\n")
        addr = icd.get("addr")
        iface = icd.get("iface")
        for i in self.ifaces:
            print("iface:{} pattern:{}".format(iface,i))
            if fnmatch.fnmatch(iface, i):
                if icd.origin == "dionaea.module.nl.addr.new" or "dionaea.module.nl.addr.hup":
                    self.daemons[addr] = {}
                    for s in self.services:
                        self.daemons[addr][s] = []
                        d = s.start(s, addr, iface=iface)
                        self.daemons[addr][s].append(d)
                if icd.origin == "dionaea.module.nl.addr.del":
                    print(icd.origin)
                    for s in self.daemons[addr]:
                        for d in self.daemons[addr][s]:
                            s.stop(s, d)
                break

    def start(self, addrs):
        pass


#mode = 'getifaddrs'
#mode = 'manual'
#addrs = { 'eth0' : ['127.0.0.1', '192.168.47.11'] }
mode = g_dionaea.config()['listen']['mode']
addrs = {}
ifaces = None
#def start():
#    global g_slave, mode, addrs
#    global addrs
#    g_slave.start(addrs)


def new():
    print("START")
    global g_slave, mode, addrs
    global addrs
    if mode == 'manual':
        addrs = g_dionaea.config()['listen']['addrs']
        g_slave = slave()
    elif mode == 'getifaddrs':
        g_slave = slave()
        ifaces = g_dionaea.getifaddrs()
        addrs = {}
        for iface in ifaces.keys():
            afs = ifaces[iface]
            for af in afs.keys():
                if af == 2 or af == 10:
                    configs = afs[af]
                    for config in configs:
                        if iface not in addrs:
                            addrs[iface] = []
                        addrs[iface].append(config['addr'])
        print(addrs)
    elif mode == 'nl':
        g_slave = nlslave()
        g_slave.ifaces = g_dionaea.config()['listen']['interfaces']

    load_submodules()


def start():
    g_slave.start(addrs)


def stop():
    print("STOP")
    global g_slave
    for addr in g_slave.daemons:
        for s in g_slave.daemons[addr]:
            for d in g_slave.daemons[addr][s]:
                s.stop(s, d)
    del g_slave
