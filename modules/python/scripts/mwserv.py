#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2010  Mark Schloesser
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

from dionaea.core import ihandler, incident, g_dionaea
from dionaea.util import sha512file
from dionaea import pyev

import logging
import uuid

logger = logging.getLogger('mwserv')
logger.setLevel(logging.DEBUG)

class mwserv_report:
    def __init__(self, sha512h, filepath):
        self.sha512h, self.filepath = sha512h, filepath
        self.saddr, self.sport, self.daddr, self.dport = ('', )*4
        self.download_url = ''


class mwservhandler(ihandler):
    def __init__(self, path):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)
        mwsconfig = g_dionaea.config()['modules']['python']['mwserv']
        self.backendurl = mwsconfig['url']
        self.maintainer = mwsconfig['maintainer']
        self.guid = mwsconfig['guid']
        self.secret = mwsconfig['secret']
        self.cookies = {}

        # heartbeats
        dinfo = g_dionaea.version()
        self.software = 'dionaea {0} {1}/{2} - {3} {4}'.format(
            dinfo['dionaea']['version'],
            dinfo['compiler']['os'],
            dinfo['compiler']['arch'],
            dinfo['compiler']['date'],
            dinfo['compiler']['time'],
        )
        self.loop = pyev.default_loop()
        self.heartbeat_timer = pyev.Timer(5., 120, self.loop, self._heartbeat)
        self.heartbeat_timer.start()

    def stop(self):
        self.heartbeat_timer.stop()
        self.heartbeat_timer = None
        self.loop = None


    def _heartbeat(self, events, data):
        logger.info("mwserv _heartbeat")
        i = incident("dionaea.upload.request")
        i._url = self.backendurl + 'heartbeat'
        i.maintainer = self.maintainer
        i.guid = self.guid
        i.secret = self.secret
        i.software = self.software

        i._callback = "dionaea.modules.python.mwserv.heartbeatresult"
        i.report()

    def handle_incident(self, icd):
        pass

    def handle_incident_dionaea_download_complete_unique(self, icd):
        cookie = str(uuid.uuid4())

        i = incident("dionaea.upload.request")
        i._url = self.backendurl + 'nepenthes/submit'

        i.sha512 = sha512file(icd.file)
        i.maintainer = self.maintainer
        i.guid = self.guid
        i.secret = self.secret

        mr = mwserv_report(i.sha512, icd.file)

        if hasattr(icd, 'con'):
            i.saddr = icd.con.remote.host
            i.sport = str(icd.con.remote.port)
            i.daddr = icd.con.local.host
            i.dport = str(icd.con.local.port)
            mr.saddr, mr.sport, mr.daddr, mr.dport = i.saddr, i.sport, i.daddr, i.dport
        if hasattr(icd, 'url'):
            i.url = icd.url
            mr.download_url = icd.url

        i._callback = "dionaea.modules.python.mwserv.result"
        i._userdata = cookie

        self.cookies[cookie] = mr
        i.report()

    # handle agains in the same way
    handle_incident_dionaea_download_complete_again = handle_incident_dionaea_download_complete_unique

    def handle_incident_dionaea_modules_python_mwserv_result(self, icd):
        fh = open(icd.path, mode="rb")
        c = fh.read()
        logger.info("mwserv result: {0}".format(c))

        cookie = icd._userdata
        mr = self.cookies[cookie]

        # does backend want us to upload?
        if b'UNKNOWN' in c:
            i = incident("dionaea.upload.request")
            i._url = self.backendurl + 'nepenthes/submit'

            i.sha512 = mr.sha512h
            i.maintainer = self.maintainer
            i.guid = self.guid
            i.secret = self.secret

            i.set('file://data', mr.filepath)

            i.saddr = mr.saddr
            i.sport = mr.sport
            i.daddr = mr.daddr
            i.dport = mr.dport
            i.url = mr.download_url

            i._callback = "dionaea.modules.python.mwserv.uploadresult"
            i._userdata = cookie

            i.report()
        else:
            del self.cookies[cookie]

    def handle_incident_dionaea_modules_python_mwserv_uploadresult(self, icd):
        fh = open(icd.path, mode="rb")
        c = fh.read()
        logger.info("mwserv uploadresult: {0}".format(c))

        del self.cookies[icd._userdata]

    def handle_incident_dionaea_modules_python_mwserv_heartbeatresult(self, icd):
        fh = open(icd.path, mode="rb")
        c = fh.read()
        logger.info("mwserv heartbeatresult: {0}".format(c))
