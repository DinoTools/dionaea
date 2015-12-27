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


from dionaea.core import ihandler, g_dionaea

import logging
import datetime

logger = logging.getLogger('fail2ban')
logger.setLevel(logging.DEBUG)

class fail2banhandler(ihandler):
    def __init__(self):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, "*")
        offers = g_dionaea.config()['modules']['python']['fail2ban']['offers']
        downloads = g_dionaea.config()['modules']['python'][
            'fail2ban']['downloads']
        self.offers = open(offers, "a")
        self.downloads = open(downloads, "a")

    def handle_incident_dionaea_download_offer(self, icd):
        data = "%s %s %s %s\n" % (datetime.datetime.now().isoformat(
        ), icd.con.local.host, icd.con.remote.host, icd.url)
        self.offers.write(data)
        self.offers.flush()

    def handle_incident_dionaea_download_complete_hash(self, icd):
        data = "%s %s %s %s %s\n" % (datetime.datetime.now().isoformat(
        ), icd.con.local.host, icd.con.remote.host, icd.url, icd.md5hash)
        self.downloads.write(data)
        self.downloads.flush()
