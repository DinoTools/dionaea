################################################################################
#
# Stand-alone VoIP honeypot client (preparation for Dionaea integration)
# Copyright (c) 2010 Tobias Wulff (twu200 at gmail)
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
# 
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
################################################################################
#
# Parts of the SIP response codes and a lot of SIP message parsing are taken
# from the Twisted Core: http://twistedmatrix.com/trac/wiki/TwistedProjects
#
# The hash calculation for SIP authentication has been copied from SIPvicious
# Sipvicious (c) Sandro Gaucci: http://code.google.com/p/sipvicious
#
################################################################################

import logging
import time
import random
import hashlib

from dionaea.core import connection, ihandler, g_dionaea, incident

logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)

# Shortcut to sip config
g_sipconfig = g_dionaea.config()['modules']['python']['sip']
