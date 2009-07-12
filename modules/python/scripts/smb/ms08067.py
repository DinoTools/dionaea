#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter & Mark Schloesser
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

ms08067log = logging.getLogger('MS08-067')

def checkfn(p):
	# we need DCERPC_Header packet
	if hasattr(p, 'OpNum') and p.OpNum == 0x1f:
		return True

def ourcallback(p):
	ms08067log.info('got the DCERPC request for NetprPathCanonicalize. MS08-067 exploit?')
	ms08067log.debug('DCERPC request: {0}'.format(p.summary()))

def register():
	return 'c84f324b7016d30112785a47bf6ee188', checkfn, ourcallback

