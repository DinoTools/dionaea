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

rpclog = logging.getLogger('RPCVULN')

class RPCVULN:
	uuid = ''
	opnum = 0

	@classmethod
	def processrequest(cls, p):
		pass

class MS08_067(RPCVULN):
	#SRVSVC
	uuid = 'c84f324b7016d30112785a47bf6ee188'
	# NetprPathCanonicalize
	opnum = 0x1f

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for NetprPathCanonicalize. MS08-067 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))

class MS04_011(RPCVULN):
	#SRVSVC
	uuid = '6a2819390cb1d0119ba800c04fd92ef5'
	# NetprPathCanonicalize
	opnum = 0x09

	@classmethod
	def processrequest(cls, p):
		rpclog.info('got the DCERPC request for DsRolerUpgradeDownlevelServer. MS04-011 exploit?')
		rpclog.debug('DCERPC request: {0}'.format(p.summary()))



