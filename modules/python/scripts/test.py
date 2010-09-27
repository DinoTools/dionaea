#********************************************************************************
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

from dionaea.core import ihandler, incident, g_dionaea
from dionaea.core import connection
import logging
import json
global p

logger = logging.getLogger('test')
logger.setLevel(logging.DEBUG)


class uniquedownloadihandler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)
	def handle_incident(self, icd):
		logger.debug("submitting file")
		try:
			tos = g_dionaea.config()['submit']
		except:
			return

		for to in tos:
			if 'urls' not in tos[to]:
				logger.warn("your configuration lacks urls to submit to %s" % to)
				continue
			for url in tos[to]['urls']:
				i = incident("dionaea.upload.request")
				i._url = url
				# copy all values for this url
				for key in tos[to]:
					if key == 'urls':
						continue
					if key == 'file_fieldname':
						i.set("file://" + tos[to][key], icd.file)
						continue
					i.set(key, tos[to][key])
				i.report()
