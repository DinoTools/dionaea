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

from dionaea import *
import logging

global handler
global logger

class DionaeaLogHandler(logging.Handler):
	def __init__(self):
		logging.Handler.__init__(self, logging.DEBUG)
	def emit(self,record):
		dlhfn(record.name, record.levelno, record.pathname, record.lineno, record.msg)


def start():
	global logger
	global handler
	logger = logging.getLogger('')
	logger.setLevel(logging.DEBUG)
	handler = DionaeaLogHandler()
#	print("add handler" + str(handler))
	logger.addHandler(handler)
#	logtest = logging.getLogger("test")
#	logtest.warn("Das liegt nun in der test domain")

def stop():
	global logger
	global handler
#	print("remove handler " + str(handler))
	logger.removeHandler(handler)

# "application" code
#logger.debug("debug message")
#logger.info("info message")
#logger.warn("warn message")
#logger.critical("critical message")
#logger.error("error message")
#
#logx = logging.getLogger("logx")
#logx.warn("x")


#class idumper(ihandler):
#	def __init__(self, pattern):
#		ihandler.__init__(self, pattern)
#	def handle(self, icd):
#		icd.dump()
#
#
#...
