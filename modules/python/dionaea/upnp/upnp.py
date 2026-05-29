# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2015 Tan Kean Siong
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.core import connection, incident, ihandler
import struct
import logging
import os
import sys
import datetime
import io
import cgi
import urllib.parse
import re
import tempfile

logger = logging.getLogger('upnp')
logger.setLevel(logging.DEBUG)
httpversion = ''

class upnpreq:
	def __init__(self, header):
		hlines = header.split(b'\n')
		req = hlines[0]
		reqparts = req.split(b" ")
		self.type = reqparts[0]
		self.path = urllib.parse.unquote(reqparts[1].decode('utf-8'))
		global httpversion
		httpversion = reqparts[2]
		r = httpversion.find(b"\r")
		if r:
			httpversion = httpversion[:r]
		self.headers = {}
		for hline in hlines[1:]:
			if hline[len(hline)-1] == 13: # \r
				hline = hline[:len(hline)-1]
			hset = hline.split(b":", 1)
			try:
				self.headers[hset[0].lower()] = hset[1].strip()
			except:
				logger.info("potential upnp exploit: %s", hset[0])

	def print(self):
		logger.debug("Type: %s Path: %s HTTP-Version: %s", self.type, self.path, httpversion)
		for i in self.headers:
			logger.debug("%s: %s", i, self.headers[i])


class upnpd(connection):
	shared_config_values = [
		"max_request_size",
		"personalities",
		"root",
		"rwchunksize"
	]

	def __init__(self, proto='udp'):
		connection.__init__(self,proto)
		self.state = 'HEADER'
		self.rwchunksize = 64*1024
		self._out.speed.limit = 16*1024
		self.env = None
		self.boundary = None
		self.fp_tmp = None
		self.cur_length = 0
		self.personalities = ''
		self.loaded = ''
		self.root = ""

		# 32MB
		self.max_request_size = 32768 * 1024

	def apply_config(self, config):
		self.root = config.get("root", self.root)
		max_request_size = config.get("max_request_size")
		if max_request_size is not None:
			self.max_request_size = max_request_size * 1024

		# load the UPnP device personality
		self.personalities = config["personality"]['cache']
		self.personalities += config["personality"]['st']
		self.personalities += config["personality"]['usn']
		self.personalities += config["personality"]['server']
		self.personalities += config["personality"]['location']
		self.personalities += config["personality"]['opt']

	def handle_origin(self, parent):
		pass

	def handle_established(self):
		logger.debug("%r handle_established", self)

		self.timeouts.idle = 10
		self.timeouts.sustain = 120
		self.processors()

		# fake a connection entry
		i = incident("dionaea.connection.udp.connect")
		i.con = self
		i.report()

	def chroot(self, path):
		self.root = path

	def handle_io_in(self, data):
		if self.state == 'HEADER':
			# End Of Head
			eoh = data.find(b'\r\n\r\n')
			# Start Of Content
			soc = eoh + 4

			if eoh == -1:
				eoh = data.find(b'\n\n')
				soc = eoh + 2
			if eoh == -1:
				return 0

			header = data[0:eoh]
			data = data[soc:]
			self.header = upnpreq(header)

			self.header.print()

			# current Dionaea supports header type 'M-SEARCH' for SSDP discovery
			if self.header.type == b'M-SEARCH':
				self.handle_MSEARCH()
				return len(data)

			# header not found
			else:
				logger.info('unknown upnp ssdp header: %s', self.header.type)
				self.handle_unknown()
			return len(data)

		else:
			self.close()
			return len(data)


	def handle_MSEARCH(self):
		"""Handle the M-SEARCH method"""
		r = self.personalities
		self.send_response_upnp(200, r)
		self.close()

	def handle_unknown(self):
		pass

	def handle_io_out(self):
		logger.debug("handle_io_out")


	def send_response_upnp(self, code, upnp_response):
		if code in self.responses:
			message = self.responses[code][0]
		else:
			message = ''
		self.version  = httpversion[-3:].decode('utf-8')
		self.send("%s/%s %d %s\r\n%s\r\n" % ("HTTP", self.version, code, message, upnp_response))

	def handle_timeout_sustain(self):
		logger.debug("%r handle_timeout_sustain", self)
		return True

	def handle_timeout_idle(self):
		logger.debug("%r handle_timeout_idle", self)
		self.close()
		return False

	def handle_disconnect(self):
		return False


	responses = {
		200: ('OK', 'Request fulfilled, document follows'),
		}
