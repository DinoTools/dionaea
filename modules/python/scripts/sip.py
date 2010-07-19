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

def hash(s):
	return hashlib.md5(s.encode('utf-8')).hexdigest()

TRYING                      = '100'
RINGING                     = '180'
CALL_FWD                    = '181'
QUEUED                      = '182'
PROGRESS                    = '183'
OK                          = '200'
ACCEPTED                    = '202'
MULTI_CHOICES               = '300'
MOVED_PERMANENTLY           = '301'
MOVED_TEMPORARILY           = '302'
SEE_OTHER					= '303'
USE_PROXY                   = '305'
ALT_SERVICE                 = '380'
BAD_REQUEST                 = '400'
UNAUTHORIZED                = '401'
PAYMENT_REQUIRED            = '402'
FORBIDDEN                   = '403'
NOT_FOUND                   = '404'
NOT_ALLOWED                 = '405'
NOT_ACCEPTABLE              = '406'
PROXY_AUTH_REQUIRED         = '407'
REQUEST_TIMEOUT             = '408'
CONFLICT                    = '409'
GONE                        = '410'
LENGTH_REQUIRED             = '411'
ENTITY_TOO_LARGE            = '413'
URI_TOO_LARGE               = '414'
UNSUPPORTED_MEDIA           = '415'
UNSUPPORTED_URI				= '416'
BAD_EXTENSION               = '420'
EXTENSION_REQUIRED			= '421'
INTERVAL_TOO_BRIEF			= '423'
NOT_AVAILABLE               = '480'
NO_TRANSACTION              = '481'
LOOP                        = '482'
TOO_MANY_HOPS               = '483'
ADDRESS_INCOMPLETE          = '484'
AMBIGUOUS                   = '485'
BUSY_HERE                   = '486'
CANCELLED                   = '487'
NOT_ACCEPTABLE_HERE         = '488'
REQUEST_PENDING				= '491'
UNDECIPHERABLE				= '493'
INTERNAL_ERROR              = '500'
NOT_IMPLEMENTED             = '501'
BAD_GATEWAY                 = '502'
UNAVAILABLE                 = '503'
GATEWAY_TIMEOUT             = '504'
SIP_VERSION_NOT_SUPPORTED   = '505'
MESSAGE_TOO_LARGE			= '513'
BUSY_EVERYWHERE             = '600'
DECLINE                     = '603'
DOES_NOT_EXIST              = '604'
NOT_ACCEPTABLE_6xx          = '606'

# SIP Responses from SIP Demystified by Gonzalo Camarillo
RESPONSE = { 
	# 1xx
	TRYING:                     '100 Trying',
	RINGING:                    '180 Ringing',
	CALL_FWD:                   '181 Call is being forwarded',
	QUEUED:                     '182 Queued',
	PROGRESS:                   '183 Session progress',

	# 2xx
	OK:                         '200 OK',
	ACCEPTED:                   '202 Accepted',

	# 3xx
	MULTI_CHOICES:              '300 Multiple choices',
	MOVED_PERMANENTLY:          '301 Moved permanently',
	MOVED_TEMPORARILY:          '302 Moved temporarily',
	SEE_OTHER:					'303 See other',
	USE_PROXY:                  '305 Use proxy',
	ALT_SERVICE:                '380 Alternative service',

	# 4xx
	BAD_REQUEST:                '400 Bad request',
	UNAUTHORIZED:               '401 Unauthorized',
	PAYMENT_REQUIRED:           '402 Payment required',
	FORBIDDEN:                  '403 Forbidden',
	NOT_FOUND:                  '404 Not found',
	NOT_ALLOWED:                '405 Method not allowed',
	NOT_ACCEPTABLE:             '406 Not acceptable',
	PROXY_AUTH_REQUIRED:        '407 Proxy authentication required',
	REQUEST_TIMEOUT:            '408 Request time-out',
	CONFLICT:                   '409 Conflict',
	GONE:                       '410 Gone',
	LENGTH_REQUIRED:            '411 Length required',
	ENTITY_TOO_LARGE:           '413 Request entity too large',
	URI_TOO_LARGE:              '414 Request-URI too large',
	UNSUPPORTED_MEDIA:          '415 Unsupported media type',
	UNSUPPORTED_URI:			'416 Unsupported URI scheme',
	BAD_EXTENSION:              '420 Bad extension',
	EXTENSION_REQUIRED:			'421 Extension required',
	INTERVAL_TOO_BRIEF:			'423 Interval too brief',
	NOT_AVAILABLE:              '480 Temporarily not available',
	NO_TRANSACTION:             '481 Call leg/transaction does not exist',
	LOOP:                       '482 Loop detected',
	TOO_MANY_HOPS:              '483 Too many hops',
	ADDRESS_INCOMPLETE:         '484 Address incomplete',
	AMBIGUOUS:                  '485 Ambiguous',
	BUSY_HERE:                  '486 Busy here',
	CANCELLED:                  '487 Request cancelled',
	NOT_ACCEPTABLE_HERE:        '488 Not acceptable here',
	REQUEST_PENDING:			'491 Request pending',
	UNDECIPHERABLE:				'493 Undecipherable',

	# 5xx
	INTERNAL_ERROR:             '500 Internal server error',
	NOT_IMPLEMENTED:            '501 Not implemented',
	BAD_GATEWAY:                '502 Bad gateway',
	UNAVAILABLE:                '503 Service unavailable',
	GATEWAY_TIMEOUT:            '504 Gateway time-out',
	SIP_VERSION_NOT_SUPPORTED:  '505 SIP version not supported',
	MESSAGE_TOO_LARGE:			'513 Message too large',

	# 6xx
	BUSY_EVERYWHERE:            '600 Busy everywhere',
	DECLINE:                    '603 Decline',
	DOES_NOT_EXIST:             '604 Does not exist anywhere',
	NOT_ACCEPTABLE_6xx:         '606 Not acceptable'
}

# SIP headers have short forms
shortHeaders = {"call-id": "i",
                "contact": "m",
                "content-encoding": "e",
                "content-length": "l",
                "content-type": "c",
                "from": "f",
                "subject": "s",
                "to": "t",
                "via": "v",
				"cseq": "cseq",
				"accept": "accept",
				"user-agent": "user-agent",
				"max-forwards": "max-forwards",
				"www-authentication": "www-authentication",
				"authorization": "authorization"
                }

longHeaders = {}
for k, v in shortHeaders.items():
	longHeaders[v] = k
del k, v

class SipParsingError(Exception):
	"""Exception class for errors occuring during SIP message parsing"""

class AuthenticationError(Exception):
	"""Exception class for errors occuring during SIP authentication"""

def parseSipMessage(msg):
	"""Parses a SIP message (string), returns a tupel (type, firstLine, header,
	body)"""
	# Sanitize input: remove superfluous leading and trailing newlines and
	# spaces
	msg = msg.strip("\n\r\t ")

	# Split request/status line plus headers from body: we don't care about the
	# body in the SIP parser
	parts = msg.split("\n\n", 1)
	if len(parts) < 1:
		logger.error("Message too short")
		raise SipParsingError("Message too short")

	msg = parts[0]

	# Python way of doing a ? b : c
	body = len(parts) == 2 and parts[1] or ''

	# Normalize line feed and carriage return to \n
	msg = msg.replace("\n\r", "\n")

	# Split lines into a list, each item containing one line
	lines = msg.split('\n')

	# Get message type (first word, smallest possible one is "ACK" or "BYE")
	sep = lines[0].find(' ')
	if sep < 3:
		raise SipParsingError("Malformed request or status line")

	msgType = lines[0][:sep]
	firstLine = lines[0][sep+1:]

	# Done with first line: delete from list of lines
	del lines[0]

	# Parse header
	headers = {}
	for i in range(len(lines)):
		# Take first line and remove from list of lines
		line = lines.pop(0)

		# Strip each line of leading and trailing whitespaces
		line = line.strip("\n\r\t ")

		# Break on empty line (end of headers)
		if len(line.strip(' ')) == 0:
			break

		# Parse header lines
		sep = line.find(':')
		if sep < 1:
			raise SipParsingError("Malformed header line (no ':')")

		# Get header identifier (word before the ':')
		identifier = line[:sep]
		identifier = identifier.lower()

		# Check for valid header
		if identifier not in shortHeaders.keys() and \
			identifier not in longHeaders.keys():
			raise SipParsingError("Unknown header type: {}".format(identifier))

		# Get long header identifier if necessary
		if identifier in longHeaders.keys():
			identifier = longHeaders[identifier]

		# Get header value (line after ':')
		value = line[sep+1:].strip(' ')

		# The Via header can occur multiple times
		if identifier == "via":
			if identifier not in headers:
				headers["via"] = [value]
			else:
				headers["via"].append(value)

		# Assign any other header value directly to the header key
		else:
			headers[identifier] = value

	# Return message type, header dictionary, and body string
	return (msgType, firstLine, headers, body)

class Sip(connection):
	"""Only UDP connections are supported at the moment"""

	def __init__(self):
		connection.__init__(self, 'udp')

		# Dictionary with SIP sessions (key is Call-ID)
		self.__sessions = {}

		# Initialize remote host variables
		# TODO: Use this variables with self.remote.host and self.remote.port
		self.__remoteAddress = ''
		self.__remoteSipPort = 0

		# Set SIP connection in session class variable
		# SipSession.sipConnection = self

		# Test log entry
		logger.info("SIP server created")

	def send(self, s):
		logger.debug('Sending message "{}" to ({}:{})'.format(
			s, self.__remoteAddress, self.__remoteSipPort))
		
		self.remote.host = self.__remoteAddress
		self.remote.port = self.__remoteSipPort
		self.send(s.encode('utf-8'))

	def handle_read(self):
		data, conInfo = self.recvfrom(1024)

		# TODO: avoid race condition with remote addr/port
		self.__remoteAddress = conInfo[0]
		self.__remoteSipPort = conInfo[1]

		# Get byte data and decode to unicode string
		data = data.decode('utf-8')

		# Parse SIP message
		try:
			msgType, firstLine, headers, body = parseSipMessage(data)
		except SipParsingError as e:
			logger.error(e)
			return

		if msgType == 'INVITE':
			self.sip_INVITE(firstLine, headers, body)
		elif msgType == 'ACK':
			self.sip_ACK(firstLine, headers, body)
		elif msgType == 'OPTIONS':
			self.sip_OPTIONS(firstLine, headers, body)
		elif msgType == 'BYE':
			self.sip_BYE(firstLine, headers, body)
		elif msgType == 'CANCEL':
			self.sip_CANCEL(firstLine, headers, body)
		elif msgType == 'REGISTER':
			self.sip_REGISTER(firstLine, headers, body)
		elif msgType == 'SIP/2.0':
			self.sip_RESPONSE(firstLine, headers, body)
		elif msgType == 'Error':
			logger.error("Error on parsing SIP message")
		else:
			logger.error("Error: unknown header")
