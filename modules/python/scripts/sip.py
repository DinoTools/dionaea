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
from dionaea import pyev

g_default_loop = pyev.default_loop()

logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)

# Shortcut to sip config
g_sipconfig = g_dionaea.config()['modules']['python']['sip']

# Make "yes"/"no" from config file into boolean value
if g_sipconfig['use_authentication'].lower() == 'no':
	g_sipconfig['use_authentication'] = False
else:
	g_sipconfig['use_authentication'] = True

# Shortcut hashing function
def hash(s):
	return hashlib.md5(s.encode('utf-8')).hexdigest()

#############
# SIP globals
#############

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

#############
# SDP globals
#############

sessionDescriptionTypes = {
	"v": "protocol version",
	"o": "session owner",
	"s": "session name",
	"i": "session information",
	"u": "uri",
	"e": "email address",
	"p": "phone number",
	"c": "connection information",
	"b": "bandwidth information",
	"z": "time zone adjustment",
	"k": "encryption key",
	"t": "active time",
	"r": "repeat time",
	"a": "session attribute line"
}

mediaDescriptionTypes = {
	"m": "media name",
	"i": "media title",
	"c": "connection information",
	"b": "bandwidth information",
	"k": "encryption key",
	"a": "attribute line"
}

class SdpParsingError(Exception):
	"""Exception class for errors occuring during SDP message parsing"""

###################
# Parsing functions
###################

def parseSdpMessage(msg):
	"""Parses an SDP message (string), returns a tupel of dictionaries with
	{type: value} entries: (sessionDescription, mediaDescriptions)"""
	# Normalize line feed and carriage return to \n
	msg = msg.replace("\n\r", "\n")

	# Sanitize input: remove superfluous leading and trailing newlines and
	# spaces
	msg = msg.strip("\n\r\t ")

	# Split message into session description, and media description parts
	SEC_SESSION, SEC_MEDIA = range(2)
	curSection = SEC_SESSION
	sessionDescription = {}
	mediaDescriptions = []
	mediaDescriptionNumber = -1

	# Process each line individually
	if len(msg) > 0:
		lines = msg.split("\n")
		for line in lines:
			# Remove leading and trailing whitespaces from line
			line = line.strip('\n\r\t ')

			# Get first two characters of line and check for "type="
			if len(line) < 2:
				raise SdpParsingError("Line too short")
			elif line[1] != "=":
				raise SdpParsingError("Invalid SDP line")

			type = line[0]
			value = line[2:].strip("\n\r\t ")

			# Change current section if necessary
			# (session -> media -> media -> ...)
			if type == "m":
				curSection = SEC_MEDIA
				mediaDescriptionNumber += 1
				mediaDescriptions.append({})

			# Store the SDP values
			if curSection == SEC_SESSION:
				if type not in sessionDescriptionTypes:
					raise SdpParsingError(
						"Invalid session description type: " + type)
				else:
					sessionDescription[type] = value
			elif curSection == SEC_MEDIA:
				if type not in mediaDescriptionTypes:
					raise SdpParsingError(
						"Invalid media description type: " + type)
				else:
					mediaDescriptions[mediaDescriptionNumber][type] = value

	return (sessionDescription, mediaDescriptions)

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
		logger.warn("SIP message is too short")
		raise SipParsingError("SIP message is too short")

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

#########
# Classes
#########

class RtpUdpStream(connection):
	"""RTP stream that can send data and writes the whole conversation to a
	file"""
	def __init__(self, address, port):
		connection.__init__(self, 'udp')

		# Bind to free random port for incoming RTP traffic
		# TODO: Address from config file?
		self.bind('0.0.0.0', 0)

		# The address and port of the remote host
		self.__address = address
		self.__port = port

		# Send byte buffer
		self.__sendBuffer = b''

		# Create a stream dump file with date and time and random ID in case of
		# flooding attacks
		dumpDateTime = time.strftime("%Y%m%d_%H:%M:%S")
		dumpId = random.randint(1000, 9999)
		streamDumpFileIn = "var/dionaea/stream_{0}_{1}_in.rtpdump".format(
			dumpDateTime, dumpId)
		streamDumpFileOut = "var/dionaea/stream_{0}_{1}_out.rtpdump".format(
			dumpDateTime, dumpId)

		# Catch IO errors
		try:
			self.__streamDumpIn = open(streamDumpFileIn, "wb")
		except IOError as e:
			logger.warn("RtpStream: Could not open stream dump file: {}".format(e))
			self.__streamDumpIn = None

		try:
			self.__streamDumpOut = open(streamDumpFileOut, "wb")
		except IOError as e:
			logger.warn("RtpStream: Could not open stream dump file: {}".format(e))
			self.__streamDumpOut = None

		logger.info("Created RTP channel on ports :{} <-> :{}".format(
			self.local.port, self.__port))

	def handle_timeout_idle(self):
		return False

	def handle_timeout_sustain(self):
		return False

	def handle_close(self):
		self.close()
		logger.info("Closed RTP channel on ports :{} <-> :{}".format(
			self.local.port, self.remote.port))

	def handle_io_in(self, data):
		# Write incoming data to disk
		if self.__streamDumpIn:
			self.__streamDumpIn.write(data)

		return len(data)

	def handle_io_out(self):
		# TODO: Only necessary to set once in __init__?
		self.remote.host = self.__address
		self.remote.port = self.__port
		bytesSent = self.send(self.__sendBuffer)

		# Write the sent part of the buffer to the stream dump file
		if self.__streamDumpOut:
			self.__streamDumpOut.write(self.__sendBuffer[:bytesSent])

		# Shift sending window for next send operation
		self.__sendBuffer = self.__sendBuffer[bytesSent:]

	def close(self):
		if self.__streamDumpIn:
			self.__streamDumpIn.close()

		if self.__streamDumpOut:
			self.__streamDumpOut.close()

		connection.close(self)

class SipSession(object):
	"""Usually, a new SipSession instance is created when the SIP server
	receives an INVITE message"""
	NO_SESSION, SESSION_SETUP, ACTIVE_SESSION, SESSION_TEARDOWN = range(4)
	sipConnection = None

	def __init__(self, conInfo, rtpPort, inviteHeaders):
		if not SipSession.sipConnection:
			logger.critical("SIP connection class variable not set")

		# Store incoming information of the remote host
		self.__state = SipSession.SESSION_SETUP
		self.__remoteAddress = conInfo[0]
		self.__remoteSipPort = conInfo[1]
		self.__remoteRtpPort = rtpPort
		self.__callId = inviteHeaders['call-id']

		# Generate static values for SIP messages
		global g_sipconfig
		self.__sipTo = inviteHeaders['from']
		self.__sipFrom = "{0} <sip:{0}@{1}>".format(g_sipconfig['user'],
			g_sipconfig['ip'])
		self.__sipVia = "SIP/2.0/UDP {}:{}".format(g_sipconfig['ip'],
			g_sipconfig['port'])

	def send(self, s):
		s += '\n\n'
		SipSession.sipConnection.sendto(s,
			(self.__remoteAddress, self.__remoteSipPort))

	def handle_INVITE(self, headers):
		# Check authentication
		self.__authenticate(headers)

		# Create RTP stream instance and pass address and port of listening
		# remote RTP host
		self.__rtpStream = RtpUdpStream(self.__remoteAddress,
			self.__remoteRtpPort)

		# Send 180 Ringing to make honeypot appear more human-like
		msgLines = []
		msgLines.append("SIP/2.0 " + RESPONSE[RINGING])
		msgLines.append("Via: " + self.__sipVia)
		msgLines.append("Max-Forwards: 70")
		msgLines.append("To: " + self.__sipTo)
		msgLines.append("From: " + self.__sipFrom)
		msgLines.append("Call-ID: {}".format(self.__callId))
		msgLines.append("CSeq: " + headers['cseq'])
		msgLines.append("Contact: " + self.__sipFrom)
		msgLines.append("User-Agent: " + g_sipconfig['useragent'])
		self.send('\n'.join(msgLines))

		def timer_cb(watcher, events):
			# Send our RTP port to the remote host as a 200 OK response to the
			# remote host's INVITE request
			logger.debug("getsockname SipSession: {}".format(
				self.__rtpStream.local.port))
			localRtpPort = self.__rtpStream.local.port
			
			msgLines = []
			msgLines.append("SIP/2.0 " + RESPONSE[OK])
			msgLines.append("Via: " + self.__sipVia)
			msgLines.append("Max-Forwards: 70")
			msgLines.append("To: " + self.__sipTo)
			msgLines.append("From: " + self.__sipFrom)
			msgLines.append("Call-ID: {}".format(self.__callId))
			msgLines.append("CSeq: " + headers['cseq'])
			msgLines.append("Contact: " + self.__sipFrom)
			msgLines.append("User-Agent: " + g_sipconfig['useragent'])
			msgLines.append("Content-Type: application/sdp")
			msgLines.append("\nv=0")
			msgLines.append("o=... 0 0 IN IP4 localhost")
			msgLines.append("t=0 0")
			msgLines.append("m=audio {} RTP/AVP 0".format(localRtpPort))
			self.send('\n'.join(msgLines))

			# Delete timer reference
			del self.timer

		# Delay between 180 and 200 response with pyev callback timer
		global g_default_loop
		self.timer = pyev.Timer(3, 0, g_default_loop, timer_cb)
		self.timer.start()

		return 0

	def handle_ACK(self, headers, body):
		if self.__state != SipSession.SESSION_SETUP:
			logger.warn("ACK received but not in session setup mode")

		else:
			# Authenticate ACK
			self.__authenticate(headers)

			logger.info("SIP session established (session {})".format(
				self.__callId))

			# Set current state to active (ready for multimedia stream)
			self.__state = SipSession.ACTIVE_SESSION

			# Send 200 OK response
			msgLines = []
			msgLines.append("SIP/2.0 " + RESPONSE[OK])
			msgLines.append("Via: " + self.__sipVia)
			msgLines.append("Max-Forwards: 70")
			msgLines.append("To: " + self.__sipTo)
			msgLines.append("From: " + self.__sipFrom)
			msgLines.append("Call-ID: {}".format(self.__callId))
			msgLines.append("CSeq: " + headers['cseq'])
			msgLines.append("Contact: " + self.__sipFrom)
			msgLines.append("User-Agent: " + g_sipconfig['useragent'])
			self.send('\n'.join(msgLines))

	def handle_CANCEL(self, headers, body):
		self.__authenticate(headers)

	def handle_BYE(self, headers, body):
		global g_sipconfig

		if self.__state != SipSession.ACTIVE_SESSION:
			logger.warn("BYE received but not in active session mode")

		else:
			self.__authenticate(headers)

			# Close RTP channel
			self.__rtpStream.close()

			# A BYE ends the session immediately
			self.__state = SipSession.NO_SESSION

			# Send OK response to other client
			msgLines = []
			msgLines.append("SIP/2.0 200 OK")
			msgLines.append("Via: " + self.__sipVia)
			msgLines.append("Max-Forwards: 70")
			msgLines.append("To: " + self.__sipTo)
			msgLines.append("From: " + self.__sipFrom)
			msgLines.append("Call-ID: {}".format(self.__callId))
			msgLines.append("CSeq: " + headers['cseq'])
			msgLines.append("Contact: " + self.__sipFrom)
			msgLines.append("User-Agent: " + g_sipconfig['useragent'])
			self.send('\n'.join(msgLines))

	def __authenticate(self, headers):
		global g_sipconfig

		if not g_sipconfig['use_authentication']:
			logger.debug("Skipping authentication")
			return

		logger.debug("'Authorization' in SIP headers: {}".format(
			'authorization' in headers))

		if "authorization" not in headers:
			# Calculate new nonce for authentication based on current time
			nonce = hash("{}".format(time.time()))

			# Send 401 Unauthorized response
			msgLines = []
			msgLines.append('SIP/2.0 ' + RESPONSE[UNAUTHORIZED])
			msgLines.append("Via: " + self.__sipVia)
			msgLines.append("Max-Forwards: 70")
			msgLines.append("To: " + self.__sipTo)
			msgLines.append("From: " + self.__sipFrom)
			msgLines.append("Call-ID: {}".format(self.__callId))
			msgLines.append("CSeq: " + headers['cseq'])
			msgLines.append("Contact: " + self.__sipFrom)
			msgLines.append("User-Agent: " + g_sipconfig['useragent'])
			msgLines.append('WWW-Authenticate: Digest ' + \
				'realm="{}@{}",'.format(g_sipconfig['user'],
					g_sipconfig['ip']) + \
				'nonce="{}"'.format(nonce))
			self.send('\n'.join(msgLines))

			raise AuthenticationError("Request was unauthenticated")

		else:
			# Check against config file
			authMethod, authLine = headers['authorization'].split(' ', 1)
			if authMethod != 'Digest':
				logger.warn("Authorization method is not Digest")
				raise AuthenticationError("Method is not Digest")

			# Get Authorization header parts (a="a", b="b", c="c", ...) and put
			# them in a dictionary for easy lookup
			authLineParts = [x.strip(' \t\r\n') for x in authLine.split(',')]
			authLineDict = {}
			for x in authLineParts:
				parts = x.split('=')
				authLineDict[parts[0]] = parts[1].strip(' \n\r\t"\'')

			logger.debug("Authorization dict: {}".format(authLineDict))

			if 'nonce' not in authLineDict:
				logger.warn("Nonce missing from authorization header")
				raise AuthenticationError("Nonce missing")

			if 'response' not in authLineDict:
				logger.warn("Response missing from authorization header")
				raise AuthenticationError("Response missing")

			# The calculation of the expected response is taken from
			# Sipvicious (c) Sandro Gaucci
			realm = "{}@{}".format(g_sipconfig['user'], g_sipconfig['ip'])
			uri = "sip:" + realm
			a1 = hash("{}:{}:{}".format(
				g_sipconfig['user'], realm, g_sipconfig['secret']))
			a2 = hash("INVITE:{}".format(uri))
			expected = hash("{}:{}:{}".format(a1, authLineDict['nonce'], a2))

			logger.debug("a1: {}".format(a1))
			logger.debug("a2: {}".format(a2))
			logger.debug("expected: {}".format(expected))

			if expected != authLineDict['response']:
				logger.warn("Authorization failed")
				raise AuthenticationError("Authorization failed")

			logger.info("Authorization succeeded")

class Sip(connection):
	"""Only UDP connections are supported at the moment"""

	def __init__(self):
		connection.__init__(self, 'udp')

		# Dictionary with SIP sessions (key is Call-ID)
		self.__sessions = {}

		# Set SIP connection in session class variable
		SipSession.sipConnection = self

		# Test log entry
		logger.info("SIP server created")

	def sendto(self, s, con):
		"""
		Since the dionaea connection class doesn't provide a sendto method it is
		implemented here. It is needed to other classes (instances) send
		messages through the SIP connection (particularly instances of
		SipSession). It is not needed in this class itself because all send
		calls are in direct response to an incoming message so self.remote.host
		and self.remote.port are already set correctly.
		"""
		logger.debug('Sending message "{}" to ({}:{})'.format(
			s, con[0], con[1]))
		
		# Set remote host and port before UDP send
		self.remote.host = con[0]
		self.remote.port = con[1]
		self.send(s.encode('utf-8'))

	def handle_io_in(self, data):
		# Get byte data and decode to unicode string
		data = data.decode('utf-8')

		# Parse SIP message
		try:
			msgType, firstLine, headers, body = parseSipMessage(data)
		except SipParsingError as e:
			logger.warn("Error while parsing SIP message: {}".format(e))
			return len(data)

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
		else:
			logger.warn("Unknown SIP header " + \
				"(supported: INVITE, ACK, OPTIONS, BYE, CANCEL, REGISTER " + \
				"and SIP responses")

		logger.debug("io_in: returning {}".format(len(data)))
		return len(data)

	def sip_INVITE(self, requestLine, headers, body):
		global g_sipconfig

		# Print SIP header
		logger.info("Received INVITE")
		for k, v in headers.items():
			logger.debug("SIP header {}: {}".format(k, v))

		if self.__checkForMissingHeaders(headers, ["accept", "content-type"]):
			return

		# Header has to define Content-Type: application/sdp if body contains
		# SDP message. Also, Accept has to be set to sdp so that we can send
		# back a SDP response.
		if headers["content-type"] != "application/sdp":
			logger.warn("INVITE without SDP message: exit")
			return

		if headers["accept"] != "application/sdp":
			logger.warn("INVITE without SDP message: exit")
			return

		# Check for SDP body
		if not body:
			logger.warn("INVITE without SDP message: exit")
			return

		# Parse SDP part of session invite
		try:
			sessionDescription, mediaDescriptions = parseSdpMessage(body)
		except SdpParsingError as e:
			logger.warn("Error while parsing SDP message: {}".format(e))
			return

		# Check for all necessary fields
		sdpSessionOwnerParts = sessionDescription['o'].split(' ')
		if len(sdpSessionOwnerParts) < 6:
			logger.warn("SDP session owner field to short: exit")
			return

		logger.debug("Parsed SDP message:")
		for k, v in sessionDescription.items():
			logger.debug("{}: {}".format(k, v))
		for mediaDescription in mediaDescriptions:
			for k, v in mediaDescription.items():
				logger.debug("{}: {}".format(k, v))

		# Get RTP port from SDP media description
		if len(mediaDescriptions) < 1:
			logger.warn("SDP message has to include a media description: exit")
			return
		
		# TODO: look at other mediaDescriptions as well
		mediaDescriptionParts = mediaDescriptions[0]['m'].split(' ')
		if mediaDescriptionParts[0] != 'audio':
			logger.warn("SDP media description has to be of audio type: exit")
			return

		rtpPort = mediaDescriptionParts[1]

		# Read Call-ID field and create new SipSession instance on first INVITE
		# request received (remote host might send more than one because of time
		# outs or because he wants to flood the honeypot)
		logger.debug("Currently active sessions: {}".format(self.__sessions))
		callId = headers["call-id"]
		if callId in self.__sessions:
			logger.warn("SIP session with Call-ID {} already exists".format(
				callId))
			return

		# Establish a new SIP session
		newSession = SipSession((self.remote.host, self.remote.port),
			rtpPort, headers)
		try:
			r = newSession.handle_INVITE(headers)
		except AuthenticationError:
			logger.warn("Authentication failed, not creating SIP session")
			del newSession
		else:
			# Store session object in sessions dictionary
			self.__sessions[callId] = newSession

	def sip_ACK(self, requestLine, headers, body):
		logger.info("Received ACK")

		if self.__checkForMissingHeaders(headers):
			return

		# Check if session (identified by Call-ID) exists
		callId = headers['call-id'] 
		if callId not in self.__sessions:
			logger.warn("Given Call-ID does not belong to any session: exit")
		else:
			try:
				# Handle incoming ACKs depending on current state
				self.__sessions[callId].handle_ACK(headers, body)
			except AuthenticationError:
				logger.warn("Authentication failed for ACK request")

	def sip_OPTIONS(self, requestLine, headers, body):
		logger.info("Received OPTIONS")

		# Construct OPTIONS response
		global g_sipconfig
		msgLines = []
		msgLines.append("SIP/2.0 " + RESPONSE[OK])
		msgLines.append("Via: SIP/2.0/UDP {}:{}".format(g_sipconfig['ip'],
			g_sipconfig['port']))
		msgLines.append("To: " + headers['from'])
		msgLines.append("From: {0} <sip:{0}@{1}>".format(g_sipconfig['user'],
			g_sipconfig['ip']))
		msgLines.append("Call-ID: " + headers['call-id'])
		msgLines.append("CSeq: " + headers['cseq'])
		msgLines.append("Contact: {0} <sip:{0}@{1}>".format(g_sipconfig['user'],
			g_sipconfig['ip']))
		msgLines.append("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE")
		msgLines.append("Accept: application/sdp")
		msgLines.append("Accept-Language: en")
		msgLines.append('\n')

		self.send('\n'.join(msgLines))

	def sip_BYE(self, requestLine, headers, body):
		logger.info("Received BYE")

		if self.__checkForMissingHeaders(headers):
			return
		
		# Check if session (identified by Call-ID) exists
		callId = headers['call-id'] 
		if callId not in self.__sessions:
			logger.warn("Given Call-ID does not belong to any session: exit")
		else:
			try:
				# Handle incoming BYE request depending on current state
				self.__sessions[callId].handle_BYE(headers, body)
			except AuthenticationError:
				logger.warn("Authentication failed for BYE request")
			else:
				# Delete session instance
				del self.__sessions[callId]

	def sip_CANCEL(self, requestLine, headers, body):
		logger.info("Received CANCEL")

		# Check mandatory headers
		if self.__checkForMissingHeaders(headers):
			return

		# Get Call-Id and check if there's already a SipSession
		callId = headers['call-id']

		# Get CSeq to find out which request to cancel
		cseqParts = headers['cseq'].split(' ')
		cseqMethod = cseqParts[1]

		if cseqMethod == "INVITE" or cseqMethod == "ACK":
			# Find SipSession and delete it
			if callId not in self.__sessions:
				logger.warn(
					"CANCEL request does not match any existing SIP session")
				return

			try:
				self.__session[callId].handle_CANCEL(headers)
			except AuthenticationError:
				logger.warn("Authentication failed for CANCEL request")
				return
			else:
				# No RTP connection has been made yet so deleting the session
				# instance is sufficient
				del self.__session[callId]
		
		# Construct CANCEL response
		global g_sipconfig
		msgLines = []
		msgLines.append("SIP/2.0 " + RESPONSE[OK])
		msgLines.append("Via: SIP/2.0/UDP {}:{}".format(g_sipconfig['ip'],
			g_sipconfig['port']))
		msgLines.append("To: " + headers['from'])
		msgLines.append("From: {0} <sip:{0}@{1}>".format(g_sipconfig['user'],
			g_sipconfig['ip']))
		msgLines.append("Call-ID: " + headers['call-id'])
		msgLines.append("CSeq: " + headers['cseq'])
		msgLines.append("Contact: {0} <sip:{0}@{1}>".format(g_sipconfig['user'],
			g_sipconfig['ip']))

		self.send('\n'.join(msgLines))

	def sip_REGISTER(self, requestLine, headers, body):
		logger.info("Received REGISTER")

	def sip_RESPONSE(self, statusLine, headers, body):
		logger.info("Received a response")

	def __checkForMissingHeaders(self, headers, mandatoryHeaders=[]):
		"""
		Check for specific missing headers given as a list in the second
		argument are present as keys in the dictionary of headers.
		If list of mandatory headers is omitted, a set of common standard
		headers is used: To, From, Call-ID, CSeq, and Contact.
		"""
		if not mandatoryHeaders:
			mandatoryHeaders = ["to", "from", "call-id", "cseq", "contact"]

		headerMissing = False

		for m in mandatoryHeaders:
			if m not in headers:
				logger.warn("Mandatory header {} not in message".format(m))
				headerMissing = True

		return headerMissing
