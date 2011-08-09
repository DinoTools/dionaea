#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (c) 2010 Tobias Wulff (twu200 at gmail)
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
#*
#*
#* Parts of the SIP response codes and a lot of SIP message parsing are taken
#* from the Twisted Core: http://twistedmatrix.com/trac/wiki/TwistedProjects
#*
#* The hash calculation for SIP authentication has been copied from SIPvicious
#* Sipvicious (c) Sandro Gaucci: http://code.google.com/p/sipvicious
#*******************************************************************************


import logging
import time
import random
import os
import errno
import datetime
import tempfile

from dionaea.core import connection, ihandler, g_dionaea, incident
from dionaea import pyev

from dionaea.sip.extras import int2bytes, SipConfig

# load config before loading the other sip modules
g_sipconfig = SipConfig(g_dionaea.config()['modules']['python'].get("sip", {}))

from dionaea.sip import rfc3261
from dionaea.sip import rfc4566
from dionaea.sip import rfc2617 # auth


g_default_loop = pyev.default_loop()

logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)

_SipCall_sustain_timeout = 20

class AuthenticationError(Exception):
	"""Exception class for errors occuring during SIP authentication"""

class SdpParsingError(Exception):
	"""Exception class for errors occuring during SDP message parsing"""

#########
# Classes
#########

class User(object):
	def __init__(self, user_id, **kwargs):
		self.id = user_id
		self.branch = kwargs.get("branch", None)
		self.expires = kwargs.get("expires", 3600)
		self._msg = kwargs.get("msg", None)

		if self._msg != None:
			self.loads(self._msg)

		self.expire_time = datetime.datetime.now(), datetime.datetime.now() + datetime.timedelta(0, self.expires)

	def loads(self, msg):
		# get branch
		vias = msg.headers.get(b"via", [])
		via = vias[-1]
		self.branch = via.get_raw().get_param(b"branch")

		# get expires
		try:
			self.expires = int(msg.headers.get(b"expires"))
		except:
			pass


class RegistrationManager(object):
	def __init__(self):
		self._users = {}
		self._branches = {}

	def register(self, user):
		if not user.id in self._users:
			self._users[user.id] = []

		self._users[user.id].append(user)


g_reg_manager = RegistrationManager()

class RtpUdpStream(connection):
	"""RTP stream that can send data and writes the whole conversation to a
	file"""
	def __init__(self, name, call, session, local_address, local_port, remote_address, remote_port, bistream_enabled = False, pcap = None):
		logger.debug("{:s} __init__".format(self))
		connection.__init__(self, 'udp')

		self._call = call
		self._name = name
		self._pcap = pcap
		self._session = session

		# Bind to free random port for incoming RTP traffic
		self.bind(local_address, local_port)
		self.connect(remote_address, remote_port)

		# The address and port of the remote host
		self.remote.host = remote_address
		self.remote.port = remote_port

		self._bistream = []
		self._bistream_enabled = bistream_enabled

		# Send byte buffer
		self.__sendBuffer = b''

		# ToDo:
		# Report incident
		# ToDo:
		#i = incident("dionaea.modules.python.sip.rtp")
		#i.con = self
		#i.dumpfile = self.__streamDumpFileIn
		#i.report()

		logger.info("Created RTP channel on ports :{} <-> :{}".format(
			self.local.port, self.remote.port))

	def close(self):
		logger.debug("{:s} close".format(self))
		logger.debug("Closing stream dump (in)")
		connection.close(self)

		if len(self._bistream) == 0:
			return

		global g_dionaea

		now = datetime.datetime.now()
		dirname = "%04i-%02i-%02i" % (now.year, now.month, now.day)
		bistream_path = os.path.join(g_dionaea.config()['bistreams']['python']['dir'], dirname)
		if not os.path.exists(bistream_path):
			os.makedirs(bistream_path)

		fp = tempfile.NamedTemporaryFile(
			delete = False,
			prefix = "SipCall-{local_port}-{remote_host}:{remote_port}-".format(local_port = self.local.port, remote_host = self.remote.host, remote_port = self.remote.port),
			dir = bistream_path
		)
		fp.write(b"stream = ")
		fp.write(str(self._bistream).encode())
		fp.close()

	def handle_established(self):
		logger.debug("{:s} handle_established".format(self))
		self.timeouts.idle = 1.0
		self.timeouts.sustain = 120.0

	def handle_timeout_idle(self):
		logger.debug("{:s} handle_timeout_idle".format(self))
		self.close()
		return False

	def handle_timeout_sustain(self):
		logger.debug("{:s} handle_timeout_sustain".format(self))
		return True

	def handle_io_in(self, data):
		logger.debug("{:s} handle_io_in".format(self))
		#logger.debug("Incoming RTP data (length {})".format(len(data)))

		if self._bistream_enabled == True:
			self._bistream.append(("in", data))
		if self._pcap != None:
			self._pcap.write(src_port = self.remote.port, dst_port = self.local.port, data = data)

		return len(data)

	def handle_io_out(self):
		logger.info("{:s} handle_io_out".format(self))

		# ToDo: send rtp data
		#logger.debug("Outdoing RTP data (length {})".format(len(data)))

		#bytesSent = self.send(self.__sendBuffer)

		# Shift sending window for next send operation
		#self.__sendBuffer = self.__sendBuffer[bytesSent:]

	def handle_disconnect(self):
		logger.info("{:s} handle_disconnect".format(self))
		self._call.event_stream_closed(self._name)
		self._pcap.close()
		return False


class SipCall(connection):
	"""
	Usually, a new SipCall instance is created when the SIPSession
	receives an INVITE message
	"""
	NO_SESSION, SESSION_SETUP, ACTIVE_SESSION, SESSION_TEARDOWN, INVITE, INVITE_TRYING, INVITE_RINGING, INVITE_CANCEL, CALL = range(9)

	def __init__(self, proto, call_id, session, conInfo, rtpPort, invite_message):
		logger.debug("{:s} __init__".format(self))

		logger.debug("SipCall {} session {} ".format(self, session))
		connection.__init__(self, proto)
		# Store incoming information of the remote host

		self.__session = session
		self.__state = SipCall.SESSION_SETUP
		self.__remote_address = conInfo[0]
		self.__remote_sip_port = conInfo[1]
		self.__remote_rtp_port = rtpPort
		self.__msg = invite_message
		# list of messages
		self._msg_stack = []

		self.__call_id = invite_message.headers.get(b"call-id").value
		self._call_id = call_id
		self._rtp_streams = {}

		self.local.host = self.__session.local.host
		self.local.port = self.__session.local.port

		self.remote.host = self.__session.remote.host
		self.remote.port = self.__session.remote.port

		user = self.__msg.headers.get(b"to").get_raw().uri.user

		self._user = g_sipconfig.get_user_by_username(
			self.__session.personality,
			user
		)

		# fake a connection entry
		i = incident("dionaea.connection.udp.connect")
		i.con = self
		i.report()

		global _SipCall_sustain_timeout

		# Global timers
		self._timers = {
			#"idle": pyev.Timer(500, 0, g_default_loop, self.__handle_idle_timeout),
			"invite_handler": pyev.Timer(5.0, 0.0, g_default_loop, self.__handle_invite),
			#pyev.Timer(3, 0, g_default_loop, self.__handle_invite_timeout),
			#"substain": pyev.Timer(_SipCall_sustain_timeout, 0, g_default_loop, self.__handle_sustain_timeout),
		}

		#self._timers["idle"].start()

	def __handle_invite(self, watcher, events):
		logger.info("Handle invite")
		if self.__state == SipCall.INVITE:
			logger.debug("Send TRYING")
			# ToDo: Check authentication
			#self.__authenticate(headers)

			if self._user == None:
				msg = self.__msg.create_response(rfc3261.NOT_FOUND)
				self.send(msg.dumps())
				self.__state = SipCall.NO_SESSION
				return

			msg = self.__msg.create_response(rfc3261.TRYING)

			self.send(msg)

			self.__state = SipCall.INVITE_TRYING
			# Wait up to two seconds
			self._timers["invite_handler"].set(random.random() * 2, 0)
			self._timers["invite_handler"].start()
			return

		if self.__state == SipCall.INVITE_TRYING:
			# Send 180 Ringing to make honeypot appear more human-like
			logger.debug("Send RINGING")
			msg = self.__msg.create_response(rfc3261.RINGING)

			self.send(msg)

			delay = random.randint(self._user.pickup_delay_min, self._user.pickup_delay_max)
			logger.info("Choosing ring delay between {} and {} seconds: {}".format(self._user.pickup_delay_min, self._user.pickup_delay_max, delay))
			self.__state = SipCall.INVITE_RINGING
			self._timers["invite_handler"].set(delay, 0)
			self._timers["invite_handler"].start()
			return

		if self.__state == SipCall.INVITE_RINGING:
			logger.debug("Send OK")

			# Create a stream dump file with date and time and random ID in case of
			# flooding attacks
			global g_sipconfig

			pcap = g_sipconfig.get_pcap()

			# Create RTP stream instance and pass address and port of listening
			# remote RTP host

			sdp = self.__msg.sdp

			media_port_names = g_sipconfig.get_sdp_media_port_names(self._user.sdp)


			media_ports = {}

			for name in media_port_names:
				media_ports[name] = None

			bistream_enabled = False
			if "bistream" in g_sipconfig._rtp.get("mode"):
				bistream_enabled = True

			for name in media_port_names:
				for media in sdp.get(b"m"):
					if media.media.lower() == bytes(name[:5], "utf-8"):
						self._rtp_streams[name] = RtpUdpStream(
							name,
							self,
							self.__session,
							self.__session.local.host,
							0, # random port
							self.__remote_address,
							media.port,
							pcap = pcap,
							bistream_enabled = bistream_enabled
						)
						media_ports[name] = self._rtp_streams[name].local.port
			# ToDo: report
			#
			# i = incident("dionaea.connection.link")
			# i.parent = self
			# i.child = self._rtp_stream
			# i.report()

			# Send 200 OK and pick up the phone
			msg = self.__msg.create_response(rfc3261.OK)

			# ToDo: add IP6 support
			msg.sdp = rfc4566.SDP.froms(
				g_sipconfig.get_sdp_by_name(
					self._user.sdp,
					unicast_address = self.local.host,
					addrtype = "IP4",
					media_ports = media_ports
				)
			)

			msg_stack = self._msg_stack
			msg_stack.append(("out", msg))

			pcap.open(
				msg_stack = msg_stack,
				personality = self.__session.personality,
				local_host = self.local.host,
				local_port = self.local.port,
				remote_host = self.remote.host,
				remote_port = self.remote.port
			)

			self.send(msg)

			self.__state = SipCall.CALL

			# ToDo: Send rtp data?
			return


	def handle_timeout_idle(self):
		logger.debug("{:s} handle_timeout_idle".format(self))
#		logger.warn("self {} IDLE TIMEOUT watcher {}".format(self, watcher))
		self.close()
		return False

	def handle_timeout_sustain(self):
		logger.debug("{:s} handle_timeout_sustain".format(self))
		logger.debug("SipCall.__handle_sustain_timeout self {} watcher {}".format(self, watcher))
		return True

	def __handle_invite_timeout(self, watcher, events):
		msg = self.__msg.create_response(rfc3261.OK)

		self.send(msg)

	def send(self, msg):
		logger.debug("{:s} send".format(self))

		if type(msg) == rfc3261.Message:
			self._msg_stack.append(("out", msg))
			msg = msg.dumps()

		self.__session.send(msg)

	def close(self):
		logger.debug("{:s} close".format(self))

		logger.debug("SipCall.close {} Session {}".format(self, self.__session))

		self.__session.event_call_closed(self._call_id)

		# stop timers
		for name, timer in self._timers.items():
			if timer == None:
				continue

			logger.debug("SipCall timer {} active {} pending {}".format(timer,timer.active,timer.pending))
			#if timer.active == True or timer.pending == True:
			#	logger.warn("SipCall Stopping {}".format(name))

			timer.stop()

		# close rtpStream
		for n,v in self._rtp_streams.items():
			if v != None:
				v.close()

			self._rtp_streams[n] = None

		self._rtp_streams = {}

		# close connection
		connection.close(self)

	def event_stream_closed(self, name):
		logger.debug("{:s} event_stream_closed".format(self))

		self._rtp_streams[name] = None

	def handle_ACK(self, msg_ack):
		logger.debug("{:s} handle_ACK".format(self))

		self._msg_stack.append(("in", msg_ack))
		# does this ACK belong to a CANCEL request?
		if not self.__state == SipCall.INVITE_CANCEL:
			logger.info("No method to cancel")
			return

		cseq = self.__msg.headers.get(b"cseq").get_raw()
		cseq_ack = msg_ack.headers.get(b"cseq").get_raw()

		# does this ACK belong to this session?
		if cseq.seq != cseq_ack.seq:
			logger.info("Sequence number doesn't match INVITE id {}; ACK id {}".format(cseq.seq, cseq_ack.seq))
			return

		self.close()
		return True

	def handle_BYE(self, msg_bye):
		logger.debug("{:s} handle_BYE".format(self))

		self._msg_stack.append(("in", msg_bye))
		if not self.__state == SipCall.CALL:
			logger.info("BYE without call")
			return

		msg = msg_bye.create_response(rfc3261.OK)
		self.send(msg.dumps())
		self.close()
		return True

	def handle_CANCEL(self, msg_cancel):
		logger.debug("{:s} handle_CANCEL".format(self))

		self._msg_stack.append(("in", msg_cancel))
		# Todo:
		#self.__authenticate(headers)
		if not (self.__state == SipCall.INVITE or self.__state == SipCall.INVITE_TRYING or self.__state == SipCall.INVITE_RINGING):
			logger.info("No method to cancel")
			return

		cseq = self.__msg.headers.get(b"cseq").get_raw()
		cseq_cancel = msg_cancel.headers.get(b"cseq").get_raw()

		if cseq.seq != cseq_cancel.seq:
			logger.info("Sequence number doesn't match INVITE id {}; CANCEL id {}".format(cseq.seq, cseq_cancel.seq))
			return

		self.__state = SipCall.INVITE_CANCEL

		self._timers["invite_handler"].stop()

		# RFC3261 send 487 Request Terminated after cancel
		# old RFC2543 don't send 487
		#ToDo: use timeout to close the session
		msg = self.__msg.create_response(rfc3261.REQUEST_TERMINATED)
		self.send(msg.dumps())
		msg = msg_cancel.create_response(rfc3261.OK)
		self.send(msg.dumps())

	def handle_INVITE(self, msg):
		logger.debug("{:s} handle_INVITE".format(self))

		self._msg_stack.append(("in", msg))
		self.__state = SipCall.INVITE
		self._timers["invite_handler"].set(0.1, 0)
		self._timers["invite_handler"].data = msg
		self._timers["invite_handler"].start()
		return True

class SipSession(connection):
	ESTABLISHED, CLOSED = range(2)

	def __init__(self, proto = None):
		logger.debug("{:s} __init__".format(self))

		connection.__init__(self, proto)

		self.personality = g_sipconfig.get_personality_by_address(self.local.host)

		# fake a connection entry
		i = incident("dionaea.connection.udp.connect")
		i.con = self
		i.report()

		# Dictionary with SIP sessions (key is Call-ID)
		self._callids = {}

		logger.info("SIP Session created with personality '{}'".format(self.personality))

		self._timers = {}

		self._auth = None

		self._state = None

		global g_sipconfig

		# Setup timers
		global g_default_loop

		self._timers = {
# ToDo:
#			"idle": pyev.Timer(
#				g_sipconfig.get_timer("idle").timeout,
#				g_sipconfig.get_timer("idle").timeout,
#				g_default_loop,
#				self.__handle_idle_timeout
#			)
		}

		# start idle timer for this session
#		self._timers["idle"].start()

	def handle_established(self):
		logger.debug("{:s} handle_established".format(self))
		self._state = SipSession.ESTABLISHED

		self.timeouts.idle = 10
		self.processors()

	def handle_timeout_sustain(self):
		logger.debug("{:s} handle_timeout_sustain".format(self))
		return True

	def handle_timeout_idle(self):
		logger.debug("{:s} handle_timeout_idle".format(self))
		if len(self._callids) == 0:
			self.close()
			return False
		return True

	def handle_io_in(self, data):
		if self._state == SipSession.CLOSED:
			# Don't process any data while the connection is closed.
			return len(data)

		logger.debug("{:s} handle_io_in".format(self))

		if self.transport == "udp":
			# Header must be terminated by an empty line.
			# If empty line is missing add it.
			# This works only for sip over udp but not for sip over tcp,
			# because one UDP package is exactly one sip message.
			# SIP-Servers like Asterisk do it the same way.
			len_used = len(data)

			if not b"\n\r\n" in data and not b"\n\n" in data:
				data = data + b"\n\r\n"

			# all lines must end with \r\n
			data = data.replace(b"\r\n", b"\n")
			data = data.replace(b"\n", b"\r\n")
			try:
				msg = rfc3261.Message.froms(data)
			except rfc3261.SipParsingError:
				self.close()
				return len_used

		elif self.transport == "tcp":
			try:
				(len_used, data_load) = rfc3261.Message.loads(data)
			except rfc3261.SipParsingError:
				self.close()
				return len(data)

			# this is not the complete message, wait for the rest
			if len_used == 0:
				return 0

			msg = rfc3261.Message(**data_load)
			logger.debug("Got {} bytes, Used {} bytes".format(len(data), len_used))

		msg.set_personality(self.personality)

		# ToDo: report
		# SIP message incident
#		i = incident("dionaea.modules.python.sip.in")
#		i.con = self
#		i.direction = "in"
#		i.msgType = msgType
#		i.firstLine = firstLine
#		i.sipHeaders = headers
#		i.sipBody = body
#		i.report()

		handler_name = msg.method.decode("utf-8").upper()

		if not g_sipconfig.is_handled_by_personality(handler_name, self.personality):
			self.handle_unknown(msg)
			return len(data)

		logger.info("Received: {}".format(handler_name))

		try:
			func = getattr(self, "handle_" + handler_name, None)
		except:
			func = None

		if func is not None and callable(func) == True:
			func(msg)
		else:
			self.handle_unknown(msg)

		logger.debug("io_in: returning {}".format(len_used))
		return len_used

	def close(self):
		self._state = SipSession.CLOSED

		logger.debug("{:s} close".format(self))

		logger.debug("SipSession.close {}".format(self))
		# close all calls
		for callid in [x for x in self._callids]:
#			logger.debug("closing callid {} call {}".format(callid, self._callids[callid]))
			call = self._callids[callid]
			self._callids[callid] = None
			call.close()

		self._callids = {}

		# stop timers
		for name, timer in self._timers.items():
			logger.debug("SipSession timer {} name {} active {} pending {}".format(timer,name, timer.active,timer.pending))
			if timer.active == True or t.pending == True:
#				logger.debug("SipSession Stopping {}".format(t))
				timer.stop()

		connection.close(self)

	def event_call_closed(self, call_id):
		self._callids[call_id] = None

	def handle_unknown(self, msg):
		logger.debug("{:s} unknown".format(self))
		logger.warn("Unknown SIP header: {}".format(repr(msg.method)[:128]))

		res = msg.create_response(rfc3261.NOT_IMPLEMENTED)
		d = res.dumps()
		self.send(res.dumps())


	def handle_ACK(self, msg):
		logger.debug("{:s} handle_ACK".format(self))

		#if self.__checkForMissingHeaders(headers):
		#	return

		# Check if session (identified by Call-ID) exists
		# ToDo: check if call-id header exist
		call_id = msg.headers.get(b"call-id").value

		if call_id not in self._callids:
			logger.warn("Given Call-ID does not belong to any session: exit")
			# ToDo: error
			return

		try:
			# Handle incoming ACKs depending on current state
			self._callids[call_id].handle_ACK(msg)
		except AuthenticationError:
			# ToDo error handling
			logger.warn("Authentication failed for ACK request")


	def handle_BYE(self, msg):
		logger.debug("{:s} handle_BYE".format(self))

		#if self.__checkForMissingHeaders(headers):
		#	return

		# Check if session (identified by Call-ID) exists
		call_id = msg.headers.get(b"call-id").value
		if call_id not in self._callids:
			logger.warn("Given Call-ID does not belong to any session: exit")
			# ToDo: error
			return

		try:
			# Handle incoming BYE request depending on current state
			self._callids[call_id].handle_BYE(msg)
		except AuthenticationError:
			# ToDo: handle
			logger.warn("Authentication failed for BYE request")


	def handle_CANCEL(self, msg):
		logger.debug("{:s} handle_CANCEL".format(self))

		# ToDo: Check mandatory headers, check for problems with some scanners
		#if self.__checkForMissingHeaders(headers):
		#	return

		# Get Call-Id and check if there's already a SipSession
		call_id = msg.headers.get(b"call-id").value

		cseq = msg.headers.get(b"cseq").get_raw()

		# Find SipSession and delete it
		if call_id not in self._callids or self._callids[call_id] == None:
			logger.warn("CANCEL request does not match any existing SIP session")
			self.send(msg.create_response(rfc3261.CALL_TRANSACTION_DOSE_NOT_EXIST).dumps())
			return

		try:
			self._callids[call_id].handle_CANCEL(msg)
		except AuthenticationError:
			logger.warn("Authentication failed for CANCEL request")


	def handle_INVITE(self, msg):
		logger.debug("{:s} handle_INVITE".format(self))

		global g_sipconfig

		# ToDo: content-length? also for udp or only for tcp?
		if not msg.headers_exist([b"content-type"]):
			logger.warn("INVITE without accept and content-type")
			# ToDo: return error
			return

		# Header has to define Content-Type: application/sdp if body contains
		# SDP message. Also, Accept has to be set to sdp so that we can send
		# back a SDP response.
		if msg.headers.get("content-type").value.lower() != b"application/sdp":
			# ToDo: error
			logger.warn("INVITE without SDP message: exit")
			return

		#if msg.headers.get("accept").value.lower() != "application/sdp":
		#	logger.warn("INVITE without SDP message: exit")
			# ToDo: error
		#	return

		if msg.sdp == None:
			logger.warn("INVITE without SDP message: exit")
			# ToDo: error
			return

		# Get RTP port from SDP media description
		medias = msg.sdp[b"m"]
		if len(medias) < 1:
			logger.warn("SDP message has to include a media description: exit")
			# ToDo: error
			return

		audio = None
		for media in medias:
			if media.media.lower() == b"audio":
				audio = media
				# ToDo: parse the rest to find the best one
				break

		if audio == None:
			logger.warn("SDP media description has to be of audio type: exit")
			return

		# Read Call-ID field and create new SipCall instance on first INVITE
		# request received (remote host might send more than one because of time
		# outs or because he wants to flood the honeypot)
		logger.debug("Currently active sessions: {}".format(self._callids))
		call_id = msg.headers.get(b"call-id").value

		if call_id in self._callids:
			logger.warn("SIP session with Call-ID {} already exists".format(
				call_id))
			# ToDo: error
			return

		# Establish a new SIP Call
		new_call = SipCall(
			self.transport,
			call_id,
			self,
			(self.remote.host, self.remote.port),
			audio.port,
			msg
		)

		# Store session object in sessions dictionary
		self._callids[call_id] = new_call

		i = incident("dionaea.connection.link")
		i.parent = self
		i.child = new_call
		i.report()

		try:
			r = new_call.handle_INVITE(msg)
		except AuthenticationError:
			logger.warn("Authentication failed, not creating SIP session")
			new_call.close()
			del new_call


	def handle_OPTIONS(self, msg):
		logger.debug("{:s} handle_OPTIONS".format(self))

		res = msg.create_response(rfc3261.OK)
		res.headers.append(rfc3261.Header(name = "Accept", value = "application/sdp"))
		res.headers.append(rfc3261.Header(name = "Accept-Language", value = "en"))

		self.send(res.dumps())


	def handle_REGISTER(self, msg):
		"""
		:See: http://tools.ietf.org/html/rfc3261#section-10
		"""
		logger.debug("{:s} handle_REGISTER".format(self))

		# ToDo: check for request-uri?
		if not msg.headers_exist([b"to", b"from", b"call-id", b"cseq"]):
			logger.warn("REGISTER, header missing")
			# ToDo: return error
			return

		to = msg.headers.get(b"to")
		user_id = to.get_raw().uri.user

		u = g_sipconfig.get_user_by_username(self.personality, user_id)

		# given user not found
		if u == None:
			res = msg.create_response(rfc3261.NOT_FOUND)
			self.send(res.dumps())
			return

		if u.password != None and u.password != "":
			header_auth = msg.headers.get(b"authorization", None)
			if header_auth == None or self._auth == None:
				# ToDo: change nonce
				self._auth = rfc2617.Authentication(
					method = "digest",
					algorithm = "md5",
					nonce = "foobar123",
					realm = u.realm
				)
				res = msg.create_response(rfc3261.UNAUTHORIZED)
				res.headers.append(rfc3261.Header(name = b"www-authenticate", value = self._auth))
				self.send(res.dumps())
				return

			auth_response = rfc2617.Authentication.froms(header_auth[0].value)

			# ToDo: change realm
			if self._auth.check(u.username, u.password, "REGISTER", auth_response) == False:
				# ToDo: change nonce
				self._auth = rfc2617.Authentication(
					method = "digest",
					algorithm = "md5",
					nonce = b"foobar123",
					realm = u.realm
				)
				res = msg.create_response(rfc3261.UNAUTHORIZED)
				res.headers.append(rfc3261.Header(name =  b"www-authenticate", value = self._auth))
				self.send(res.dumps())
				return

			# ToDo: Report authentication incident
			#i = incident("dionaea.modules.python.sip.authentication")
			#i.authenticationSuccessful = expected == authLineDict['response']
			#i.realm = realm
			#i.uri = uri
			#i.nonce = authLineDict['nonce']
			#i.challengeResponse = authLineDict['response']
			#i.expected = expected
			#i.report()


		user = User(user_id, msg = msg)
		g_reg_manager.register(user)

		res = msg.create_response(rfc3261.OK)
		self.send(res.dumps())

	def send(self, s):
		logger.debug("{:s} send".format(self))

		logger.debug('Sending message "{}" to ({}:{})'.format(
			s, self.remote.host, self.remote.port))

		# ToDo: SIP response incident
#		i = incident("dionaea.modules.python.sip.out")
#		i.con = self
#		i.direction = "out"
#		i.msgType = "RESPONSE"
#		i.message = s
#		i.report()

		connection.send(self, s)
