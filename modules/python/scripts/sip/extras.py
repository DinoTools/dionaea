"""
Some helper functions.
"""
import datetime
import logging
import os
import pprint
import re
import sqlite3
import struct
import tempfile
import time

from dionaea.core import g_dionaea

logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)

DEFAULT_SDP = """
v=0
o=- 1304279835 1 IN {addrtype} {unicast_address}
s=SIP Session
c=IN {addrtype} {unicast_address}
t=0 0
m=audio {media_port} RTP/AVP 111 0 8 9 101 120
a=sendrecv
a=rtpmap:111 Speex/16000/1
a=fmtp:111 sr=16000,mode=any
a=rtpmap:0 PCMU/8000/1
a=rtpmap:8 PCMA/8000/1
a=rtpmap:9 G722/8000/1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16,32,36
a=rtpmap:120 NSE/8000
a=fmtp:120 192-193
"""


def int2bytes(value):
	"""
	Convert integer to bytes
	"""
	return bytes(str(value), "utf-8")


class SipConfig(object):
	"""
	This class helps to access the config values.
	"""

	def __init__(self, config = {}):
		"""
		:param config: The config dict from dionaea
		:type config: Dict

		"""

		self.root_path = os.getcwd()

		self.users = os.path.join(self.root_path, config.get("users", "var/dionaea/sipaccounts.sqlite"))

		self._conn = sqlite3.connect(self.users)
		self._cur = self._conn.cursor()

		if not self._table_exists("users"):
			self._cur.execute("CREATE TABLE IF NOT EXISTS users (username STRING, password STRING, personality STRING, pickup_delay_min INTEGER, pickup_delay_max INTEGER, action STRING, sdp STRING)")
			# example without password
			self._cur.execute("INSERT INTO users (username, password, personality, pickup_delay_min, pickup_delay_max, action, sdp) VALUES ('^[1-9][0-9]{0,4}$', '', 'default', 5, 10, 'default', 'default')")
			# example with password
			self._cur.execute("INSERT INTO users (username, password, personality, pickup_delay_min, pickup_delay_max, action, sdp) VALUES ('^pw[1-9][0-9]{0,4}$', 'password', 'default', 5, 10, 'default', 'default')")

		if not self._table_exists("sdp"):
			self._cur.execute("CREATE TABLE IF NOT EXISTS sdp (name STRING, sdp STRING)")
			self._cur.execute("INSERT INTO sdp (name, sdp) VALUES ('default', ?)", (DEFAULT_SDP,))

		# set default values
		self.personalities = {
			"default": {
				"domain": "localhost",
				"name": "",
				"personality": "generic",
				"serve": [],
				"default_sdp": "default",
				"handle": ["REGISTER", "OPTIONS", "INVITE", "CANCEL", "BYE", "ACK"]
			}
		}

		for pers_name, personality in config.get("personalities", {}).items():
			if not pers_name in self.personalities:
				self.personalities[pers_name] = {}

			for n in ["domain", "name", "personality", "serve", "default_sdp", "handle"]:
				v = personality.get(n, self.personalities["default"][n])
				if type(v) != type(self.personalities["default"][n]):
					v = self.personalities["default"][n]
				# convert values
				if n == "handle":
					# convert all values to uppercase
					v = [t.upper() for t in v]

				self.personalities[pers_name][n] = v

		self.actions = config.get("actions", {})

		# ToDo: read values from config
		# set default values
		self.timers = {
			"idle": {
				"timeout": 30
			}
		}

		self._rtp = config.get("rtp", {})

		rtp_enable = self._rtp.get("enable", "no")
		if rtp_enable.lower() == "yes":
			self._rtp["enable"] = True
		else:
			self._rtp["enable"] = False

		self.actions = config.get("actions", {})


	def _table_exists(self, name):
		"""
		Check if table exists
		"""
		ret = self._cur.execute("SELECT name FROM sqlite_master WHERE type='table' and name=?", (name,))
		if ret.fetchone() == None:
			return False
		return True


	def get_action(self, name):
		# ToDo:
		#return (func, params)
		pass


	def get_handlers_by_personality(self, personality):
		if not personality in self.personalities:
			personality = "default"

		return self.personalities[personality]["handle"]

	def get_timer(self, name):
		if not name in self.timers:
			return False

		timer = self.timers[name]

		return Timer(
			timeout = timer["timeout"]
		)


	def get_user_by_username(self, personality, username):
		conn = sqlite3.connect(self.users)
		def regexp(expr, value):
			if type(expr) != str:
				expr = str(expr)
			regex = re.compile(expr)
			return regex.match(value) is not None

		sqlite3.enable_callback_tracebacks(True)
		conn.create_function("regexp", 2, regexp)

		if username == None:
			username = b""

		username = username.decode("utf-8")

		cur = conn.cursor()
		cur.execute("SELECT username, password, pickup_delay_min, pickup_delay_max, action, sdp FROM users WHERE personality = ? AND ? REGEXP username", (personality, username))
		row = cur.fetchone()

		if row == None:
			return None

		password = row[1]
		if type(password) == int:
			password = str(password)

		sdp = row[5]
		if sdp == '' or sdp == None:
			sdp = self.personalities[personality].default_sdp

		return User(
			username = username,
			username_regex = row[0],
			password = password,
			pickup_delay_min = row[2],
			pickup_delay_max = row[3],
			action = row[4],
			sdp = row[5]
		)


	def get_personality_by_address(self, address):
		for pers_name, personality in self.personalities.items():
			for serve in personality["serve"]:
				if serve == address:
					return pers_name
		return "default"


	def get_rtp(self):
		return RTP(
			path = self._rtp.get("path", "var/dionaea/rtp/{personality}/%Y-%m-%d/"),
			filename = self._rtp.get("filename", "%H:%M:%S_{remote_host}_{remote_port}_in.rtp"),
			enable = self._rtp.get("enable", False),
			mode = self._rtp.get("mode", ["pcap"])
		)


	def get_sdp_by_name(self, name, **params):
		"""
		Fetch the SDP content from the database and add missing values.
		"""
		logger.debug("Loading sdp with: {}".format(pprint.pformat(params)))
		ret = self._cur.execute("SELECT sdp FROM sdp WHERE name='?'")
		data = ret.fetchone()

		if data == None:
			# try to fetch the default sdp from the db
			ret = self._cur.execute("SELECT sdp FROM sdp WHERE name='default'")
			data = ret.fetchone()

		if data == None:
			data = (DEFAULT_SDP,)

		sdp = data[0]
		sdp = sdp.format(**params)
		return bytes(sdp, "utf-8")


	def is_handled_by_personality(self, handler_name, personality = "default"):
		"""
		Check if dionaea handles the given SIP-Method
		"""
		if personality in self.personalities:
			personality = "default"

		if handler_name.upper() in self.personalities[personality]["handle"]:
			return True

		return False


class RTP(object):
	"""
	PCAP-Format see: http://wiki.wireshark.org/Development/LibpcapFileFormat
	"""
	def __init__(self, path, filename, enable = False, mode = ["pcap"]):
		self.path = path
		self.filename = filename
		self.enable = enable
		self._modes = mode

		if type(self._modes) != list:
			self.modes = [self._modes]

		self._params = {}
		for n in ["personality", "local_host", "local_port", "remote_host", "remote_port"]:
			self._params[n] = n

		self._bistream = []

		self._pcap = None

	def _carry_arround_add(self, a, b):
		c = a + b
		return (c & 0xffff) + (c >> 16)

	def _ip_checksum(self, data):
		s = 0
		for i in range(0, len(data), 2):
			word = data[i] + (data[i + 1] << 8)
			s = self._carry_arround_add(s, word)
		return ~s & 0xffff

	def close(self):
		if self._pcap != None:
			self._pcap.close()

		if "bistream" in self._modes:
			logger.debug("SipCall: RTP.close() write bistream")
			if len(self._bistream) > 0:
				now = datetime.datetime.now()
				dirname = "%04i-%02i-%02i" % (now.year, now.month, now.day)
				bistream_path = os.path.join(g_dionaea.config()['bistreams']['python']['dir'], dirname)
				if not os.path.exists(bistream_path):
					os.makedirs(bistream_path)

				fp = tempfile.NamedTemporaryFile(
					delete = False,
					prefix = "SipCall-{local_port}-{remote_host}:{remote_port}-".format(**self._params),
					dir = bistream_path
				)
				fp.write(b"stream = ")
				fp.write(str(self._bistream).encode())
				fp.close()

	def open(self, **params):
		if self.enable == False:
			logger.info("RTP-Capture NOT enabled")
			return

		self._params.update(params)

		if "pcap" in self._modes:
			path = self.path.format(**params)
			today = datetime.datetime.now()
			path = today.strftime(path)
			#'%H:%M:%S_{remote_host}_{remote_port}_in.rtp'
			filename = today.strftime(self.filename)
			filename = filename.format(**params)
			# ToDo: error check
			try:
				os.makedirs(path)
			except:
				logger.info("Can't create RTP-Dump dir: {}".format(path))
			try:
				self._pcap = open(os.path.join(path, filename), "wb")
			except:
				logger.warning("Can't create RTP-Dump file: {}".format(os.path.join(path, filename)))

			# write pcap global header
			self._pcap.write(b"\xd4\xc3\xb2\xa1")
			# version 2.4
			self._pcap.write(b"\x02\x00\x04\x00")
			# GMT to local correction
			self._pcap.write(b"\x00\x00\x00\x00")
			# accuracy of timestamps
			self._pcap.write(b"\x00\x00\x00\x00")
			# max length of captured packets, in octets
			self._pcap.write(b"\xff\xff\x00\x00")
			# data link type (1 = Ethernet) http://www.tcpdump.org/linktypes.html
			self._pcap.write(b"\x01\x00\x00\x00")

	def write(self, data):
		t = time.time()
		ts = int(t)
		tm = int((t - ts) * 1000000)
		if "bistream" in self._modes:
			self._bistream.append(("in", data))

		if self._pcap != None:
			# udp packet
			udp = struct.pack(">H", 5061)  # port src
			udp = udp + struct.pack(">H", 5061) # port dst
			udp = udp + struct.pack(">H", len(data) + 8) # length
			udp = udp + struct.pack(">H", 0) # checksum
			udp = udp + data

			ip = b"\x45" # version + header length 20bytes
			ip = ip + b"\x00"
			ip = ip + struct.pack(">H", len(udp) + 20) # pkt length
			ip = ip + b"\x00\x00" # identification
			ip = ip + b"\x40\x00" # flags(do not fragment) + fragment offset(0)
			ip = ip + b"\x40\x11" # ttl(64) + protocol(udp)
			ip = ip + b"\x00\x00" # header checksum
			ip = ip + b"\x0A\x00\x00\x01" # ip src
			ip = ip + b"\x0A\x00\x00\x02" # ip dst

			# add checksum to ip header
			ip = ip[:10] + struct.pack("<H", self._ip_checksum(ip)) + ip[12:]

			ether = b"\x00\x00\x00\x00\x00\x02" # MAC src
			ether = ether + b"\x00\x00\x00\x00\x00\x01" # MAC dst
			ether = ether + b"\x08\x00" # pkt type IPv4

			pkt = ether + ip + udp
			# pcap packet header
			pcap = struct.pack("i", ts) # time seconds
			pcap = pcap + struct.pack("i", tm) # microseconds
			pcap = pcap + struct.pack("i", len(pkt)) # length captured
			pcap = pcap + struct.pack("i", len(pkt)) # real length
			pcap = pcap + pkt

			self._pcap.write(pcap)

class Timer(object):
	def __init__(self, **kwargs):
		self.timeout = kwargs.get("timeout", 30)


class User(object):
	def __init__(self, **kwargs):
		self.realm = kwargs.get("realm", "test")
		self.username = kwargs.get("username", "")
		self.username_regex = kwargs.get("username_regex", "")
		self.password = kwargs.get("password", "")
		self.pickup_delay_min = kwargs.get("pickup_delay_min", 5)
		self.pickup_delay_max = kwargs.get("pickup_delay_max", 10)
		self.action = kwargs.get("action", "default")
		self.sdp = kwargs.get("sdp", "default")
