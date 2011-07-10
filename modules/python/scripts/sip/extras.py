"""
Some helper functions.
"""
import os
import re
import sqlite3

DEFAULT_SDP = """
v=0
o=- 1304279835 1 IN {addrtype} {unicast_address}
s=SIP Session
c=IN {addrtype} {unicast_address}
t=0 0
m=audio 5074 RTP/AVP 111 0 8 9 101 120
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

		print(self.users)
		self._conn = sqlite3.connect(self.users)
		self._cur = self._conn.cursor()

		if not self._table_exists("users"):
			self._cur.execute("CREATE TABLE IF NOT EXISTS users (username STRING, password STRING, personality STRING, pickup_delay_min INTEGER, pickup_delay_max INTEGER, action STRING, sdp STRING)")
			self._cur.execute("INSERT INTO users (username, password, personality, pickup_delay_min, pickup_delay_max, action, sdp) VALUES ('^[1-9][0-9]{0,4}$', '', 'default', 5, 10, 'default', 'default')")

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
				"default_sdp": "default"
			}
		}

		for pers_name, personality in config.get("personalities", {}).items():
			if not pers_name in self.personalities:
				self.personalities[pers_name] = {}

			for n in ["domain", "name", "personality", "serve", "default_sdp"]:
				v = personality.get(n, self.personalities["default"][n])
				if type(v) != type(self.personalities["default"][n]):
					v = self.personalities["default"][n]

				self.personalities[pers_name][n] = v

		self.actions = config.get("actions", {})

		# ToDo: read values from config
		# set default values
		self.timers = {
			"idle": {
				"timeout": 30
			}
		}

		rtp = config.get("rtp", {})

		rtp_enable = rtp.get("enable", "no")
		if rtp_enable.lower() != "yes":
			self.rtp_enable = True
		else:
			self.rtp_enable = False

		self.rtp_dumps = os.path.join(self.root_path, rtp.get("dumps", "var/dionaea/rtp/$(personality)/%Y-%M-%d/"))
		self.actions = config.get("actions", {})


	def _table_exists(self, name):
		"""
		Check if table exists
		"""
		print(name)
		ret = self._cur.execute("SELECT name FROM sqlite_master WHERE type='table' and name=?", (name,))
		if ret.fetchone() == None:
			return False
		return True


	def get_action(self, name):
		# ToDo:
		#return (func, params)
		pass


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
			print("----", type(expr), type(value))
			regex = re.compile(expr)
			return regex.match(value) is not None
		sqlite3.enable_callback_tracebacks(True)
		regexp("200", "500")
		conn.create_function("regexp", 2, regexp)

		if username == None:
			username = b""

		username = username.decode("utf-8")

		cur = conn.cursor()
		cur.execute("SELECT username, password, pickup_delay_min, pickup_delay_max, action, sdp FROM users WHERE personality = ? AND ? REGEXP username", (personality, username))
		row = cur.fetchone()

		if row == None:
			return None

		sdp = row[5]
		if sdp == '' or sdp == None:
			sdp = self.personalities[personality].default_sdp

		return User(
			username = username,
			username_regex = row[0],
			password = row[1],
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


	def get_sdp_by_name(self, name, **params):
		"""
		Fetch the SDP content from the database and add missing values.
		"""
		print(params)
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
