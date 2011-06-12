"""
Some helper functions.
"""
import os
import re
import sqlite3

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
		conn = sqlite3.connect(self.users)
		cur = conn.cursor()
		cur.execute("CREATE TABLE IF NOT EXISTS users (username STRING, password STRING, personality STRING, pickup_delay_min INTEGER, pickup_delay_max INTEGER, action)")

		# set default values
		self.personalities = {
			"default": {
				"domain": "localhost",
				"name": "",
				"personality": "generic",
				"serve": []
			}
		}

		for pers_name, personality in config.get("personalities", {}).items():
			if not pers_name in self.personalities:
				self.personalities[pers_name] = {}

			for n in ["domain", "name", "personality", "serve"]:
				v = personality.get(n, self.personalities["default"][n])
				if type(v) != type(self.personalities["default"][n]):
					v = self.personalities["default"][n]

				self.personalities[pers_name][n] = v

		self.actions = config.get("actions", {})

		rtp = config.get("rtp", {})

		rtp_enable = rtp.get("enable", "no")
		if rtp_enable.lower() != "yes":
			self.rtp_enable = True
		else:
			self.rtp_enable = False

		self.rtp_dumps = os.path.join(self.root_path, rtp.get("dumps", "var/dionaea/rtp/$(personality)/%Y-%M-%d/"))
		self.actions = config.get("actions", {})


	def get_action(self, name):
		# ToDo:
		#return (func, params)
		pass


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

		cur = conn.cursor()
		cur.execute("SELECT username, password, pickup_delay_min, pickup_delay_max FROM users WHERE personality = ? AND ? REGEXP username", (personality, username.decode("utf-8")))
		row = cur.fetchone()

		if row == None:
			return None

		# ToDo: add action
		return User(
			username = username,
			username_regex = row[0],
			password = row[1],
			pickup_delay_min = row[2],
			pickup_delay_max = row[3],
		)


	def get_personality_by_address(self, address):
		for pers_name, personality in self.personalities.items():
			for serve in personality["serve"]:
				if serve == address:
					return pers_name
		return "default"

class User(object):
	def __init__(
		self,
		username,
		username_regex,
		password,
		pickup_delay_min,
		pickup_delay_max
	):
		self.username = username
		self.username_regex = username_regex
		self.password = password
		self.pickup_delay_min = pickup_delay_min
		self.pickup_delay_max = pickup_delay_max
