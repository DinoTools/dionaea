"""
This package implements RFC 4566

:See: http://tools.ietf.org/html/rfc4566
"""

import time

try:
	from dionaea.sip.extras import int2bytes
except:
	from extras import int2bytes

class Attribute(object):
	"""
	"Attributes are the primary means for extending SDP."

	Format: a=<attribute>
	Format: a=<attribute>:<value>

	:See: http://tools.ietf.org/html/rfc4566#page-21

	>>> s = b"tool:foo"
	>>> a = Attribute(s)
	>>> print(a.dumps() == s)
	True
	>>> print(a.value, a.attribute)
	b'foo' b'tool'
	>>> s = b"sendrecv"
	>>> a = Attribute(s)
	>>> print(a.dumps() == s)
	True
	>>> print(a.attribute)
	b'sendrecv'
	>>> print(a.value == None)
	True
	"""

	def __init__(self, data = None, attribute = None, value = None):
		self.attribute = attribute
		self.value = value

		if data != None:
			self.loads(data)

		# we need at least a name
		if self.attribute == None or self.attribute == b"":
			raise Exception("Error", "Error")

	def loads(self, data):
		self.attribute, sep, v = data.partition(b":")
		if v == b"":
			return

		self.value = v

	def dumps(self):
		if self.value == None:
			return self.attribute

		return b":".join([self.attribute, self.value])

class Attributes(object):
	"""
	Handle a list of attributes
	"""

	def __init__(self):
		self._attributes = []

	def __iter__(self):
		return iter(self._attributes)

	def append(self, data):
		if type(data) == bytes:
			self._attributes.append(Attribute(data))
			return

		self._attributes.append(data)

	def get(self, name, default = None):
		"""
		Get the first attribute with the specified name.
		"""

		for a in self._attributes:
			if name == a.attribute:
				return a

	def get_list(self, name):
		"""
		Get a list of all attributes with the specified name.
		"""
		ret = []
		for a in self._attributes:
			if name == a.attribute:
				ret.append(a)

		return ret

	def get_value(self, name, default = None):
		"""
		Get the value of a specified attribute.
		"""
		attr = self.get(name, default)
		if attr == default:
			return None

		return attr.value

class Bandwidth(object):
	"""
	Format: b=<bwtype>:<bandwidth>

	:See: http://tools.ietf.org/html/rfc4566#page-16

	# Example taken from RFC4566
	>>> s = b"X-YZ:128"
	>>> b = Bandwidth(s)
	>>> print(b.dumps() == s)
	True
	>>> print(b.bwtype)
	b'X-YZ'
	>>> print(b.bandwidth)
	128
	"""

	def __init__(self, value = None):
		self.bwtype = None
		self.bandwidth = None

		if value != None:
			self.loads(value)

	def loads(self, value):
		self.bwtype, self.bandwidth = value.split(b":")
		self.bandwidth = int(self.bandwidth)

	def dumps(self):
		return b":".join([self.bwtype, int2bytes(self.bandwidth)])

class ConnectionData(object):
	"""
	"The "c=" field contains connection data."

	Format: c=<nettype> <addrtype> <connection-address>

	:See: http://tools.ietf.org/html/rfc4566#page-14

	Test values are taken from RFC4566

	>>> s = b"IN IP4 224.2.36.42/127"
	>>> c = ConnectionData(s)
	>>> print(c.dumps() == s)
	True
	>>> print(str(c.ttl), c.connection_address, c.addrtype, c.nettype)
	127 b'224.2.36.42' b'IP4' b'IN'
	>>> s = b"IN IP4 224.2.1.1/127/3"
	>>> c = ConnectionData(s)
	>>> print(c.dumps() == s)
	True
	>>> print(str(c.number_of_addresses), str(c.ttl), c.connection_address, c.addrtype, c.nettype)
	3 127 b'224.2.1.1' b'IP4' b'IN'
	"""

	def __init__(self, value):
		self.nettype = None
		self.addrtype = None
		self.connection_address = None
		self.ttl = None
		self.number_of_addresses = None

		if value != None:
			self.loads(value)

	def loads(self, value):
		self.nettype, self.addrtype, con_addr = value.split(b" ")
		con_values = con_addr.split(b"/")
		self.connection_address = con_values[0]

		if self.addrtype == b"IP4":
			if len(con_values) > 1:
				self.ttl = int(con_values[1])
			if len(con_values) > 2:
				self.number_of_addresses = int(con_values[2])
		# ToDo: IP6?

	def dumps(self):
		addr = self.connection_address
		if self.addrtype == b"IP4":
			if self.ttl != None:
				addr = addr + b"/" + int2bytes(self.ttl)
			if self.ttl != None and self.number_of_addresses != None:
				addr = addr + b"/" + int2bytes(self.number_of_addresses)

		# ToDo: IP6

		return b" ".join([self.nettype, self.addrtype, addr])

class Media(object):
	"""
	"A session description may contain a number of media descriptions."

	Format: m=<media> <port>/<number of ports> <proto> <fmt> ...

	:See: http://tools.ietf.org/html/rfc4566#page-22

	>>> s = b"video 49170/2 RTP/AVP 31"
	>>> m = Media(s)
	>>> print(m.dumps() == s)
	True
	>>> print(m.fmt, m.proto, m.number_of_ports, m.port, m.media)
	[b'31'] b'RTP/AVP' 2 49170 b'video'
	>>> s = b"audio 49170 RTP/AVP 31"
	>>> m = Media(s)
	>>> print(m.dumps() == s)
	True
	>>> print(m.fmt, m.proto, m.number_of_ports, m.port, m.media)
	[b'31'] b'RTP/AVP' None 49170 b'audio'
	"""

	def __init__(self, value = None):
		self.media = None
		self.port = None
		self.number_of_ports = None
		self.proto = None
		self.fmt = None
		self.attributes = Attributes()

		if value != None:
			self.loads(value)

	def loads(self, value):
		self.media, ports, self.proto, rest = value.split(b" ", 3)
		# Media: currently defined media are "audio", "video", "text", "application", and "message"
		# check if we support the type and if not send an error?

		# ToDo: error on wrong format?
		port, sep, ports = ports.partition(b"/")
		self.port = int(port)
		if ports != b"":
			self.number_of_ports = int(ports)

		# ToDo: better fmt handling
		self.fmt = rest.split(b" ")

	def dumps(self):
		# ToDo: better fmt handling
		fmt = b" ".join(self.fmt)

		ports = int2bytes(self.port)

		if self.number_of_ports != None:
			ports = ports + b"/" + int2bytes(self.number_of_ports)

		return b" ".join([self.media, ports, self.proto, fmt])


class Origin(object):
	"""
	"The "o=" field gives the originator of the session (her username and the address of the user's host) plus a session identifier and version number"

	:See: http://tools.ietf.org/html/rfc4566#page-11

	>>> s = b"Foo 12345 12345 IN IP4 192.168.1.1"
	>>> o = Origin(s)
	>>> print(s == o.dumps())
	True
	"""
	def __init__(self, value = None):
		t = int(time.time())
		# ToDo: IP6 support
		self.username, self.sess_id, self.sess_version, self.nettype, self.addrtype, self.unicast_address = \
			b"-", t, t, b"IN", b"IP4", b"127.0.0.1"

		if value != None:
			self.loads(value)


	def loads(self, value):
		self.username, self.sess_id, self.sess_version, self.nettype, self.addrtype, self.unicast_address = value.split(b" ")
		self.sess_id = int(self.sess_id)
		self.sess_version = int(self.sess_version)

	def dumps(self):
		return b" ".join([self.username, int2bytes(self.sess_id), int2bytes(self.sess_version), self.nettype, self.addrtype, self.unicast_address])


class SDP(object):
	"""
	Example taken from RFC4566 p.10 See: http://tools.ietf.org/html/rfc4566#page-10
	>>> s = b"v=0\\r\\n"
	>>> s = s + b"o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\\r\\n"
	>>> s = s + b"s=SDP Seminar\\r\\n"
	>>> s = s + b"i=A Seminar on the session description protocol\\r\\n"
	>>> s = s + b"u=http://www.example.com/seminars/sdp.pdf\\r\\n"
	>>> s = s + b"e=j.doe@example.com (Jane Doe)\\r\\n"
	>>> s = s + b"c=IN IP4 224.2.17.12/127\\r\\n"
	>>> s = s + b"t=2873397496 2873404696\\r\\n"
	>>> s = s + b"a=recvonly\\r\\n"
	>>> s = s + b"m=audio 49170 RTP/AVP 0\\r\\n"
	>>> s = s + b"m=video 51372 RTP/AVP 99\\r\\n"
	>>> s = s + b"a=rtpmap:99 h263-1998/90000\\r\\n"
	>>> sdp = SDP(s)
	>>> #print(str(s, "utf-8"), "--", str(sdp.dumps(), "utf-8"))
	>>> #print(sdp.dumps(), s)
	>>> print(sdp.dumps() == s)
	True
	"""

	_must = ["v", "s"]
	_once = ["u", "c"]
	_multi = []
	_attributes_allowed = [b"v", b"o", b"s", b"i", b"u", b"e", b"p", b"c", b"b", b"t", b"r", b"z", b"a", b"m"]


	def __init__(self, data):
		self._attributes = {
			b"a": None, # Attributes
			b"b": None, # Bandwidth
			b"c": None, # Connection Data
			b"e": None, # Email Address
			b"i": None, # Session Information
			b"k": None, # Encryption Keys
			b"m": None, # Media Description
			b"o": None, # Origin
			b"p": None, # Phone Number
			b"r": None, # Repeat Times
			b"s": None, # Session Name
			b"t": None, # Timing
			b"u": None, # URI
			b"v": None, # Protocol Version
			b"z": None, # Time Zone
		}

		if data != None:
			self.loads(data)

	def __getitem__(self, name):
		return self.get(name)

	def loads(self, data):
		data = data.replace(b"\r\n", b"\n")
		for line in data.split(b"\n"):
			k, sep, v = line.partition(b"=")
			if k == b"v":
				self._attributes[k] = int(v)
			elif k == b"o":
				self._attributes[k] = Origin(v)
			elif k == b"c":
				self._attributes[k] = ConnectionData(v)
			elif k == b"b":
				self._attributes[k] = Bandwidth(v)
			elif k == b"t":
				self._attributes[k] = Timing(v)
			elif k == b"r":
				# ToDo: parse it
				self._attributes[k] = v
			elif k == b"z":
				# ToDo: parse it
				self._attributes[k] = v
			elif k == b"a":
				if self._attributes[b"m"] == None:
					# append attribute to session
					if self._attributes[k] == None:
						self._attributes[k] = Attributes()
					self._attributes[k].append(v)
				else:
					# append attribute to media
					self._attributes[b"m"][-1].attributes.append(v)

			elif k == b"m":
				if self._attributes[k] == None:
					self._attributes[k] = []
				self._attributes[k].append(Media(v))

			elif k in self._attributes_allowed:
				self._attributes[k] = v

	def dumps(self):
		ret = []
		for k in self._attributes_allowed:
			v = self._attributes[k]
			if v == None:
				continue

			if type(v) != list and type(v) != Attributes:
				v = [v]

			for v2 in v:
				if type(v2) == int:
					d = int2bytes(v2)
				elif type(v2) == bytes:
					d = v2
				else:
					d = v2.dumps()

				ret.append(b"=".join([k, d]))
				if k != b"m":
					# continue with next value if it isn't a media
					continue

				for attr in v2.attributes:
					ret.append(b"=".join([b"a", attr.dumps()]))

		ret.append(b"")

		return b"\r\n".join(ret)

	def get(self, name):
		return self._attributes.get(name, None)


class Timing(object):
	"""

	Format: t=<start-time> <stop-time>

	:See: http://tools.ietf.org/html/rfc4566#page-17
	"""

	def __init__(self, value = None):
		self.start_time = None
		self.stop_time = None

		if value != None:
			self.loads(value)

	def loads(self, value):
		self.start_time, self.stop_time = value.split(b" ", 1)
		self.start_time = int(self.start_time)
		self.stop_time = int(self.stop_time)

	def dumps(self):
		return b" ".join([int2bytes(self.start_time), int2bytes(self.stop_time)])

if __name__ == '__main__':
    import doctest
    doctest.testmod()
