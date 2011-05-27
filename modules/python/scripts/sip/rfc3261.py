import re
import logging

try:
	from dionaea.sip import rfc2396, rfc4566
	from dionaea.sip.extras import int2bytes
except:
	import rfc2396, rfc4566
	from extras import int2bytes

logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)

# For more information see RFC3261 Section: 21 Response Codes
# http://tools.ietf.org/html/rfc3261#section-21
status_messages = {
	# Provisional 1xx
	100: b"Trying",
	180: b"Ringing",
	181: b"Call Is Being Forwarded",
	182: b"Queued",
	183: b"Session Progress",

	# Successful 2xx
	200: b"OK",

	# Redirection 3xx
	300: b"Multiple Choices",
	301: b"Moved Permanently",
	302: b"Moved Temporarily",
	305: b"Use Proxy",
	380: b"Alternative Service",

	# Request Failure 4xx
	400: b"Bad Request",
	401: b"Unauthorized",
	402: b"Payment Required",
	403: b"Forbidden",
	404: b"Not Found",
	405: b"Method Not Allowed",
	406: b"Not Acceptable",
	407: b"Proxy Authentication Required",
	408: b"Request Timeout",
	410: b"Gone",
	413: b"Request Entity Too Large",
	414: b"Request-URI Too Large",
	415: b"Unsupported Media Type",
	416: b"Unsupported URI Scheme",
	420: b"Bad Extension",
	421: b"Extension Required",
	423: b"Interval Too Brief",
	480: b"Temporarily Unavailable",
	481: b"Call/Transaction Does Not Exist",
	482: b"Loop Detected",
	483: b"Too Many Hops",
	484: b"Address Incomplete",
	485: b"Ambiguous",
	486: b"Busy Here",
	487: b"Request Terminated",
	488: b"Not Acceptable Here",
	491: b"Request Pending",
	493: b"Undecipherable",

	# Server Failure 5xx
	500: b"Internal Server Error",
	501: b"Not Implemented",
	502: b"Bad Gateway",
	503: b"Service Unavailable",
	504: b"Server Time-out",
	505: b"Version Not Supported",
	513: b"Message Too Large",

	# Global Failures 6xx
	600: b"Busy Everywhere",
	603: b"Decline",
	604: b"Does Not Exist Anywhere",
	606: b"Not Acceptable",
}


class Header(object):
	"""
	>>> print(Header('"John Doe" <sip:john@example.org>', 'to').dumps())
	b'To: "John Doe" <sip:john@example.org>'
	>>> print(Header(b'"John Doe" <sip:john@example.org>', b'to').dumps())
	b'To: "John Doe" <sip:john@example.org>'
	"""

	_address = [
		b"contact",
		b"from",
		b"record-route",
		b"refer-to",
		b"referred-by",
		b"route",
		b"to"
	]
	_exception = {
		b"call-id": b"Call-ID",
		b"cseq": b"CSeq",
		b"www-authenticate": b"WWW-Authenticate"
	}

	def __init__(self, value, name = None):
		self.loads(value, name)

	def loads(self, value, name):
		if type(value) == str:
			value = bytes(value, "utf-8")
		if type(name) == str:
			name = bytes(name, "utf-8")

		# Get name
		if name != None:
			name = name.lower()
			self.name = name
			self._value = value
			return 0

		value = value.strip()
		v = value.split(b":", 1)
		name = v[0].lower()
		value = v[1].strip()
		self.name = name
		# parse value
		if name in self._address:
			addr = rfc2396.Address()
			addr.must_quote = True
			l = addr.loads(value)
			# ToDo: use l to parse the rest
			self._value = addr
			return l

		self._value = value
		return len(value)


	def dumps(self):
		"""
		Dump the value with header name.
		"""
		return self.format_name(self.name) + b": "  + self.get_value()

	def format_name(self, name):
		name = name.lower()
		if name in self._exception:
			return self._exception[name]
		
		names = name.split(b"-")
		names = [n.capitalize() for n in names]
		
		return b"-".join(names)

	def get_value(self):
		"""
		Prepare the value and return it as bytes.
		"""
		if type(self._value) == bytes:
			return self._value
		if type(self._value) == int:
			return int2bytes(self._value)

		return self._value.dumps()

	value = property(get_value)



class Headers(object):

	_single = [
		b"call-id",
		b"content-disposition",
		b"content-length",
		b"content-type",
		b"cseq",
		b"date",
		b"expires",
		b"event",
		b"max-forwards",
		b"organization",
		b"refer-to",
		b"referred-by",
		b"server",
		b"session-expires",
		b"subject",
		b"timestamp",
		b"to",
		b"user-agent"
	]

	def __init__(self):
		self._headers = {}

	def __getattr__(self, name):
		return self.get(name)

	def __iter__(self):
		return iter(self._headers)

	def append(self, headers, copy = False, name_new = None):
		if headers == None:
			return

		if type(headers) != list:
			headers = [headers]
		for header in headers:
			print(header)
			if copy == True:
				header = Header(header.dumps())
			if name_new != None:
				header.name = name_new

			if header.name in self._single:
				self._headers[header.name] = header
			elif header.name in self._headers:
				self._headers[header.name].append(header)
			else:
				self._headers[header.name] = [header]

	def dump_list(self):
		ret = []
		for name, header in self._headers.items():
			if not type(header) == list:
				header = [header]
			for h in header:
				ret.append(h.dumps())

		return ret


	def get(self, name, default = None):
		if type(name) == str:
			name = bytes(name, "utf-8")

		name = name.lower()
		if not name in self._headers:
			return default

		return self._headers[name]

	def items(self):
		return self._headers.items()

class Message(object):
	"""
	>>> s = b'ACK sip:alice@example.org SIP/2.0\\r\\n'
	>>> s = s + b'CSeq: 1 ACK\\r\\n'
	>>> s = s + b'Via: SIP/2.0/UDP example.org:5060;branch=foo-bar;rport\\r\\n'
	>>> s = s + b'From: "Bob" <sip:bob@example.org>;tag=123\\r\\n'
	>>> s = s + b'Call-ID: cWhfKU3v\\r\\n'
	>>> s = s + b'To: "Alice" <sip:alice@example.org>\\r\\n'
	>>> s = s + b'Content-Length: 0\\r\\n'
	>>> s = s + b'Max-Forwards: 70\\r\\n'
	>>> s = s + b'\\r\\n'
	>>> m = Message(s)
	>>> print(m.method)
	b'ACK'
	>>> print(m.protocol)
	b'SIP/2.0'
	>>> m.uri
	b'sip:alice@example.org'
	>>> print(m.headers.get(b"to").dumps())
	b'To: "Alice" <sip:alice@example.org>'
	>>> print(m.headers.get(b"call-id").dumps())
	b'Call-ID: cWhfKU3v'
	>>> s = m.dumps()
	>>> # parse the generated message again
	>>> m = Message(s)
	>>> s2 = m.dumps()
	>>> # check if the content is the same
	>>> t1 = s.split(b"\\r\\n")
	>>> t2 = s2.split(b"\\r\\n")
	>>> t1.sort()
	>>> t2.sort()
	>>> print(b"\\r\\n".join(t1) == b"\\r\\n".join(t2))
	True
	>>> s1 = b"INVITE sip:alice@example.org SIP/2.0\\r\\n"
	>>> s1 = s1 + b"Via: SIP/2.0/UDP example.org;branch=foo-bar\\r\\n"
	>>> s1 = s1 + b"To: Alice <sip:alice@home.com>\\r\\n"
	>>> s1 = s1 + b"From: Bob <sip:bob@example.net>;tag=123\\r\\n"
	>>> s1 = s1 + b"Call-ID: cWhfKU3v\\r\\n"
	>>> s1 = s1 + b"CSeq: 123 INVITE\\r\\n"
	>>> s1 = s1 + b"Max-Forwards: 70\\r\\n"
	>>> s1 = s1 + b"Contact: <sip:bob@example.org>\\r\\n"
	>>> s1 = s1 + b"Content-Type: application/sdp\\r\\n"
	>>> s1 = s1 + b"Content-Length: 155\\r\\n\\r\\n"
	>>> s2 = b"v=0\\r\\n"
	>>> s2 = s2 + b"o=bob 12345 23456 IN IP4 192.168.1.1\\r\\n"
	>>> s2 = s2 + b"s=A dionaea test\\r\\n"
	>>> s2 = s2 + b"c=IN IP4 192.168.1.2\\r\\n"
	>>> s2 = s2 + b"t=0 0\\r\\n"
	>>> s2 = s2 + b"m=audio 8080 RTP/AVP 0 8\\r\\n"
	>>> s2 = s2 + b"m=video 8081 RTP/AVP 31\\r\\n"
	>>> s = s1 + s2
	>>> m = Message(s)
	>>> m.sdp[b"v"]
	0
	>>> m.sdp[b"o"].dumps()
	b'bob 12345 23456 IN IP4 192.168.1.1'
	>>> m.sdp[b"s"]
	b'A dionaea test'
	>>> m.sdp[b"c"].dumps()
	b'IN IP4 192.168.1.2'
	"""

	def __init__(self, data = None):
		self.method = None
		self.uri = None
		self.response_code = None
		self.status_message = None
		self.protocol = None
		self._body = None

		self.headers = Headers()
		self.sdp = None

		if data != None:
			self.loads(data)

	def create_response(self, code, message = None):
		res = Message()

		res.protocol = b"SIP/2.0"
		res.response_code = code
		if message == None:
			if code in status_messages:
				res.status_message = status_messages[code]
			else:
				res.status_message = b""
		print("----create response")
		for name in [b"cseq", b"call-id", b"via"]:
			res.headers.append(self.headers.get(name, None), True)

		res.headers.append(self.headers.get(b"from", None), True, b"to")
		res.headers.append(self.headers.get(b"to", None), True, b"from")
		res.headers.append(self.headers.get(b"to", None), True, b"contact")

		res.headers.append(Header(0, b"Content-Length"))

		return res

	def headers_exist(self, headers, overwrite = False):
		if overwrite == False:
			headers = headers + [b"to", b"from", b"call-id", b"cseq", b"contact"]

		for header in headers:
			if self.headers.get(header) == None:
				logger.warn("Header missing: {}".format(repr(header)))
				return False

		return True


	def loads(self, data):
		"""
		Parse a SIP-Message and return the used bytes

		:return: bytes used
		"""
		# End Of Head
		if type(data) == bytes:
			eoh = data.find(b"\r\n\r\n")
		else:
			eoh = data.find("\r\n\r\n")
			

		if eoh == -1:
			return 0

		header = data[:eoh]

		headers = header.split(b"\r\n")

		self._body = data[eoh+4:]

		# remove first line and parse it
		h1, h2, h3 = headers[0].split(b" ", 2)
		del headers[0]

		try:
			self.response, self.protocol, self.responsetext = int(h2), h1, h3
		except:
			# ToDo: parse h2 as uri
			self.method, self.uri, self.protocol = h1, rfc2396.Address(h2), h3
		
		# ToDo: check protocol

		for h in headers:
			header = Header(h)
			self.headers.append(header)

		content_length = self.headers.get(b"content-length", None)
		if content_length == None:
			return

		content = self._body[:int(content_length.value)]

		content_type = self.headers.get(b"content-type", None)
		if content_type != None and content_type.value.lower().strip() == b"application/sdp":
			self.sdp = rfc4566.SDP(content)


	def dumps(self):
		# h = Header
		h = []
		if self.method != None:
			h.append(self.method + b" " + self.uri.dumps() + b" " + self.protocol)
		elif self.response_code != None:
			h.append(self.protocol + b" " + int2bytes(self.response_code) + b" " + self.status_message)
		else:
			return None

		sdp = b""
		if self.sdp != None:
			sdp = self.sdp.dumps()
			self.headers.append(Header(b"application/sdp", b"content-type"))
			self.headers.append(Header(len(sdp), b"content-length"))

		h = h + self.headers.dump_list()

		return b"\r\n".join(h) + b"\r\n\r\n" + sdp


if __name__ == '__main__':
    import doctest
    doctest.testmod()

