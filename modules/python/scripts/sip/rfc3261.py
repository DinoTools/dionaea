import re

if __name__ == '__main__':
	from rfc2396 import *
else:
	from dionaea.sip.rfc2396 import *

# For more information see RFC3261 Section: 21 Response Codes
# http://tools.ietf.org/html/rfc3261#section-21
status_messages = {
	# Provisional 1xx
	100: "Trying",
	180: "Ringing",
	181: "Call Is Being Forwarded",
	182: "Queued",
	183: "Session Progress",

	# Successful 2xx
	200: "OK",

	# Redirection 3xx
	300: "Multiple Choices",
	301: "Moved Permanently",
	302: "Moved Temporarily",
	305: "Use Proxy",
	380: "Alternative Service",

	# Request Failure 4xx
	400: "Bad Request",
	401: "Unauthorized",
	402: "Payment Required",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	406: "Not Acceptable",
	407: "Proxy Authentication Required",
	408: "Request Timeout",
	410: "Gone",
	413: "Request Entity Too Large",
	414: "Request-URI Too Large",
	415: "Unsupported Media Type",
	416: "Unsupported URI Scheme",
	420: "Bad Extension",
	421: "Extension Required",
	423: "Interval Too Brief",
	480: "Temporarily Unavailable",
	481: "Call/Transaction Does Not Exist",
	482: "Loop Detected",
	483: "Too Many Hops",
	484: "Address Incomplete",
	485: "Ambiguous",
	486: "Busy Here",
	487: "Request Terminated",
	488: "Not Acceptable Here",
	491: "Request Pending",
	493: "Undecipherable",

	# Server Failure 5xx
	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Server Time-out",
	505: "Version Not Supported",
	513: "Message Too Large",

	# Global Failures 6xx
	600: "Busy Everywhere",
	603: "Decline",
	604: "Does Not Exist Anywhere",
	606: "Not Acceptable",
}


class Header(object):
	"""
	>>> print(Header('"John Doe" <sip:john@example.org>', 'to').dumps())
	To: "John Doe" <sip:john@example.org>
	"""

	_address = ['contact', 'from', 'record-route', 'refer-to', 'referred-by', 'route', 'to']
	_exception    = {'call-id':'Call-ID','cseq':'CSeq','www-authenticate':'WWW-Authenticate'}

	def __init__(self, value, name = None):
		self.loads(value, name)

	def loads(self, value, name):
		# Get name
		if name != None:
			name = name.lower()
			self.name = name
			self.value = value
			return 0

		value = value.strip()
		v = value.split(":", 1)
		name = v[0].lower()
		value = v[1].strip()
		self.name = name
		# parse value
		if name in self._address:
			addr = Address()
			addr.must_quote = True
			l = addr.loads(value)
			# ToDo: use l to parse the rest
			self.value = addr
			return l

		self.value = value
		return len(value)

	def dumps(self):
		r = self.format_name(self.name) + ": "
		if type(self.value) == str:
			return r + self.value
		if type(self.value) == int:
			return r + str(self.value)

		return r + self.value.dumps()

	def format_name(self, name):
		name = name.lower()
		if name in self._exception:
			return self._exception[name]
		
		names = name.split("-")
		names = [n.capitalize() for n in names]
		
		return '-'.join(names)

class Headers(object):

	_single = ['call-id', 'content-disposition', 'content-length', 'content-type', 'cseq', 'date', 'expires', 'event', 'max-forwards', 'organization', 'refer-to', 'referred-by', 'server', 'session-expires', 'subject', 'timestamp', 'to', 'user-agent']

	def __init__(self):
		self._headers = {}

	def __getattr__(self, name):
		return self.get(name)

	def __iter__(self):
		return iter(self._headers)

	def append(self, headers, copy = False):
		if headers == None:
			return

		if type(headers) != list:
			headers = [headers]
		for header in headers:
			if copy == True:
				header = Header(header.dumps())

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
	ACK
	>>> print(m.protocol)
	SIP/2.0
	>>> print(m.uri)
	sip:alice@example.org
	>>> print(m.headers.get('to').dumps())
	To: "Alice" <sip:alice@example.org>
	>>> print(m.headers.get('call-id').dumps())
	Call-ID: cWhfKU3v
	>>> s = m.dumps()
	>>> # parse the generated message again
	>>> m = Message(s)
	>>> s2 = m.dumps()
	>>> # check if the content is the same
	>>> t1 = s.split("\\r\\n")
	>>> t2 = s2.split("\\r\\n")
	>>> t1.sort()
	>>> t2.sort()
	>>> print("\\r\\n".join(t1) == "\\r\\n".join(t2))
	True
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

		res.protocol = "SIP/2.0"
		res.response_code = code
		if message == None:
			if code in status_messages:
				res.status_message = status_messages[code]
			else:
				res.status_message = ""

		for name in ["cseq", "from", "to", "call-id"]:
			res.headers.append(self.headers.get(name, None))

		res.headers.append(Header(0, "Content-Length"))

		return res

	def headers_exist(self, headers, overwrite = False):
		if overwrite == False:
			headers = headers + ["to", "from", "call-id", "cseq", "contact"]

		for header in headers:
			if not header in self._headers:
				logger.warn("Header missing: {}".format(header))
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
		if type(header) == bytes:
			header = header.decode("utf-8")
		
		headers = header.split("\r\n")

		self._body = data[eoh+4:]

		# remove first line and parse it
		h1, h2, h3 = headers[0].split(" ", 2)
		del headers[0]

		try:
			self.response, self.protocol, self.responsetext = int(h2), h1, h3
		except:
			# ToDo: parse h2 as uri
			self.method, self.uri, self.protocol = h1, h2, h3
		
		# ToDo: check protocol

		for h in headers:
			header = Header(h)
			self.headers.append(header)


	def dumps(self):
		# h = Header
		h = []
		if self.method != None:
			h.append(self.method + " " + str(self.uri) + " " + self.protocol)
		elif self.response_code != None:
			h.append(self.protocol + " " + str(self.response_code) + " " + self.status_message)
		else:
			return None

		h = h + self.headers.dump_list()

		return "\r\n".join(h) + "\r\n\r\n"


if __name__ == '__main__':
    import doctest
    doctest.testmod()

