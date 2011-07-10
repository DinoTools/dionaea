import re

try:
	from dionaea.sip.extras import int2bytes
except:
	from extras import int2bytes

class Address(object):
	"""
	>>> a1 = Address(b"sip:john@example.org")
	>>> b1 = Address(b"<sip:john@example.org>")
	>>> c1 = Address(b'John Doe <sip:john@example.org>')
	>>> d1 = Address(b'"John Doe" <sip:john@example.org>')
	>>> print(a1.dumps() == b1.dumps() and c1.dumps() == d1.dumps())
	True
	"""
	_syntax = [
		re.compile(b'^(?P<name>[a-zA-Z0-9\-\.\_\+\~\ \t]*)<(?P<uri>[^>]+)>( *; *(?P<params>.*))?'),
		re.compile(b'^(?:"(?P<name>[a-zA-Z0-9\-\.\_\+\~\ \t]+)")[\ \t]*<(?P<uri>[^>]+)>( *; *(?P<params>.*))?'),
		re.compile(b'^[\ \t]*(?P<name>)(?P<uri>[^;]+)( *; *(?P<params>.*))?')
	]

	def __init__(self, value = None):
		self.display_name = None
		self.uri = None
		self.must_quote = False
		self.params = {}

		if type(value) == bytes or type(value) == str:
			self.loads(value)
		elif type(value) == URI:
			self.uri = value

	def __repr__(self):
		return repr(self.dumps())

	def loads(self, value):
		"""
		Parse an address

		:return: length used
		:rtype: Integer
		"""
		for regex in self._syntax:
			m = regex.match(value)
			if m:
				self.display_name = m.groups()[0].strip()
				self.uri = URI(m.groups()[1].strip())
				params = m.groupdict()["params"]
				if params == None:
					return m.end()

				for param in re.split(b" *; *", params):
					n,s,v = param.partition(b"=")
					self.params[n.strip()] = v.strip()

				return m.end()

		return 0

	def dumps(self):
		r = b""
		if self.display_name:
			r = b'"' + self.display_name + b'"'
			if self.uri:
				r = r + b" "

		if not self.uri:
			return r
	
		if self.must_quote:
			r = r + b"<" + self.uri.dumps() + b">"
		else:
			r = r + self.uri.dumps()

		if len(self.params) > 0:
			params = []
			for n,v in self.params.items():
				params.append(b"=".join([n,v]))

			r = r + b";" + b";".join(params)
		return r

class URI(object):
	"""
	>>> print(URI(b"sip:john@example.org"))
	sip:john@example.org
	>>> u = URI(b"sip:foo:bar@example.org:5060;transport=udp;novalue;param=pval?header=val&second=sec_val")
	>>> print(u.scheme, u.user, u.password, u.host, u.port, len(u.params), len(u.headers))
	b'sip foo bar example.org 5060 3 2'
	>>> d = u.dumps()
	>>> u = URI(d)
	>>> print(u.dumps() == d)
	True
	"""


	_syntax = re.compile(b"^(?P<scheme>[a-zA-Z][a-zA-Z0-9\+\-\.]*):"  # scheme
		+ b"(?:(?:(?P<user>[a-zA-Z0-9\-\_\.\!\~\*\'\(\)&=\+\$,;\?\/\%]+)" # user
		+ b"(?::(?P<password>[^:@;\?]+))?)@)?" # password
		+ b"(?:(?:(?P<host>[^;\?:]*)(?::(?P<port>[\d]+))?))"  # host, port
		+ b"(?:;(?P<params>[^\?]*))?" # parameters
		+ b"(?:\?(?P<headers>.*))?$" # headers
	)

	def __init__(self, value = None):
		self.scheme = None
		self.user = None
		self.password = None
		self.host = None
		self.port = None
		self.params = {}
		self.headers = []

		self.loads(value)

	def __repr__(self):
		return self.dumps()

	def dumps(self):
		r = self.scheme + b":"
		if self.user:
			r = r + self.user
			if self.password:
				r = r + b":" + self.password

			r = r + b"@"
		if self.host:
			r = r + self.host
			if self.port:
				r = r + b":" + int2bytes(self.port)

		if len(self.params) > 0:
			r = r + b";" + b"j".join([n + b"=" + v for n,v in self.params.items()])

		if len(self.headers) > 0:
			r = r + b"?" + b"&".join(self.headers)

		return r

	def loads(self, value):
		if value:
			m = self._syntax.match(value)
			if not m:
				print("value", value)
				# ToDo: error handling
				return
			self.scheme = m.group("scheme")
			self.user = m.group("user")
			self.password = m.group("password")
			self.host = m.group("host")
			self.port = m.group("port")
			params = m.group("params")
			headers = m.group("headers")

			# ToDo: error check
			try:
				self.port = int(self.port)
			except:
				pass

			if params:
				for param in params.split(b";"):
					t = param.partition(b"=")
					n = t[0].strip()
					v = t[2].strip()
					self.params[n] = v

			if headers:
				self.headers = headers.split(b"&")
