from dionaea import connection, ihandler
from lxml import etree as etree
from xml.etree import ElementTree
from lxml.etree import XMLParser
from io import open
import base64
import hashlib
import re
import random
import mmap
import json

#from xml.sax import saxutils


def HH(some): return hashlib.md5(some).hexdigest()
def H(some): return hashlib.md5(some).digest()
def C(some): 
	print(some)
	return b':'.join(some)

__nsmap__ = {
	'jabber' : "jabber:client",
	'stream': 'http://etherx.jabber.org/streams',
	'sasl': 'urn:ietf:params:xml:ns:xmpp-sasl',
	'bind' : 'urn:ietf:params:xml:ns:xmpp-bind',
	'session': 'urn:ietf:params:xml:ns:xmpp-session',
	'iq': 'http://jabber.org/features/iq-register'}

class xmppparser:
	def __init__(self, client):
		self.client = client
		self.parser = XMLParser(target=self)
		self.__nsmap__ = __nsmap__

	def feed(self, data):
		self.parser.feed(data)
		try:
			self.parser.close()
		except Exception as e:
			print(e)

	def start(self, tag, attrib, nsmap):
		print("START current %s" % self.client.element)
		e = etree.Element(tag, attrib, self.__nsmap__)
		if self.client.xmlroot == None:
			self.client.xmlroot = e
		if self.client.element != None:
			self.client.element.append(e)
		self.client.element = e
		self.client.elements.append(e)

	def data(self, data):
		if self.client.element.text == None:
			self.client.element.text = data
		else:
			self.client.element.text += data

	def end(self, tag):
		print("END current %s" % self.client.element)
		self.client.elements.pop()
		self.client.element = self.client.elements[-1]

	def close(self):
		print("CLOSE current %s" % self.client.element)


class xmppclient(connection):
	def __init__(self, server='localhost', port=5222, username=None, password=None, resource=None, muc=None, channels=[]):
		connection.__init__(self, 'tls')
		self.server = username.split('@')[1]
		self.username = username.split('@')[0]
		self.password = password
		self.state = "connecting"
		self.__nsmap__ = __nsmap__
		self.parser = xmppparser(self)
		self.muc = muc
		self.xmlroot = None
		self.element = None
		self.elements = []
		self.connect(server,port)
		self.timeouts.reconnect = 10.0
		self.channels = channels
		self.resource = resource

	def reset_parser(self):
		self.parser = xmppparser(self)
		self.xmlroot = None
		self.element = None


	def handle_established(self):
		self.state = "connected"
		n = ElementTree.Element('stream:stream', attrib={
			'xmlns' : 'jabber:client',
			'xmlns:stream' :'http://etherx.jabber.org/streams',
			'xmlns:sasl' : 'http://www.iana.org/assignments/sasl-mechanisms',
			'xmlns:xml' : 'http://www.w3.org/XML/1998/namespace',
			'to' : self.server,
			'xml:lang' : 'en',
			'version' : '1.0'
			})
		d = """<?xml version="1.0"?>\r\n%s>""" % ElementTree.tostring(n)[:-3]
		print(d)
		self.send(d)

	def handle_io_in(self, data):
		print(data)
		data = data
		self.parser.feed(data)

#		for element in self.xmlroot:
#		print("ELEMENT %s" % (ElementTree.tostring(element), ))
		if self.xmlroot == None:
			print("ROOT IS EMPTY")
			return len(data)

		print("%s" % (etree.tostring(self.xmlroot, pretty_print=True).decode('ascii'), ))
		
		d = "NONE"
		print("STATE %s" % self.state)
		if self.state == "connected":
			mechs = self.xmlroot.xpath('/stream:stream/stream:features/sasl:mechanisms/sasl:mechanism', namespaces=self.__nsmap__)
			for auth in mechs:
				print("AUTH %s" % auth.text)
				if auth.text == "DIGEST-MD5":
					n = etree.Element('auth', attrib={
						'xmlns' :'urn:ietf:params:xml:ns:xmpp-sasl',
						'mechanism' : 'DIGEST-MD5'})
					d = etree.tostring(n) #.decode('ascii')
					self.state = "digest-md5"
					self.send(d)
				p = auth.getparent()
				p.remove(auth)
		elif self.state == "digest-md5":
			""" the digest auth code is copied from xmpppy and was ported to work with python3"""
			print("digest-md5")
			challenges = self.xmlroot.xpath('/stream:stream/sasl:challenge', namespaces=self.__nsmap__)
			for challenge in challenges:
				text = challenge.text

				cstring = base64.b64decode(text.encode('ascii'))
				print(cstring)
				chal = {}
				for pair in re.findall(b'(\w+\s*=\s*(?:(?:"[^"]+")|(?:[^,]+)))',cstring):
					key,value=[x.strip() for x in pair.decode('ascii').split('=', 1)]
					if value[:1]== '"' and value[-1:]== '"': value=value[1:-1]
					chal[key]=value
				print(chal)
				if 'qop' in chal and 'auth' in [x.strip() for x in chal['qop'].split(',')]:
					resp={}
#					resp['username']=self.username.encode('ascii')
					resp['username'] = self.username.encode('ascii')
					resp['realm']= self.server.encode('ascii')
					resp['nonce']=chal['nonce'].encode('ascii')
					cnonce=''
					for i in range(7):
						cnonce+=hex(int(random.random()*65536*4096))[2:]
					resp['cnonce']=cnonce.encode('ascii')
					resp['nc']=(b'00000001')
					resp['qop']='auth'.encode('ascii')
					resp['digest-uri']=b'xmpp/' + self.server.encode('ascii') # example.com'
					A1=C([H(C([resp['username'],resp['realm'],self.password.encode('ascii')])),resp['nonce'],resp['cnonce']])
					A2=C([b'AUTHENTICATE',resp['digest-uri']])
					response= HH(C([HH(A1).encode('ascii'),resp['nonce'],resp['nc'],resp['cnonce'],resp['qop'],HH(A2).encode('ascii')]))
					resp['response']=response
					resp['charset']='utf-8'
					sasl_data=''
					for key in ['charset','username','realm','nonce','nc','cnonce','digest-uri','response','qop']:
						if key in ['nc','qop','response','charset']:
							if isinstance(resp[key], bytes):
								sasl_data+="%s=%s,"%(key,resp[key].decode('ascii'))
							else:
								sasl_data+="%s=%s,"%(key,resp[key])
						else: 
							if isinstance(resp[key], bytes):
								sasl_data+='%s="%s",'%(key,resp[key].decode('ascii'))
							else:
								sasl_data+='%s="%s",'%(key,resp[key])
					sasl_data = sasl_data[:-1]
					n = etree.Element('response', attrib={
						'xmlns' :'urn:ietf:params:xml:ns:xmpp-sasl'})
					print(sasl_data)
					n.text = base64.b64encode(sasl_data.encode('ascii'))
					d = etree.tostring(n) #.decode('ascii')
					self.state = "digest-md5"
					self.send(d)
				elif 'rspauth' in chal:
					n = etree.Element('response', attrib={
						'xmlns' :'urn:ietf:params:xml:ns:xmpp-sasl'})
					d = etree.tostring(n)
					self.state = "sasl"
					self.send(d)


				p = challenge.getparent()
				p.remove(challenge)

		# rspauth is optional
		# http://www.ietf.org/rfc/rfc2831.txt
		if self.state == "sasl" or self.state == "digest-md5":
			sasl = self.xmlroot.xpath('/stream:stream/sasl:success', namespaces=self.__nsmap__)
			if len(sasl) == 1:
				self.xmlroot = None
				self.element = None
				self.elements = []
				self.parser = xmppparser(self)
				n = ElementTree.Element('stream:stream', attrib={
					'xmlns' : 'jabber:client',
					'xmlns:stream' :'http://etherx.jabber.org/streams',
					'xmlns:sasl' : 'http://www.iana.org/assignments/sasl-mechanisms',
					'xmlns:xml' : 'http://www.w3.org/XML/1998/namespace',
					'to' : self.server, #'example.com',
					'xml:lang' : 'en',
					'version' : '1.0'
					})
				d = """<?xml version="1.0"?>\r\n%s>""" % ElementTree.tostring(n)[:-3]
				print(d)
				self.send(d)
				self.state = "features"
			for s in sasl:
				p = s.getparent()
				p.remove(s)

		elif self.state == "features":
			features = self.xmlroot.xpath('/stream:stream/stream:features', namespaces=self.__nsmap__)
			for i in features:
				for j in i:
					print(j.tag)
					if j.tag == '{urn:ietf:params:xml:ns:xmpp-bind}bind':
						n = etree.Element('iq', attrib={
							'type' :  'set',
							'id' : 'bind_1'})
						b = etree.Element('bind', attrib={
							'xmlns' :'urn:ietf:params:xml:ns:xmpp-bind'})
						r = etree.Element('resource')
						r.text = self.resource
						b.append(r)
						n.append(b)
						d = etree.tostring(n)
						self.state = "bind"
						self.send(d)
		elif self.state == "bind":
			binds = self.xmlroot.xpath('/stream:stream/jabber:iq/bind:bind/bind:jid', namespaces=self.__nsmap__)
			for bind in binds:
				print(bind)
				n = etree.Element('iq', attrib={
					'type' :  'set',
					'id' : 'bind_1'})
				s = etree.Element('session', attrib = { 'xmlns' : "urn:ietf:params:xml:ns:xmpp-session" })
				n.append(s)
				d = etree.tostring(n)
				self.state = "session"
				self.send(d)
		elif self.state == "session":
			sessions = self.xmlroot.xpath('/stream:stream/jabber:iq/session:session', namespaces=self.__nsmap__)
			for session in sessions:
				print(session)
			for channel in self.channels:
				n = etree.Element('presence', attrib={
					'to' : "%s@%s/%s" % (channel, self.muc, self.username + '-' + self.resource) })
				p = etree.Element('x', attrib = { 'xmlns' : "http://jabber.org/protocol/muc" })
				d = etree.tostring(n)
				print("JOIN %s" % d)
				self.send(d)
			self.state = "online"

		if self.state == "online":
			for i in self.xmlroot:
				print("removing %s" % i)
				self.xmlroot.remove(i)

		print("DONE %s" % d)
		return len(data)


	def handle_disconnect(self):
		self.reset_parser()
		return True

	def handle_error(self, err):
		return True


class logxmpp(ihandler):
	def __init__(self, server, port, username, password, resource, muc, config):
		
		self.muc = muc
		self.config = config.copy()
		for e in self.config:
			self.config[e]['pcre'] = []
			for p in self.config[e]['events']:
#				p = p.replace('.','\\.') # workaround liblcfg bug
				print(p)
				self.config[e]['pcre'].append(re.compile(p))
		print(self.config)
		self.resource = resource
		self.username = username.split('@')[0]
		self.client = xmppclient(server=server, port=port, username=username, password=password, resource=resource, muc=muc, channels=list(self.config.keys()))
		ihandler.__init__(self, '*')

	def broadcast(self, i, n):
		for to in self.config:
			for r in self.config[to]['pcre']:
				if r.match(i.origin) is None:
					continue
				self.report(i, to, n)

	def broadcast_connection(self, i, t):
		for to in self.config:
			if 'anonymous' in self.config[to] and self.config[to]['anonymous'] == 'yes':
				anon = True
			else:
				anon = False
			for r in self.config[to]['pcre']:
				if r.match(i.origin) is None:
					continue
				self.report_connection(i, to, t, anon=anon)


	def report(self, i, to, xmlobj):
		if self.client is not None and self.client.state != 'online':
			return
		m = etree.Element('message', attrib={
			'type' : 'groupchat',
			'to' : '%s@%s'% (to, self.muc),
			'{http://www.w3.org/XML/1998/namespace}lang' : 'en'
			})
		b =  etree.Element('body')
		x = etree.Element('dionaea', attrib={
			'xmlns' : "http://dionaea.carnivore.it",
			'incident' : i.origin
			})
		x.append(xmlobj)
		# if you want readable dumps in your xmpp client
		# append as text instead of child
		# b.text = etree.tostring(x, pretty_print=True).decode('ascii')
		b.append(x)
		n = etree.Element('nick', attrib={
			'xmlns' : 'http://jabber.org/protocol/nick'})
		n.text = self.username + '-' + self.resource
		m.append(b)
		m.append(n)
		d = etree.tostring(m, pretty_print=True)
		self.client.send(d)
		print("XMPP-INCIDENT %s" % d)

	def report_connection(self, i, to, connection_type, anon=False):
		c = i.con
		print("HOSTS %s %s " % (c.remote.hostname, c.local.host) )

		local_host = c.local.host
		remote_host = c.remote.host
		remote_hostname = c.remote.hostname

		if anon == True:
			if c.remote.hostname == c.local.host:
				remote_host = remote_hostname = local_host = "127.0.0.1"
			else:
				local_host = "127.0.0.1"

		n = etree.Element('connection', attrib={
			'type' : connection_type, 
			'transport' : c.transport,
			'protocol' : c.protocol,
			'local_host' : local_host,
			'local_port' : str(c.local.port),
			'remote_host' : remote_host,
			'remote_hostname' : remote_hostname,
			'remote_port' : str(c.remote.port),
			'ref' : str(c.__hash__())})
		self.report(i, to, n)


	def handle_incident(self, i):
		pass

	def handle_incident_dionaea_connection_tcp_listen(self, i):
		self.broadcast_connection(i, 'listen')

	def handle_incident_dionaea_connection_tls_listen(self, i):
		self.broadcast_connection(i, 'listen')

	def handle_incident_dionaea_connection_tcp_connect(self, i):
		self.broadcast_connection(i, 'connect')

	def handle_incident_dionaea_connection_tls_connect(self, i):
		self.broadcast_connection(i, 'connect')

	def handle_incident_dionaea_connection_udp_connect(self, i):
		self.broadcast_connection(i, 'connect')

	def handle_incident_dionaea_connection_tcp_accept(self, i):
		self.broadcast_connection(i, 'accept')

	def handle_incident_dionaea_connection_tls_accept(self, i):
		self.broadcast_connection(i, 'accept')

	def handle_incident_dionaea_connection_tcp_reject(self, i):
		self.broadcast_connection(i, 'reject')

	def handle_incident_dionaea_connection_link(self, i):
		child = i.child
		parent = i.parent
		n = etree.Element('link', attrib={
			'child' : str(child.__hash__()),
			'parent' : str(parent.__hash__())
			})
		self.broadcast(i, n)


	def handle_incident_dionaea_connection_free(self, i):
		c = i.con
		n = etree.Element('connection', attrib={
			'ref' : str(c.__hash__())})
		self.broadcast(i, n)



	def handle_incident_dionaea_module_emu_profile(self, i):
		p = json.loads(i.profile)
		p = str(p)
		c = i.con
		n = etree.Element('profile', attrib={
			'ref' : str(c.__hash__())})
		n.text = p
		self.broadcast(i, n)

	def handle_incident_dionaea_download_offer(self, i):
		c = i.con
		url = i.url
		n = etree.Element('offer', attrib={
			'url' : url,
			'ref' : str(c.__hash__())})
		self.broadcast(i, n)


	def handle_incident_dionaea_download_complete_hash(self, i):
		if not hasattr(i, 'con'):
			return
		c = i.con
		url = i.url
		md5hash = i.md5hash
		n = etree.Element('download', attrib={
			'url' : url,
			'md5_hash' : md5hash,
			'ref' : str(c.__hash__())})
		self.broadcast(i, n)


	def handle_incident_dionaea_download_complete_unique(self, i):
		md5hash = i.md5hash
		n = etree.Element('file', attrib={
			'md5_hash' : md5hash
			})
		f = open(i.file, "rb")
		m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
		n.text = base64.b64encode(m.read(m.size()))
		m.close()
		f.close()
		self.broadcast(i, n)

	def handle_incident_dionaea_service_shell_listen(self, i):
		pass

	def handle_incident_dionaea_service_shell_connect(self, i):
		pass

	def handle_incident_dionaea_modules_python_p0f(self, i):
		pass

	def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, i):
		c = i.con
		uuid = i.uuid
		opnum = i.opnum
		n = etree.Element('dcerpcrequest', attrib={
			'uuid' : uuid,
			'opnum' : str(opnum),
			'ref' : str(c.__hash__())})
		self.broadcast(i, n)
		
	def handle_incident_dionaea_modules_python_smb_dcerpc_bind(self, i):
		c = i.con
		uuid = i.uuid
		transfersyntax = i.transfersyntax
		n = etree.Element('dcerpcbind', attrib={
			'uuid' : uuid,
			'transfersyntax' : transfersyntax,
			'ref' : str(c.__hash__())})
		self.broadcast(i, n)

