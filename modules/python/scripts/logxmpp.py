from dionaea.core import connection, ihandler, g_dionaea, incident
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
import hashlib
import tempfile
import logging
from random import choice
import string

logger = logging.getLogger('logxmpp')
logger.setLevel(logging.DEBUG)


#from xml.sax import saxutils


def HH(some): return hashlib.md5(some).hexdigest()
def H(some): return hashlib.md5(some).digest()
def C(some): 
#	logger.debug(some)
	return b':'.join(some)

__nsmap__ = {
	'jabber' : "jabber:client",
	'stream': 'http://etherx.jabber.org/streams',
	'sasl': 'urn:ietf:params:xml:ns:xmpp-sasl',
	'bind' : 'urn:ietf:params:xml:ns:xmpp-bind',
	'session': 'urn:ietf:params:xml:ns:xmpp-session',
	'iq': 'http://jabber.org/features/iq-register',
	'mucuser': 'http://jabber.org/protocol/muc#user',
	'dionaea' : 'http://dionaea.carnivore.it'
}

class xmppparser:
	"""this is a feed parser using lxml targets
	ref: http://codespeak.net/lxml/parsing.html#the-feed-parser-interface
	the parser accepts the first root element and adds elements to the root once these elements received their end tag"""

	def __init__(self, client):
		self.client = client
		self.parser = XMLParser(target=self)
		# libxml2 <= 2.7.6 is buggy
		# this may be related to
		# https://bugs.launchpad.net/lxml/+bug/569957
		# to avoid having to install libxml2 from source
		# prime the xml tree with ... nothing and it works
		self.parser.feed(b'')
		self.__nsmap__ = __nsmap__

	def feed(self, data):
		self.parser.feed(data)


	def start(self, tag, attrib, nsmap):
		"""we got a starting tag"""
		logger.debug("START current %s" % self.client.element)
		e = etree.Element(tag, attrib, self.__nsmap__)
		if self.client.xmlroot == None:
			# if there is no root element yet, this is our new root element
			self.client.xmlroot = e
		else:
			# else we add this element to the list of pending elements
			# this lists head is always the current element
			self.client.elements.append(e)
			if self.client.element != None:
				# if we have an active element, the new element is a child element
				self.client.element.append(e)

		# the new element is our current element
		self.client.element = e
		

	def data(self, data):
		if self.client.element.text == None:
			self.client.element.text = data
		else:
			self.client.element.text += data

	def end(self, tag):
		"""we got an end tag"""
		logger.debug("END current %s" % (self.client.element, ))
		self.client.elements.pop()
		# remove the element from the list of elements
		if len(self.client.elements) == 0:
			# if the list of elements is 0, we finished a whole subtree
			logger.debug("APPENDING to root")
			self.client.xmlroot.append(self.client.element)
			# assign this new subtree to the root element
			self.client.element = None
			# set the current element None, so we can start over
		else:
			# there are still elements waiting to be finished in the list
			# the new element to finish is the last element in the list
			self.client.element = self.client.elements[-1]

	def close(self):
#		logger.debug("CLOSE current %s" % self.client.element)
		pass


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
		self.joined = 0
		self.me = '%s@%s/%s' % (self.username, self.server, self.resource)
		self.timeouts.idle = 10 * 60 # default to 10 minutes idle timeout
		self.ids = {}
		logger.info("I am %s" % username + '/' + resource)

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
#		logger.debug(d)
		self.send(d)

	def handle_io_in(self, data):
#		print(data)
#		data = data
		self.parser.feed(data)

#		for element in self.xmlroot:
#		print("ELEMENT %s" % (ElementTree.tostring(element), ))
		if self.xmlroot == None:
			logger.warn("ROOT IS EMPTY")
			return len(data)

#		print("%s" % (etree.tostring(self.xmlroot, pretty_print=True).decode('ascii'), ))
		
		d = "NONE"
#		print("STATE %s" % self.state)
		if self.state == "connected":
			mechs = self.xmlroot.xpath('/stream:stream/stream:features/sasl:mechanisms/sasl:mechanism', namespaces=self.__nsmap__)
			for auth in mechs:
				logger.debug("AUTH %s" % auth.text)
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
#			logger.debug("digest-md5")
			challenges = self.xmlroot.xpath('/stream:stream/sasl:challenge', namespaces=self.__nsmap__)
			for challenge in challenges:
				text = challenge.text

				cstring = base64.b64decode(text.encode('ascii'))
#				logger.debug(cstring)
				chal = {}
				for pair in re.findall(b'(\w+\s*=\s*(?:(?:"[^"]+")|(?:[^,]+)))',cstring):
					key,value=[x.strip() for x in pair.decode('ascii').split('=', 1)]
					if value[:1]== '"' and value[-1:]== '"': value=value[1:-1]
					chal[key]=value
#				logger.debug(chal)
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
#					logger.debug(sasl_data)
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


				challenge.getparent().remove(challenge)

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
#				logger.debug(d)
				self.send(d)
				self.state = "features"
				sasl[0].getparent().remove(sasl[0])

		elif self.state == "features":
			features = self.xmlroot.xpath('/stream:stream/stream:features', namespaces=self.__nsmap__)
			for i in features:
				for j in i:
#					logger.debug(j.tag)
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
				i.getparent().remove(i)

		elif self.state == "bind":
			binds = self.xmlroot.xpath('/stream:stream/jabber:iq/bind:bind/bind:jid', namespaces=self.__nsmap__)
			for bind in binds:
				n = etree.Element('iq', attrib={
					'type' :  'set',
					'id' : 'bind_1'})
				s = etree.Element('session', attrib = { 'xmlns' : "urn:ietf:params:xml:ns:xmpp-session" })
				n.append(s)
				d = etree.tostring(n)
				self.state = "session"
				self.send(d)
				self.xmlroot.remove(bind.getparent().getparent())

		elif self.state == "session":
			sessions = self.xmlroot.xpath('/stream:stream/jabber:iq/session:session', namespaces=self.__nsmap__)
			for session in sessions:
				self.xmlroot.remove(session.getparent())

			binds = self.xmlroot.xpath('/stream:stream/jabber:iq/bind:bind', namespaces=self.__nsmap__)
			for bind in binds:
				self.xmlroot.remove(bind.getparent())

			iqs = self.xmlroot.xpath('/stream:stream/jabber:iq', namespaces=self.__nsmap__)
			for iq in iqs:
				self.xmlroot.remove(iq)

			for channel in self.channels:
				to = "%s@%s/%s" % (channel, self.muc, self.username + '-' + self.resource)
				n = etree.Element('presence', attrib={
					'to' : to })
				p = etree.Element('x', attrib = { 'xmlns' : "http://jabber.org/protocol/muc" })
				d = etree.tostring(n)
				logger.info("trying to join %s" % to)
				self.send(d)
			self.state = "join"
		elif self.state == "join":
			presences = self.xmlroot.xpath('/stream:stream/jabber:presence', namespaces=self.__nsmap__)
			for presence in presences:
#				logger.warn("%s" % etree.tostring(presence, pretty_print=True).decode('ascii'))
				channel = presence.attrib['from'].split('@')[0]
				to = presence.attrib['to']
				me = '%s@%s/%s' % (self.username, self.server, self.resource)
#				logger.warn("%s %s -> %s" % (me, to, channel) )
				if to == me and channel in self.channels:
					muis = presence.xpath('count(./mucuser:x/mucuser:item[@jid="%s"])' % to, namespaces=self.__nsmap__)
					self.joined = self.joined + int(muis)
#					for mui in muis:
#						if mui.attrib['jid'] == me:
#							logger.info("%s joined %s" % (to, presence.attrib['from']) )
#							self.joined = self.joined + 1
					errors = presence.xpath('./error', namespaces=self.__nsmap__)
					for error in errors:
						logger.warn("could not join %s\n%s" % (to, etree.tostring(error, pretty_print=True).decode('ascii')))

				self.xmlroot.remove(presence)

			if self.joined == len(self.channels):
				self.state = "online"
				logger.info("logxmpp is online!")
			

		if self.state == "online":
			# we received a file via xmpp
			files = self.xmlroot.xpath('/stream:stream/jabber:message/jabber:body/dionaea:dionaea/dionaea:file', namespaces=self.__nsmap__)
			for i in files:
				xmlobj = i
				md5_hash = xmlobj.attrib['md5_hash']
				f = base64.b64decode(xmlobj.text.encode('ascii'))
				my_hash = hashlib.md5(f).hexdigest()
				logger.debug("file %s <-> %s" % (md5_hash, my_hash))
				if md5_hash == my_hash:
					fileobj = tempfile.NamedTemporaryFile(delete=False, prefix='xmpp-', suffix=g_dionaea.config()['downloads']['tmp-suffix'], dir=g_dionaea.config()['downloads']['dir'])
					fileobj.write(f)
					fileobj.close()
					icd = incident("dionaea.download.complete")
					icd.path = fileobj.name
					icd.con = self
					icd.url = "logxmpp://" + md5_hash
					icd.report()
					fileobj.unlink(fileobj.name)
				self.xmlroot.remove(i.getparent().getparent().getparent())

			messages = self.xmlroot.xpath('/stream:stream/jabber:message/jabber:body', namespaces=self.__nsmap__)
			for message in messages:
#				logger.debug("proper del %s" % message)
				self.xmlroot.remove(message.getparent())

			subjects = self.xmlroot.xpath('/stream:stream/jabber:message/jabber:subject', namespaces=self.__nsmap__)
			for subject in subjects:
#				logger.debug("proper del %s" % subject)
				self.xmlroot.remove(subject.getparent())
			
			presences = self.xmlroot.xpath('/stream:stream/jabber:presence', namespaces=self.__nsmap__)
			for presence in presences:
#				logger.debug("proper del %s" % presence)
				self.xmlroot.remove(presence)

			iqs = self.xmlroot.xpath('/stream:stream/jabber:iq', namespaces=self.__nsmap__)
			for iq in iqs:
				if 'id' in iq.attrib:
					id = iq.attrib['id']
					if id in self.ids:
						if self.ids[id] == 'ping':
							logger.info("ping-pong keepalive")
						# remove iqs which are replies to our requests, like ping
						del self.ids[id]
						self.xmlroot.remove(iq)

		if self.xmlroot is not None:
			for i in self.xmlroot:
				logger.debug("unknown/unhandled xml element: removing %s\n%s\n" % (i, etree.tostring(i, pretty_print=True).decode('ascii')) )
				self.xmlroot.remove(i)
	
		return len(data)
	
	def handle_timeout_idle(self):
		# XEP-0199: XMPP Ping
		# 4.2 Client-To-Server Pings
		# http://xmpp.org/extensions/xep-0199.html#c2s
		xid = ''.join([choice(string.ascii_letters) for i in range(4)])
		n = etree.Element('iq', attrib={
			'from' :self.me,
			'to' : self.server,
			'type': 'get',
			'id' : xid})
		ping = etree.Element('ping', attrib={
			'xmlns' : 'urn:xmpp:ping'
			})
		n.append(ping)
		d = etree.tostring(n)
		self.send(d)
		self.ids[xid] = 'ping'
		return True

	def handle_disconnect(self):
		if self.state != 'quit':
			self.reset_parser()
			self.joined = 0
			return True
		return False

	def handle_error(self, err):
		if self.state != 'quit':
			return True
		return False

	def quit(self):
		self.state = 'quit'
		self.close()


class logxmpp(ihandler):
	def __init__(self, server, port, username, password, resource, muc, config):
		
		self.muc = muc
		self.config = config.copy()
		for e in self.config:
			self.config[e]['pcre'] = []
			for p in self.config[e]['events']:
#				p = p.replace('.','\\.') # workaround liblcfg bug
				logger.debug(p)
				self.config[e]['pcre'].append(re.compile(p))
#		logger.debug(self.config)
		self.resource = resource
		self.username = username.split('@')[0]
		self.client = xmppclient(server=server, port=port, username=username, password=password, resource=resource, muc=muc, channels=list(self.config.keys()))
		ihandler.__init__(self, '*')

	def __del__(self):
		self.muc = None
		self.config = None
		self.resource = None
		self.username = None
		self.client.quit()
		self.client = None

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
#		logger.debug("XMPP-INCIDENT %s" % d)

	def report_connection(self, i, to, connection_type, anon=False):
		c = i.con
#		logger.debug("HOSTS %s %s " % (c.remote.hostname, c.local.host) )

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

		# do not announce files gatherd via xmpp
		if i.con == self.client:
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
		# do not broadcast files gatherd via xmpp
		if hasattr(i, 'con') and i.con == self.client:
			return

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

