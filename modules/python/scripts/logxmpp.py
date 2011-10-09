#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter
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

from dionaea.core import connection, ihandler, g_dionaea, incident
from xml.etree import ElementTree as etree
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
import copy

logger = logging.getLogger('logxmpp')
logger.setLevel(logging.INFO)


def HH(some): return hashlib.md5(some).hexdigest()
def H(some): return hashlib.md5(some).digest()
def C(some): 
	return b':'.join(some)

__nsmap__ = {
	'jabber' : "jabber:client",
	'stream': 'http://etherx.jabber.org/streams',
	'sasl': 'urn:ietf:params:xml:ns:xmpp-sasl',
	'bind' : 'urn:ietf:params:xml:ns:xmpp-bind',
	'session': 'urn:ietf:params:xml:ns:xmpp-session',
	'iq': 'http://jabber.org/features/iq-register',
	'mucuser': 'http://jabber.org/protocol/muc#user',
	'dionaea' : 'http://dionaea.carnivore.it',
	'xml' : 'http://www.w3.org/XML/1998/namespace'
}

for i in __nsmap__:
	etree._namespace_map[ __nsmap__[i]] = i

class xmppparser:
	"""this is a feed parser using lxml targets
	ref: http://codespeak.net/lxml/parsing.html#the-feed-parser-interface
	the parser accepts the first root element and adds elements to the root once these elements received their end tag"""

	def __init__(self, client):
		self.client = client
		self.parser = etree.XMLTreeBuilder(target=self) #XMLParser(target=self)
		self.parser.feed(b'')
		self.__nsmap__ = __nsmap__

	def feed(self, data):
		self.parser.feed(data)


	def start(self, tag, attrib):
		"""we got a starting tag"""
		if len(self.client.elements) > 0:
			logger.debug("START current %s" % self.client.elements[-1])
		else:
			logger.debug("START current %s" % None)
		e = etree.Element(tag, attrib)#, self.__nsmap__)
		if self.client.xmlroot == None:
			self.client.xmlroot = e
		else:
			if len(self.client.elements) > 0:
				self.client.elements[-1].append(e)
			self.client.elements.append(e)
		
	def data(self, data):
		if self.client.elements[-1].text == None:
			self.client.elements[-1].text = data
		else:
			self.client.elements[-1].text += data

	def end(self, tag):
		"""we got an end tag"""
		logger.debug("END current %s" % (self.client.elements[-1], ))
		e = self.client.elements.pop()
		if len(self.client.elements) == 0:
			self.client.xmlroot.append(e)

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
		self.timeouts.handshake = 10.0
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
		self.elements = []

	def sendxmlobj(self, xmlobj):
		self.send(etree.tostring(xmlobj))

	def handle_established(self):
		self.state = "connected"
		n = etree.Element('{http://etherx.jabber.org/streams}stream', attrib={
			'to' : self.server,
			'version' : '1.0',
			'{http://www.w3.org/XML/1998/namespace}lang' : 'en'
			}, nsmap = __nsmap__)
		d = """<?xml version="1.0"?>\r\n%s>""" % etree.tostring(n)[:-2].decode('utf-8')
		self.send(d)

	def handle_io_in(self, data):
		self.parser.feed(data)

		if self.xmlroot == None:
			logger.warn("ROOT IS EMPTY")
			return len(data)

#		print("%s" % (etree.tostring(self.xmlroot).decode('ascii'), ))
#		print("STATE %s" % self.state)
#		for element in self.xmlroot:
#			print("ELEMENT %s" % (etree.tostring(element), ))


		if self.state == "connected":
			mechs = self.xmlroot.findall('./stream:features/sasl:mechanisms/sasl:mechanism', namespaces=self.__nsmap__)
			for auth in mechs:
				logger.debug("AUTH %s" % auth.text)
				if auth.text == "DIGEST-MD5":
					n = etree.Element('auth', attrib={
						'xmlns' :'urn:ietf:params:xml:ns:xmpp-sasl',
						'mechanism' : 'DIGEST-MD5'})
					self.sendxmlobj(n)
					self.state = "digest-md5"
#				p = auth.getparent()
#				p.remove(auth)
		elif self.state == "digest-md5":
			""" the digest auth code is copied from xmpppy and was ported to work with python3"""
			logger.debug("digest-md5")
#			print(etree.tostring(self.xmlroot))
			challenges = self.xmlroot.findall('./sasl:challenge', namespaces=self.__nsmap__)
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
					n.text = base64.b64encode(sasl_data.encode('ascii')).decode('ascii')
					self.sendxmlobj(n)
					self.state = "digest-md5"
				elif 'rspauth' in chal:
					n = etree.Element('response', attrib={
						'xmlns' :'urn:ietf:params:xml:ns:xmpp-sasl'})
					self.sendxmlobj(n)
					self.state = "sasl"

				self.xmlroot.remove(challenge)

		# rspauth is optional
		# http://www.ietf.org/rfc/rfc2831.txt
		if self.state == "sasl" or self.state == "digest-md5":
			sasl = self.xmlroot.findall('./sasl:success', namespaces=self.__nsmap__)
			if len(sasl) == 1:
				self.xmlroot = None
				self.element = None
				self.elements = []
				self.parser = xmppparser(self)
				n = etree.Element('{http://etherx.jabber.org/streams}stream', attrib={
					'xmlns': 'jabber:client',
					'to' : self.server,
					'version' : '1.0',
					'{http://www.w3.org/XML/1998/namespace}lang' : 'en'
					}, nsmap = __nsmap__)
				d = """<?xml version="1.0"?>\r\n%s>""" % etree.tostring(n)[:-2].decode('utf-8')
				self.send(d)
				self.state = "features"

		elif self.state == "features":
			features = self.xmlroot.findall('./stream:features', namespaces=self.__nsmap__)
			for i in features:
				for j in i:
					logger.debug(j.tag)
					if j.tag == '{urn:ietf:params:xml:ns:xmpp-bind}bind':
						n = etree.Element('iq', attrib={
							'type' :  'set',
							'id' : 'bind_1'})
						b = etree.SubElement(n,'bind', attrib={
							'xmlns' :'urn:ietf:params:xml:ns:xmpp-bind'})
						r = etree.SubElement(b,'resource')
						r.text = self.resource
						self.sendxmlobj(n)
						self.state = "bind"
				self.xmlroot.remove(i)

		elif self.state == "bind":
			binds = self.xmlroot.findall('./jabber:iq/bind:bind/bind:jid', namespaces=self.__nsmap__)
			for bind in binds:
				n = etree.Element('iq', attrib={
					'type' :  'set',
					'id' : 'bind_1'})
				s = etree.SubElement(n, 'session', attrib = { 'xmlns' : "urn:ietf:params:xml:ns:xmpp-session" })
				self.sendxmlobj(n)
				self.state = "session"
				# cleanup './jabber:iq/bind:bind/bind:jid' below via ./jabber:iq

		elif self.state == "session":
			# cleanup './jabber:iq/session:session'
			# cleanup './jabber:iq/bind:bind'

			iqs = self.xmlroot.findall('./jabber:iq', namespaces=self.__nsmap__)
			for iq in iqs:
				self.xmlroot.remove(iq)

			for channel in self.channels:
				to = "%s@%s/%s" % (channel, self.muc, self.username + '-' + self.resource)
				n = etree.Element('presence', attrib={
					'to' : to })
				p = etree.Element('x', attrib = { 'xmlns' : "http://jabber.org/protocol/muc" })
				self.sendxmlobj(n)
				logger.info("trying to join %s" % to)
			self.state = "join"
		elif self.state == "join":
			presences = self.xmlroot.findall('./jabber:presence', namespaces=self.__nsmap__)
			for presence in presences:
				channel = presence.attrib['from'].split('@')[0]
				to = presence.attrib['to']
				me = '%s@%s/%s' % (self.username, self.server, self.resource)
				if to == me and channel in self.channels:
					muis = presence.findall('./mucuser:x/mucuser:item[@jid="%s"]' % to, namespaces=self.__nsmap__)
					self.joined = self.joined + len(muis)
					errors = presence.iterfind('./error', namespaces=self.__nsmap__)
					for error in errors:
						logger.warn("could not join %s\n%s" % (to, etree.tostring(error).decode('ascii')))

				self.xmlroot.remove(presence)

			if self.joined == len(self.channels):
				self.state = "online"
				logger.info("logxmpp is online!")
			

		if self.state == "online":
			# we received a file via xmpp
			files = self.xmlroot.findall('./jabber:message/jabber:body/dionaea:dionaea/dionaea:file', namespaces=self.__nsmap__)
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

			messages = self.xmlroot.findall('./jabber:message', namespaces=self.__nsmap__)
			for message in messages:
				self.xmlroot.remove(message)
			
			presences = self.xmlroot.findall('./jabber:presence', namespaces=self.__nsmap__)
			for presence in presences:
				self.xmlroot.remove(presence)

			iqs = self.xmlroot.findall('./jabber:iq', namespaces=self.__nsmap__)
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
				logger.debug("unknown/unhandled xml element: removing %s\n%s\n" % (i, etree.tostring(i).decode('ascii')) )
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
		etree.SubElement(n, 'ping', attrib={
			'xmlns' : 'urn:xmpp:ping'
			})
		self.sendxmlobj(n)
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
				self.config[e]['pcre'].append(re.compile(p))
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

	def report(self, i, to, xmlobj):
		if self.client is not None and self.client.state != 'online':
			return
		msg = etree.Element('message', attrib={
			'type' : 'groupchat',
			'to' : '%s@%s'% (to, self.muc),
			'{http://www.w3.org/XML/1998/namespace}lang' : 'en'
			})
		body =  etree.SubElement(msg,'body')
		dio = etree.SubElement(body,'dionaea', attrib={
			'xmlns' : "http://dionaea.carnivore.it",
			'incident' : i.origin
			})
		dio.append(xmlobj)
#		dio.text = etree.tostring(xmlobj).decode('ascii')

		nick = etree.SubElement(msg, 'nick', attrib={
			'xmlns' : 'http://jabber.org/protocol/nick'})
		nick.text = self.username + '-' + self.resource
		self.client.sendxmlobj(msg)

	def handle_incident(self, i):
		for to in self.config:
			if 'anonymous' in self.config[to] and self.config[to]['anonymous'] == 'yes':
				anonymous = True
			else:
				anonymous = False
			for r in self.config[to]['pcre']:
				if r.match(i.origin) is None:
					continue
				try:
					handler_name = i.origin
					handler_name = handler_name.replace('.','_')
					func = getattr(self, "serialize_incident_" + handler_name, None)
				except:
					func = None

				if func is not None and callable(func) == True:
					msg = func(i, anonymous=anonymous)
					if msg is None:
						continue
					self.report(i, to, msg)
#				else:
#					logger.warning("%s has no function" % handler_name)


	def _serialize_connection(self, i, connection_type, anonymous):
		c = i.con
		local_host = c.local.host
		remote_host = c.remote.host
		remote_hostname = c.remote.hostname

		if anonymous == True:
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
		return n

	def serialize_incident_dionaea_connection_tcp_listen(self, i, anonymous):
		return self._serialize_connection(i, 'listen', anonymous)

	def serialize_incident_dionaea_connection_tls_listen(self, i, anonymous):
		return self._serialize_connection(i, 'listen', anonymous)

	def serialize_incident_dionaea_connection_tcp_connect(self, i, anonymous):
		return self._serialize_connection(i, 'connect', anonymous)

	def serialize_incident_dionaea_connection_tls_connect(self, i, anonymous):
		return self._serialize_connection(i, 'connect', anonymous)

	def serialize_incident_dionaea_connection_udp_connect(self, i, anonymous):
		return self._serialize_connection(i, 'connect', anonymous)

	def serialize_incident_dionaea_connection_tcp_accept(self, i, anonymous):
		return self._serialize_connection(i, 'accept', anonymous)

	def serialize_incident_dionaea_connection_tls_accept(self, i, anonymous):
		return self._serialize_connection(i, 'accept', anonymous)

	def serialize_incident_dionaea_connection_tcp_reject(self, i, anonymous):
		return self._serialize_connection(i, 'reject', anonymous)

	def serialize_incident_dionaea_connection_link(self, i, anonymous):
		return etree.Element('link', attrib={
			'child' : str(i.child.__hash__()),
			'parent' : str(i.parent.__hash__())
			})

	def serialize_incident_dionaea_connection_free(self, i, anonymous):
		return etree.Element('connection', attrib={
			'ref' : str(i.con.__hash__())})

	def serialize_incident_dionaea_module_emu_profile(self, i, anonymous):
		n = etree.Element('profile', attrib={
			'ref' : str(i.con.__hash__())})
		n.text = str(json.loads(i.profile))
		return n

	def serialize_incident_dionaea_download_offer(self, i, anonymous):
		return etree.Element('offer', attrib={
			'url' : i.url,
			'ref' : str(i.con.__hash__())})

	def serialize_incident_dionaea_download_complete_hash(self, i, anonymous):
		if not hasattr(i, 'con'):
			return

		# do not announce files gatherd via xmpp
		if i.con == self.client:
			return
		return etree.Element('download', attrib={
			'url' : i.url,
			'md5_hash' : i.md5hash,
			'ref' : str(i.con.__hash__())})


	def serialize_incident_dionaea_download_complete_unique(self, i, anonymous):
		# do not broadcast files gatherd via xmpp
		if hasattr(i, 'con') and i.con == self.client:
			return

		n = etree.Element('file', attrib={
			'md5_hash' : i.md5hash
			})
		f = open(i.file, "rb")
		m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
		n.text = base64.b64encode(m.read(m.size())).decode('utf-8')
		m.close()
		f.close()
		return n

	def serialize_incident_dionaea_service_shell_listen(self, i, anonymous):
		pass

	def serialize_incident_dionaea_service_shell_connect(self, i, anonymous):
		pass

	def serialize_incident_dionaea_modules_python_p0f(self, i, anonymous):
		pass

	def serialize_incident_dionaea_modules_python_smb_dcerpc_request(self, i, anonymous):
		return etree.Element('dcerpcrequest', attrib={
			'uuid' : i.uuid,
			'opnum' : str(i.opnum),
			'ref' : str(i.con.__hash__())})
		
	def serialize_incident_dionaea_modules_python_smb_dcerpc_bind(self, i, anonymous):
		return etree.Element('dcerpcbind', attrib={
			'uuid' : i.uuid,
			'transfersyntax' : i.transfersyntax,
			'ref' : str(i.con.__hash__())})

	def serialize_incident_dionaea_modules_python_mysql_login(self, i, anonymous):
		return etree.Element('mysqllogin', attrib={
			'username' : i.username,
			'password' : i.password,
			'ref' : str(i.con.__hash__())})

	def serialize_incident_dionaea_modules_python_mysql_command(self, i, anonymous):
		n = etree.Element('mysqlcommand', attrib={
			'cmd' : str(i.command),
			'ref' : str(i.con.__hash__())})
		if hasattr(i,'args'):
			args = etree.SubElement(n,'args')
			for j in range(len(i.args)):
				arg = etree.SubElement(args, 'arg', attrib={
					'index' : str(j)})
				arg.text = i.args[j]
		return n

	def serialize_incident_dionaea_modules_python_sip_command(self, icd, anonymous):
		def mk_uri(uri):
			r = etree.Element('uri')
			for u in ['scheme','user','password','port','host']:
				if u not in uri or uri[u] is None:
					continue
				r.set(u, uri[u])
			return r

		def mk_addr(_type, addrs):
			r = etree.Element(_type)
			for addr in addrs:
				a = etree.SubElement(r,'addr')
				if addr['display_name'] is not None:
					a.set('display_name',addr['display_name'])
				a.append(mk_uri(addr['uri']))
			return r

		def mk_via(vias):
			r = etree.Element('vias')
			for via in vias:
				s = etree.SubElement(r,'via')
				for u in ['address','port','protocol','port','host']:
					if u not in via or via[u] is None:
						continue
					s.set(u, via[u])
			return r

		def mk_allow(allows):
			r = etree.Element('allowlist')
			for a in allows:
				e = etree.SubElement(r,'allow')
				e.text = a
			return r

		def mk_sdp(sdp):
			s=etree.Element('sdp')
			if 'o' in sdp:
				o = etree.SubElement(s, 'origin')
				for u in ['username','unicast_address','nettype','addrtype','sess_id','sess_version']:
					if u in sdp['o']:
						o.set(u, sdp['o'][u])
			if 'c' in sdp:
				c = etree.SubElement(s, 'connectiondata')
				for u in ['connection_address','number_of_addresses','addrtype','nettype','ttl']:
					if u in sdp['c']:
						c.set(u, sdp['c'][u])
			if 'm' in sdp:
				m = etree.SubElement(s, 'medialist')
				for media in sdp['m']:
					x = etree.SubElement(m,'media')
					for u in ['proto','port','media','number_of_ports']:
						if u not in media or media[u] is None:
							continue
						x.set(u, media[u])
			return s

		def mk_str(d,_replace):
			def mk_value(v,_replace):
				if isinstance(v,dict) or isinstance(v,list):
					return mk_str(v, _replace=_replace)
				elif isinstance(v,bytes):
					s = v.decode('ascii')
				elif isinstance(v, int):
					s = str(v)
				else:
					s = v
				if _replace is not None:
					s = _replace(s)
				return s

			if isinstance(d,dict):
				b={}
				for k,v in d.items():
					if v is not None:
						b[k] = mk_value(v, _replace)
				return b
			elif isinstance(d,list):
				return [mk_value(v, _replace) for v in filter(lambda x:x is not None,d)]
			else:
				return mk_value(d, _replace)


		n = etree.Element('sipcommand', attrib={
			'method' : str(icd.method),
			'ref' : str(icd.con.__hash__())})

		if anonymous:
			_replace = lambda x: x.replace(icd.con.local.host,'127.0.0.1')
		else:
			_replace = None
		
		if hasattr(icd,'user_agent') and icd.user_agent is not None:
			n.set('user_agent', mk_str(icd.user_agent,_replace))
		n.set('call_id',mk_str(icd.call_id,_replace))
		n.append(mk_addr('address',[mk_str(icd.get('addr'), _replace)]))
		n.append(mk_addr('to',[mk_str(icd.get('to'), _replace)]))
		n.append(mk_addr('contact',[mk_str(icd.get('contact'), _replace)]))
		n.append(mk_addr('from',mk_str(icd.get('from'), _replace)))
		n.append(mk_via(mk_str(icd.get('via'), _replace)))
		n.append(mk_allow(mk_str(icd.get('allow'),_replace)))
		if hasattr(icd,'sdp') and icd.sdp is not None:
			n.append(mk_sdp(mk_str(icd.sdp,_replace)))

		return n

