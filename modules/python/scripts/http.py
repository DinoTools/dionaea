#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter & Mark Schloesser
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


from dionaea.core import connection
import struct
import logging
import os
import sys
import datetime
import io
import cgi
import urllib.parse

logger = logging.getLogger('http')
logger.setLevel(logging.DEBUG)

class httpreq:
	def __init__(self, header):
		hlines = header.split(b'\n')
		req = hlines[0]
		reqparts = req.split(b" ")
		self.type = reqparts[0]
		self.path = urllib.parse.unquote(reqparts[1].decode('utf-8'))
		self.version = reqparts[2]
		r = self.version.find(b"\r")
		if r:
			self.version = self.version[:r]
		self.headers = {}
		for hline in hlines[1:]:
			if hline[len(hline)-1] == 13: # \r
				hline = hline[:len(hline)-1]
			hset = hline.split(b":", 1)
			self.headers[hset[0]] = hset[1]
		
	def print(self):
		print(self.type + b" " + self.path.encode('utf-8') + b" " + self.version)
		for i in self.headers:
			print(i + b":" + self.headers[i])


class httpd(connection):
	def __init__(self, proto='tcp'):
		logger.debug("http test")
		connection.__init__(self,proto)
		self.state = 'HEADER'
		self.rwchunksize = 64*1024
		self._out.speed.limit = 16*1024

	def handle_origin(self, parent):
		self.root = parent.root
		self.rwchunksize = parent.rwchunksize

	def handle_established(self):
#		self.processors()
		self.timeouts.idle = 10
#		pass

	def chroot(self, path):
		self.root = path

	def handle_io_in(self, data):
		print(data)
		if self.state == 'HEADER':
			eoh = data.find(b'\r\n\r\n')
			if eoh == -1:
				eoh = data.find(b'\n\n')
			if eoh == -1:
				return 0
			header = data[0:eoh]
			self.header = httpreq(header)
			self.header.print()
		
			if self.header.type == b'GET':
				self.handle_GET()
			elif self.header.type == b'HEAD':
				self.handle_GET()
			elif self.header.type == b'POST':
				self.handle_POST()
			elif self.header.type == b'PUT':
				self.handle_PUT()
		elif self.state == 'POST':
			print("posting to me")
		elif self.state == 'PUT':
			print("putting to me")
		elif self.state == 'SENDFILE':
			print("sending file")
			return 0

		return len(data)
		
	def handle_GET(self):
		x = self.send_head()
		if x :
			self.copyfile(x)

	def handle_HEAD(self):
		x = self.send_head()
		if x :
			x.close()

	def handle_POST(self):
		pass

	def handle_PUT(self):
		pass

	def copyfile(self, f):
		self.file = f
		self.state = 'SENDFILE'
		self.handle_io_out()

	def send_head(self):
		rpath = os.path.normpath(self.header.path)
		fpath = os.path.join(self.root, rpath[1:])
		apath = os.path.abspath(fpath)
		print("root %s rpath %s fpath %s apath %s" % (self.root, rpath, fpath, apath))
		if os.path.exists(apath):
			if os.path.isdir(apath):
				if not self.header.path.endswith('/'):
					self.send_response(301)
					self.send_header("Location", self.header.path + "/")
					self.send_header("Connection", "close")
					self.end_headers()
					self.close()
					return None
				return self.list_directory(apath)
			elif os.path.isfile(apath):
				f = io.open(apath, 'rb')
				self.send_response(200)
				self.send_header("Connection", "close")
				self.send_header("Content-Length", str(os.stat(apath).st_size))
				self.end_headers()
				return f
			else:
				self.send_response(404, "File not found")
				self.end_headers()
				self.close()
		else:
			self.send_response(404, "File not found")
			self.end_headers()
			self.close()
		return None

	def handle_io_out(self):
		logger.debug("handle_io_out")
		if self.state == 'SENDFILE':
			w = self.file.read(self.rwchunksize)
			if len(w) > 0:
				self.send(w)
			# send call call handle_io_out
			# to avoid double close warning we check state
			if len(w) < self.rwchunksize and self.state != None:
				self.state = None
				self.close()
				self.file.close()

	def list_directory(self, path):
		"""Helper to produce a directory listing (absent index.html).
		
		Return value is either a file object, or None (indicating an
		error).  In either case, the headers are sent, making the
		interface the same as for send_head().
		
		"""
		try:
			list = os.listdir(path)
			list.append("..")
		except os.error:
			self.send_error(404, "No permission to list directory")
			return None
		list.sort(key=lambda a: a.lower())
		r = []
		displaypath = cgi.escape(self.header.path)
		r.append('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
		r.append("<html>\n<title>Directory listing for %s</title>\n" % displaypath)
		r.append("<body>\n<h2>Directory listing for %s</h2>\n" % displaypath)
		r.append("<hr>\n<ul>\n")
		for name in list:
			fullname = os.path.join(path, name)
			displayname = linkname = name
			# Append / for directories or @ for symbolic links
			if os.path.isdir(fullname):
				displayname = name + "/"
				linkname = name + "/"
			if os.path.islink(fullname):
				displayname = name + "@"
				# Note: a link to a directory displays with @ and links with /
			r.append('<li><a href="%s">%s</a>\n' % (urllib.parse.quote(linkname), cgi.escape(displayname)))
			

		r.append("</ul>\n<hr>\n</body>\n</html>\n")
		enc = sys.getfilesystemencoding()
		encoded = ''.join(r).encode(enc)
		self.send_response(200)
		self.send_header("Content-type", "text/html; charset=%s" % enc)
		self.send_header("Content-Length", str(len(encoded)))
		self.end_headers()
		f = io.BytesIO()
		f.write(encoded)
		f.seek(0)
		return f

	def send_response(self, code, message=None):
		if message is None:
			if code in self.responses:
				message = self.responses[code][0]
			else:
				message = ''
		self.send("%s %d %s\r\n" % ("HTTP/1.0", code, message))

	def send_header(self, key, value):
		self.send("%s: %s\r\n" % (key, value))

	def end_headers(self):
		self.send("\r\n")

	def handle_disconnect(self):
		return False

	def handle_timeout_idle(self):
		return False

	responses = {
		100: ('Continue', 'Request received, please continue'),
		101: ('Switching Protocols',
			  'Switching to new protocol; obey Upgrade header'),

		200: ('OK', 'Request fulfilled, document follows'),
		201: ('Created', 'Document created, URL follows'),
		202: ('Accepted',
			  'Request accepted, processing continues off-line'),
		203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
		204: ('No Content', 'Request fulfilled, nothing follows'),
		205: ('Reset Content', 'Clear input form for further input.'),
		206: ('Partial Content', 'Partial content follows.'),

		300: ('Multiple Choices',
			  'Object has several resources -- see URI list'),
		301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
		302: ('Found', 'Object moved temporarily -- see URI list'),
		303: ('See Other', 'Object moved -- see Method and URL list'),
		304: ('Not Modified',
			  'Document has not changed since given time'),
		305: ('Use Proxy',
			  'You must use proxy specified in Location to access this '
			  'resource.'),
		307: ('Temporary Redirect',
			  'Object moved temporarily -- see URI list'),

		400: ('Bad Request',
			  'Bad request syntax or unsupported method'),
		401: ('Unauthorized',
			  'No permission -- see authorization schemes'),
		402: ('Payment Required',
			  'No payment -- see charging schemes'),
		403: ('Forbidden',
			  'Request forbidden -- authorization will not help'),
		404: ('Not Found', 'Nothing matches the given URI'),
		405: ('Method Not Allowed',
			  'Specified method is invalid for this server.'),
		406: ('Not Acceptable', 'URI not available in preferred format.'),
		407: ('Proxy Authentication Required', 'You must authenticate with '
			  'this proxy before proceeding.'),
		408: ('Request Timeout', 'Request timed out; try again later.'),
		409: ('Conflict', 'Request conflict.'),
		410: ('Gone',
			  'URI no longer exists and has been permanently removed.'),
		411: ('Length Required', 'Client must specify Content-Length.'),
		412: ('Precondition Failed', 'Precondition in headers is false.'),
		413: ('Request Entity Too Large', 'Entity is too large.'),
		414: ('Request-URI Too Long', 'URI is too long.'),
		415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
		416: ('Requested Range Not Satisfiable',
			  'Cannot satisfy request range.'),
		417: ('Expectation Failed',
			  'Expect condition could not be satisfied.'),

		500: ('Internal Server Error', 'Server got itself in trouble'),
		501: ('Not Implemented',
			  'Server does not support this operation'),
		502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
		503: ('Service Unavailable',
			  'The server cannot process the request due to a high load'),
		504: ('Gateway Timeout',
			  'The gateway server did not receive a timely response'),
		505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
		}

