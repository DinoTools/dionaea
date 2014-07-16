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


from dionaea.core import connection, g_dionaea, incident, ihandler
import struct
import logging
import os
import sys
import datetime
import io
import cgi
import urllib.parse
import re
import tempfile

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
			self.headers[hset[0].lower()] = hset[1].strip()
		
	def print(self):
		logger.debug(self.type + b" " + self.path.encode('utf-8') + b" " + self.version)
		for i in self.headers:
			logger.debug(i + b":" + self.headers[i])


class httpd(connection):
	def __init__(self, proto='tcp'):
		logger.debug("http test")
		connection.__init__(self,proto)
		self.state = 'HEADER'
		self.rwchunksize = 64*1024
		self._out.speed.limit = 16*1024
		self.env = None
		self.boundary = None
		self.fp_tmp = None
		self.cur_length = 0
		max_request_size = 32768

		try:
			if 'max-request-size' in g_dionaea.config()['modules']['python']['http']:
				# try to convert value to int
				max_request_size = int(g_dionaea.config()['modules']['python']['http']['max-request-size'])
			else:
				logger.info("Value for 'max-request-size' not found, using default value.")
		except:
			logger.warning("Error while converting 'max-request-size' to an integer value. Using default value.")

		self.max_request_size = max_request_size * 1024

	def handle_origin(self, parent):
		self.root = parent.root
		self.rwchunksize = parent.rwchunksize

	def handle_established(self):
		self.timeouts.idle = 10
		self.processors()

	def chroot(self, path):
		self.root = path

	def handle_io_in(self, data):
		if self.state == 'HEADER':
			# End Of Head
			eoh = data.find(b'\r\n\r\n')
			# Start Of Content
			soc = eoh + 4

			if eoh == -1:
				eoh = data.find(b'\n\n')
				soc = eoh + 2
			if eoh == -1:
				return 0

			header = data[0:eoh]
			data = data[soc:]
			self.header = httpreq(header)
			self.header.print()
		
			if self.header.type == b'GET':
				self.handle_GET()
				return len(data)

			elif self.header.type == b'HEAD':
				self.handle_HEAD()
				return len(data)

			elif self.header.type == b'POST':
				if b'content-type' not in self.header.headers and b'content-type' not in self.header.headers:
					self.handle_POST()
					return len(data)

				try:
					# at least this information are needed for cgi.FieldStorage() to parse the content
					self.env = {
						'REQUEST_METHOD':'POST',
						'CONTENT_LENGTH': self.header.headers[b'content-length'].decode("utf-8"),
						'CONTENT_TYPE': self.header.headers[b'content-type'].decode("utf-8")
					}
				except:
					# ignore decode() errors
					self.handle_POST()
					return len(data)

				m = re.compile("multipart/form-data;\s*boundary=(?P<boundary>.*)", re.IGNORECASE).match(self.env['CONTENT_TYPE'])

				if not m:
					self.handle_POST()
					return len(data)


				self.state = 'POST'
				# More on boundaries see: http://www.apps.ietf.org/rfc/rfc2046.html#sec-5.1.1
				self.boundary = bytes("--" + m.group("boundary") + "--\r\n", 'utf-8')

				# dump post content to file
				self.fp_tmp = tempfile.NamedTemporaryFile(delete=False, prefix='http-', suffix=g_dionaea.config()['downloads']['tmp-suffix'], dir=g_dionaea.config()['downloads']['dir'])

				pos = data.find(self.boundary)
				# ending boundary not found
				if pos < 0:
					self.cur_length = soc
					return soc

				self.fp_tmp.write(data[:pos])
				self.handle_POST()
				return soc + pos

			elif self.header.type == b'OPTIONS':
				self.handle_OPTIONS()
				return len(data)

			# ToDo
			#elif self.header.type == b'PUT':
			#	self.handle_PUT()

			# method not found
			self.handle_unknown()
			return len(data)

		elif self.state == 'POST':
			pos = data.find(self.boundary)
			length = len(data)
			if pos < 0:
				# boundary not found
				l = length - len(self.boundary)
				if l < 0:
					l = 0
				self.cur_length = self.cur_length + l

				if self.cur_length > self.max_request_size:
					# Close connection if request is to large.
					# RFC2616: "The server MAY close the connection to prevent the client from continuing the request."
					# http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.4.14
					x = self.send_error(413)
					if x:
						self.copyfile(x)
					return length
				self.fp_tmp.write(data[:l])
				return l

			# boundary found
			self.fp_tmp.write(data[:pos+len(self.boundary)])
			self.handle_POST()
			return pos + len(self.boundary)

		elif self.state == 'PUT':
			print("putting to me")
		elif self.state == 'SENDFILE':
			print("sending file")
			return 0

		return len(data)


	def handle_GET(self):
		"""Handle the GET method. Send the header and the file."""
		x = self.send_head()
		if x :
			self.copyfile(x)

	def handle_HEAD(self):
		"""Handle the HEAD method. Send only the header but not the file."""
		x = self.send_head()
		if x :
			x.close()
			self.close()

	def handle_OPTIONS(self):
		"""
		Handle the OPTIONS method. Returns the HTTP methods that the server supports.
		"""
		self.send_response(200)
		self.send_header("Allow", "OPTIONS, GET, HEAD, POST")
		self.send_header("Content-Length", "0")
		self.send_header("Connection", "close")
		self.end_headers()
		self.close()

	def handle_POST(self):
		"""
		Handle the POST method. Send the head and the file. But ignore the POST params.
		Use the bistreams for a better analysis.
		"""
		if self.fp_tmp != None:
			self.fp_tmp.seek(0)
			form = cgi.FieldStorage(fp = self.fp_tmp, environ = self.env)
			for field_name in form.keys():
				# dump only files
				if form[field_name].filename == None:
					continue

				fp_post = form[field_name].file

				data = fp_post.read(4096)

				# don't handle empty files
				if len(data) == 0:
					continue

				fp_tmp = tempfile.NamedTemporaryFile(delete=False, prefix='http-', suffix=g_dionaea.config()['downloads']['tmp-suffix'], dir=g_dionaea.config()['downloads']['dir'])
				while data != b'':
					fp_tmp.write(data)
					data = fp_post.read(4096)

				icd = incident("dionaea.download.complete")
				icd.path = fp_tmp.name
				# We need the url for logging
				icd.url = ""
				fp_tmp.close()
				icd.report()
				os.unlink(fp_tmp.name)

			os.unlink(self.fp_tmp.name)

		x = self.send_head()
		if x :
			self.copyfile(x)

	def handle_PUT(self):
		pass

	def handle_unknown(self):
		x = self.send_error(501)
		if x:
			self.copyfile(x)

	def copyfile(self, f):
		self.file = f
		self.state = 'SENDFILE'
		self.handle_io_out()

	def send_head(self):
		rpath = os.path.normpath(self.header.path)
		fpath = os.path.join(self.root, rpath[1:])
		apath = os.path.abspath(fpath)
		aroot = os.path.abspath(self.root)
		logger.debug("root %s aroot %s rpath %s fpath %s apath %s" % (self.root, aroot, rpath, fpath, apath))
		if not apath.startswith(aroot):
			self.send_response(404, "File not found")
			self.end_headers()
			self.close()
		if os.path.exists(apath):
			if os.path.isdir(apath):
				if self.header.path.endswith('/'):
					testpath = os.path.join(apath, "index.html")
					if os.path.isfile(testpath):
						apath = testpath
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
				return self.send_error(404)
		else:
			return self.send_error(404)
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
		self.send_header("Connection", "close")
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

	def send_error(self, code, message = None):
		if message is None:
			if code in self.responses:
				message = self.responses[code][0]
			else:
				message = ''
		enc = sys.getfilesystemencoding()

		r = []
		r.append('<?xml version="1.0" encoding="%s"?>\n' % (enc))
		r.append('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"\n')
		r.append('         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n')
		r.append('<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">\n')
		r.append(' <head>\n')
		r.append('  <title>%d - %s</title>\n' % (code, message))
		r.append(' </head>\n')
		r.append(' <body>\n')
		r.append('  <h1>%d - %s</h1>\n' % (code, message))
		r.append(' </body>\n')
		r.append('</html>\n')

		encoded = ''.join(r).encode(enc)

		self.send_response(code, message)
		self.send_header("Content-type", "text/html; charset=%s" % enc)
		self.send_header("Content-Length", str(len(encoded)))
		self.send_header("Connection", "close")
		self.end_headers()

		f = io.BytesIO()
		f.write(encoded)
		f.seek(0)
		return f

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

