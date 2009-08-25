from dionaea import connection
import struct
import logging
import os
import sys
import datetime

logger = logging.getLogger('http')
logger.setLevel(logging.DEBUG)


class httpd(connection):
	def __init__(self):
		logger.debug("http test")
		connection.__init__(self,'tcp')
		self.state = 'HEADER'

	def handle_established(self):
		self.processors()



	def handle_io_in(self, data):
		if self.state == 'HEADER':
			try:
				data = data.decode()
			except:
				return len(data)
			if data.find('\r\n\r\n'):
				head = data[:data.find('\r\n\r\n')]
				lines = head.split('\n')
#				for line in lines:
#					print("line :" + line)
				args = lines[0].split()
				if args[0] == 'GET':
					self.send_page(args[1])
				self.state = 'BODY'
				return len(data)
		elif self.state == 'BODY':
			print(data.decode())
			return len(data)
		return 0

	def send_page(self, page):
		body = b"""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\r
<html><head>\r
<title>Found</title>\r
</head><body>\r
<h1>Found</h1>\r
<p>The requested URL """ + page.encode() + b""" was found on this server!</p>\r
</body></html>
"""
		header = b"""HTTP/1.0 200 OK
Server: """ + sys.version.split('\n')[0].replace(' ','_').encode('UTF-8') + b"""\r
Date: """ + str(datetime.datetime.now()).encode('UTF-8') + b""" \r
Connection: close\r
Content-Type: text/html; charset=iso-8859-1\r
Content-Length: """ +str(len(body)).encode('UTF-8') + b"""\r
\r\n"""
		self.send(header)
		self.send(body)
		self.close()

	def handle_disconnect(self):
#		for s in self.bistream:
#			print('%s %s' % s)
		return False

#global h
#
#def start():
#	global h
#	h = httpd()
#	h.bind('::',9999)
#	h.listen(100)
#
#def stop():
#	global h
#	h.close()

