#!/opt/dionaea/bin/python3.1

from optparse import OptionParser
import socket
import os
import shutil
import time

parser = OptionParser()
parser.add_option("-f", "--file", action="store", type="string", dest="filename")
parser.add_option("-H", "--host", action="store", type="string", dest="host")
parser.add_option("-p", "--port", action="store", type="int", dest="port")
parser.add_option("-s", "--send", action="store_true", dest="send", default=False)
parser.add_option("-r", "--recv", action="store_true", dest="recv", default=False)
parser.add_option("-t", "--tempfile", action="store", type="string", dest="tempfile", default="retrystream")
(options, args) = parser.parse_args()

if os.path.exists(options.tempfile):
	os.unlink(options.tempfile)
shutil.copy (options.filename, options.tempfile + ".py")

import_string = "from " + options.tempfile + " import stream"
exec(import_string)

print("doing " + options.filename)
if options.send:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((options.host, options.port))

for i in stream:
	if i[0] == 'in':
		r = 0
		if options.send == True:
			r = s.send(i[1])
#		print('send %i of %i bytes' % (r, len(i[1])))
	if i[0] == 'out':
		x = ""
		if options.recv == True:
			x = s.recv(len(i[1]))
		print('recv %i of %i bytes' % ( len(x), len(i[1])) )
		time.sleep(1)

time.sleep(1)
