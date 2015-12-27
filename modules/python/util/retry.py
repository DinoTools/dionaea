#!/opt/dionaea/bin/python3.2

from optparse import OptionParser
import socket
import os
import shutil
import sys
import time

parser = OptionParser()
parser.add_option(
    "-f", "--file", action="store", type="string", dest="filename")
parser.add_option("-H", "--host", action="store", type="string", dest="host")
parser.add_option("-p", "--port", action="store", type="int", dest="port")
parser.add_option(
    "-s", "--send", action="store_true", dest="send", default=False)
parser.add_option(
    "-r", "--recv", action="store_true", dest="recv", default=False)
parser.add_option("-t", "--tempfile", action="store",
                  type="string", dest="tempfile", default="retrystream")
parser.add_option(
    "-u", "--udp", action="store_true", dest="udp", default=False)
parser.add_option(
    "-v", "--verbose", action="store_true", dest="verbose", default=False)
(options, args) = parser.parse_args()

if os.path.exists(options.tempfile):
    os.unlink(options.tempfile)
shutil.copy (options.filename, options.tempfile + ".py")

sys.path.append(".")
import_string = "from " + options.tempfile + " import stream"
exec(import_string)

print("doing " + options.filename)
if options.send:
    if options.udp == False:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.connect((options.host, options.port))

for i in stream:
    if i[0] == 'in':
        r = 0
        if options.send == True:
            r = s.send(i[1])
        if options.verbose:
            print('send %i of %i bytes' % (r, len(i[1])))
    if i[0] == 'out':
        x = ""
        if options.recv == True:
            x = s.recv(len(i[1]))
        if options.verbose:
            print('recv %i of %i bytes' % ( len(x), len(i[1])) )
        time.sleep(1)

time.sleep(1)
