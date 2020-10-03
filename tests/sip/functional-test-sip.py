################################################################################
#
# Stand-alone VoIP honeypot client (preparation for Dionaea integration)
# Copyright (c) 2010 Tobias Wulff (twu200 at gmail)
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
################################################################################

import socket
import sys
import os
import hashlib
from time import sleep
from random import randint
from glob import glob
import logging

# Check python version
if sys.version_info[0] < 3:
	raise Exception("Use python3.x for functional test")

# Setup logger
logger = logging.getLogger('test')
logger.setLevel(logging.DEBUG)
logConsole = logging.StreamHandler()
logConsole.setLevel(logging.DEBUG)
logConsole.setFormatter(logging.Formatter(
	"[%(asctime)s] - %(levelname)s - %(message)s"))
logger.addHandler(logConsole)

# Delete all stream files (stream_DATETIME_ID_{IN,OUT}.rtpdump)
#for oldStreamFile in glob("stream_*_*_*.rtpdump"):
#	os.remove(oldStreamFile)

def getHeader(data, header):
	for line in data.split('\n'):
		lineParts = line.split(':')
		if lineParts[0] == header:
			return lineParts[1].strip(' \t')

	return ""

class VoipClient(object):
	def __init__(self):
		self.__s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.__s.bind(('', 0))
		self.__port = self.__s.getsockname()[1]
		self.__callId = randint(1000, 9999)
		self.__cseq = 1

	def send(self, msg):
		msg += "\n\n"
		self.__s.sendto(msg.encode('utf-8'), ('localhost', 5060))

	def recv(self):
		data, _ = self.__s.recvfrom(1024)
		data = data.decode('utf-8')
		return data

	def getCseq(self):
		self.__cseq += 1
		return self.__cseq - 1

	def invite(self, challengeResponse=None, nonce=None):
		sdpMsg = []
		sdpMsg.append("v=0")
		sdpMsg.append("o=socketHelper 5566 7788 IN IP4 127.0.0.1")
		sdpMsg.append("s=SDP Subject")
		sdpMsg.append("i=SDP information")
		sdpMsg.append("c=IN IP4 127.0.0.1")
		sdpMsg.append("t=0 0")
		sdpMsg.append("m=audio 30123 RTP/AVP 0")

		sipMsg = []
		sipMsg.append("INVITE sip:100@localhost SIP/2.0")
		sipMsg.append("Via: SIP/2.0/UDP 127.0.0.1")
		sipMsg.append("From: socketHelper")
		sipMsg.append("To: 100@localhost")
		sipMsg.append("Call-ID: {}".format(self.__callId))
		sipMsg.append("CSeq: {} INVITE".format(self.getCseq()))
		sipMsg.append("Contact: socketHelper")
		sipMsg.append("Accept: application/sdp")
		sipMsg.append("Content-Type: application/sdp")
		sipMsg.append("Content-Length: {}".format(
			len('\n'.join(sdpMsg))))

		if challengeResponse:
			sipMsg.append('Authorization: Digest username="100", ' + \
				'realm="100@localhost", uri="sip:100@localhost", ' + \
				'nonce="{}",'.format(nonce) + \
				'response="{}"'.format(challengeResponse))

		self.send('\n'.join(sipMsg) + "\n\n" + '\n'.join(sdpMsg))

	def options(self):
		msg = []
		msg.append("OPTIONS sip:100@localhost SIP/2.0")
		msg.append("Via: SIP/2.0/UDP 127.0.0.1")
		msg.append("From: socketHelper")
		msg.append("To: 100@localhost")
		msg.append("Call-ID: {}".format(self.__callId))
		msg.append("CSeq: {} OPTIONS".format(self.getCseq()))
		msg.append("Contact: socketHelper")
		self.send('\n'.join(msg))

	def ack(self, challengeResponse=None, nonce=None):
		msg = []
		msg.append("ACK sip:100@localhost SIP/2.0")
		msg.append("Via: SIP/2.0/UDP 127.0.0.1")
		msg.append("From: socketHelper")
		msg.append("To: 100@localhost")
		msg.append("Call-ID: {}".format(self.__callId))
		msg.append("CSeq: {} ACK".format(self.getCseq()))
		msg.append("Contact: socketHelper")

		if challengeResponse:
			msg.append('Authorization: Digest username="100", ' + \
				'realm="100@localhost", uri="sip:100@localhost", ' + \
				'nonce="{}",'.format(nonce) + \
				'response="{}"'.format(challengeResponse))

		self.send('\n'.join(msg))

	def bye(self, challengeResponse=None, nonce=None):
		msg = []
		msg.append("BYE sip:100@localhost SIP/2.0")
		msg.append("Via: SIP/2.0/UDP 127.0.0.1")
		msg.append("From: socketHelper")
		msg.append("To: 100@localhost")
		msg.append("Call-ID: {}".format(self.__callId))
		msg.append("CSeq: {} BYE".format(self.getCseq()))
		msg.append("Contact: socketHelper")

		if challengeResponse:
			msg.append('Authorization: Digest username="100", ' + \
				'realm="100@localhost", uri="sip:100@localhost", ' + \
				'nonce="{}",'.format(nonce) + \
				'response="{}"'.format(challengeResponse))

		self.send('\n'.join(msg))

	def getCallId(self): return self.__callId

def authenticate(data):
	# Get nonce from received data
	auth = getHeader(data, 'WWW-Authenticate').strip(' \n\r\t')
	assert auth.split(' ', 1)[0] == 'Digest'
	auth = auth.split(' ', 1)[1]
	authLineParts = [x.strip(' \t\r\n') for x in auth.split(',')]
	for x in authLineParts:
		k, v = x.split('=', 1)
		if k == "nonce":
			nonce = v.strip(' \n\r\t"\'')
	assert nonce
	logger.debug("Nonce received: {}".format(nonce))

	# Create challenge response
	# The calculation of the expected response is taken from
	# Sipvicious (c) Sandro Gaucci
	def hash(s):
		return hashlib.md5(s.encode('utf-8')).hexdigest()

	a1 = hash("100:100@localhost:F2DS13G5")
	a2 = hash("INVITE:sip:100@localhost")
	challengeResponse = hash("{}:{}:{}".format(a1, nonce, a2))

	logger.debug("a1: {}".format(a1))
	logger.debug("a2: {}".format(a2))
	logger.debug("response: {}".format(challengeResponse))

	return challengeResponse, nonce

def runFunctionalTest1():
	c = VoipClient()
	logger.info("VoIP test client created")

	logger.info("Sending OPTIONS")
	c.options()

	data = c.recv().split('\n')
	for d in data:
		d = d.split(':')
		if d[0] == "Allow":
			# Get individual arguments
			methods = [x.strip(' ') for x in d[1].split(',')]
			assert "INVITE" in methods
			assert "OPTIONS" in methods
			assert "ACK" in methods
			assert "CANCEL" in methods
			assert "BYE" in methods
			assert "REGISTER" not in methods

	logger.info("Sending INVITE")
	c.invite()

	# Expecting a 401 Unauthorized
	data = c.recv()
	assert data.split('\n')[0] == "SIP/2.0 401 Unauthorized"
	logger.warning("Received 401 Unauthorized")

	# Calculate authentication response
	challengeResponse, nonce = authenticate(data)

	# Send INVITE again with authentication
	logger.info("Sending INVITE with challenge response")
	c.invite(challengeResponse, nonce)

	# Expecting a 180 Ringing first
	data = c.recv()
	assert data.split('\n')[0] == "SIP/2.0 180 Ringing"
	logger.info("Received 180 Ringing")

	# Expecting a 200 OK with the server's SDP message
	data = c.recv().split('\n')
	assert data[0] == "SIP/2.0 200 OK"
	assert data[5] == "Call-ID: {}".format(c.getCallId())

	logger.info("Received 200 OK")

	# Get SDP port of server
	sdpMedia = None
	for d in data:
		if d[:2] == "m=":
			sdpMedia = d[2:]
			break
	assert sdpMedia
	assert sdpMedia.split(' ')[0] == "audio"
	rtpPort = int(sdpMedia.split(' ')[1])
	logger.debug("SDP port: {}".format(rtpPort))

	# Send unauthenticated ACK
	logger.info("Sending ACK")
	c.ack()

	# Expecting 401
	data = c.recv()
	assert data.split('\n')[0] == "SIP/2.0 401 Unauthorized"
	logger.warning("Received 401 Unauthorized")

	# Calculate authentication response
	challengeResponse, nonce = authenticate(data)
	logger.info("Sending ACK with challenge response")
	c.ack(challengeResponse, nonce)

	# Expecting 200 OK
	data = c.recv().split('\n')
	assert data[0] == "SIP/2.0 200 OK"
	logger.info("Received 200 OK")

	# Active session goes here ...
	sleep(2)

	sRtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sRtp.bind(('localhost', 30123))
	sRtp.connect(('localhost', rtpPort))
	logger.debug("Sending 'Hello World' to :{}".format(rtpPort))
	sRtp.sendto(b"Hello World", ('localhost', rtpPort))

	sleep(2)

	# Send unauthenticated BYE
	logger.info("Sending BYE")
	c.bye()

	# Expecting 401
	data = c.recv()
	assert data.split('\n')[0] == "SIP/2.0 401 Unauthorized"
	logger.warning("Received 401 Unauthorized")

	# Calculate authentication response
	challengeResponse, nonce = authenticate(data)

	# Active session ends
	logger.info("Sending BYE with challenge response")
	c.bye(challengeResponse, nonce)

	# Expecting a 200 OK
	data = c.recv().split('\n')
	assert data[0] == "SIP/2.0 200 OK"
	logger.info("Received 200 OK")

	# Check if stream dump file has been created
	#for channel in ["in", "out"]:
	if False:
		streamFile = glob("var/dionaea/stream_*_*_{}.rtpdump".format(channel))
		assert streamFile
		assert len(streamFile) > 0
		streamFile = streamFile[0]
		assert streamFile
		streamFile = open(streamFile, "r")
		streamData = streamFile.read()
		streamFile.close()
		assert streamData == "Hello World"

def runFunctionalTest2():
	c = VoipClient()
	logger.info("VoIP test client created")

	logger.info("Sending INVITE")
	c.invite()

	data = c.recv()
	assert data.split('\n', 1)[0] == "SIP/2.0 401 Unauthorized"
	logger.warn("Received 401 Unauthorized")

	r, n = authenticate(data)
	for i in range(2):
		logger.info("Sending INVITE with challenge response")
		c.invite(r, n)

def main():
	try:
		runFunctionalTest1()
		#runFunctionalTest2()
	except AssertionError as e:
		logger.critical("Functional test failed (assertion error)")
		logger.critical(e)
	except Exception as e:
		logger.critical("Functional test failed (unhandled error)")
		logger.critical(e)
	else:
		logger.info("Functional test finished successfully")

if __name__ == "__main__":
	main()
