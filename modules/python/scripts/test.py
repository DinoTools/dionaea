from dionaea import ihandler, incident
from dionaea import connection
import logging
import json
global p

logger = logging.getLogger('test')
logger.setLevel(logging.DEBUG)






def start():
	global a
	logger.warn("test?")
	a = profiler()

def stop():
	global a
	del a


# ftp://ftp.kernel.org/pub/linux/kernel/v2.6/linux-2.6.29.6.tar.gz


from tftp import TftpClient


class ftpdownloader(ihandler):
	def __init__(self):
		ihandler.__init__(self, 'dionaea.download.offer')
	def handle(self, icd):
		logger.warn("do download")
		url = icd.get("url")
		p = urllib.parse.urlsplit(url)
		print(p)
		con = icd.get('con')
		if p.scheme == 'ftp':
			f = ftp()
			f.download(con.local.host, p.username, p.password, p.hostname, p.port, p.path, 'binary')
		if p.scheme == 'tftp':
			t = TftpClient()
			t.bind(con.local.host, 0)
			t.download('192.168.53.21', 69, 'zero')

x = ftpdownloader()
