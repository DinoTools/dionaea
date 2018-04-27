from dionaea.core import ihandler, incident, g_dionaea
from dionaea.util import md5file, sha512file
from dionaea import IHandlerLoader

import pyev
import logging
import uuid
import struct
import socket
from urllib.parse import urlparse

try:
    import magic
except:
    def filetype(fpath):
        return ''
else:
    def filetype(fpath):
        try:
            mc = magic.Magic()
            ftype = mc.from_file(fpath)
        except:
            ftype = ''
        return ftype

logger = logging.getLogger('submit_http')
logger.setLevel(logging.DEBUG)


class SubmitHTTPHandlerLoader(IHandlerLoader):
    name = "submit_http"

    @classmethod
    def start(cls, config=None):
        return handler("*", config=config)


class submithttp_report:
    def __init__(self, sha512h, md5, filepath):
        self.sha512h, self.md5h, self.filepath = sha512h, md5, filepath
        self.saddr, self.sport, self.daddr, self.dport = ('', )*4
        self.download_url = ''
        self.filetype = ''
        self.filename = ''


class handler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)

        self.backendurl = config.get("url")
        self.email = config.get("email")
        self.user = config.get("user", "")
        self.passwd = config.get("pass", "")
        self.cookies = {}

        # heartbeats
        #dinfo = g_dionaea.version()
        #self.software = 'dionaea {0} {1}/{2} - {3} {4}'.format(
        #    dinfo['dionaea']['version'],
        #    dinfo['compiler']['os'],
        #    dinfo['compiler']['arch'],
        #    dinfo['compiler']['date'],
        #    dinfo['compiler']['time'],
        #)
        self.loop = pyev.default_loop()

    def handle_incident(self, icd):
        pass

    def handle_incident_dionaea_download_complete_unique(self, icd):
        cookie = str(uuid.uuid4())

        i = incident("dionaea.upload.request")
        i._url = self.backendurl

        i.sha512 = sha512file(icd.file)
        i.md5 = md5file(icd.file)
        i.email = self.email
        i.user = self.user
        i.set('pass', self.passwd)

        mr = submithttp_report(i.sha512, i.md5, icd.file)

        if hasattr(icd, 'con'):
            i.source_host = str(
                struct.unpack('!I', socket.inet_aton(icd.con.remote.host))[0]
            )
            i.source_port = str(icd.con.remote.port)
            i.target_host = str(
                struct.unpack('!I', socket.inet_aton(icd.con.local.host))[0]
            )
            i.target_port = str(icd.con.local.port)
            mr.saddr, mr.sport, mr.daddr, mr.dport = i.source_host, i.source_port, i.target_host, i.target_port
        if hasattr(icd, 'url'):
            i.url = icd.url
            i.trigger = icd.url
            try:
                i.filename = urlparse(icd.url).path.split('/')[-1]
                mr.filename = i.filename
            except:
                pass
            mr.download_url = icd.url

        i.filetype = filetype(icd.file)
        mr.filetype = i.filetype

        i._callback = "dionaea.modules.python.submithttp.result"
        i._userdata = cookie

        self.cookies[cookie] = mr
        i.report()

    # handle agains in the same way
    handle_incident_dionaea_download_complete_again = handle_incident_dionaea_download_complete_unique

    def handle_incident_dionaea_modules_python_submithttp_result(self, icd):
        fh = open(icd.path, mode="rb")
        c = fh.read()
        logger.info("submithttp result: {0}".format(c))

        cookie = icd._userdata
        mr = self.cookies[cookie]

        # does backend want us to upload?
        if b'UNKNOWN' in c or b'S_FILEREQUEST' in c:
            i = incident("dionaea.upload.request")
            i._url = self.backendurl

            i.sha512 = mr.sha512h
            i.md5 = mr.md5h
            i.email = self.email
            i.user = self.user
            i.set('pass', self.passwd)

            i.set('file://data', mr.filepath)

            i.source_host = mr.saddr
            i.source_port = mr.sport
            i.target_host = mr.daddr
            i.target_port = mr.dport
            i.url = mr.download_url
            i.trigger = mr.download_url

            i.filetype = mr.filetype
            i.filename = mr.filename

            i._callback = "dionaea.modules.python.submithttp.uploadresult"
            i._userdata = cookie

            i.report()
        else:
            del self.cookies[cookie]

    def handle_incident_dionaea_modules_python_submithttp_uploadresult(self, icd):
        fh = open(icd.path, mode="rb")
        c = fh.read()
        logger.info("submithttp uploadresult: {0}".format(c))

        del self.cookies[icd._userdata]
