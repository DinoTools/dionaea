#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
# Copyright (c) 2009 Markus Koetter
# Copyright (c) 2001-2007 Twisted Matrix Laboratories.
# Copyright (c) 2001-2009
#
# Allen Short
# Andrew Bennetts
# Apple Computer, Inc.
# Benjamin Bruheim
# Bob Ippolito
# Canonical Limited
# Christopher Armstrong
# David Reid
# Donovan Preston
# Eric Mangold
# Itamar Shtull-Trauring
# James Knight
# Jason A. Mobarak
# Jean-Paul Calderone
# Jonathan Lange
# Jonathan D. Simms
# Juergen Hermann
# Kevin Turner
# Mary Gardiner
# Matthew Lefkowitz
# Massachusetts Institute of Technology
# Moshe Zadka
# Paul Swartz
# Pavel Pergamenshchik
# Ralph Meijer
# Sean Riley
# Software Freedom Conservancy
# Travis B. Hartwell
# Thomas Herve
# Eyal Lotem
# Antoine Pitrou
# Andy Gayton
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#*
#*             contact nepenthesdev@gmail.com
#*
#*******************************************************************************/



# ftp server
from dionaea import IHandlerLoader, ServiceLoader
from dionaea.core import connection, ihandler, g_dionaea, incident
import logging
import os
import urllib.parse
import tempfile

logger = logging.getLogger('ftp')
logger.setLevel(logging.DEBUG)

#
# the following definitions are taken from twisted
# MIT licensed code, gpl compatible
# Copyright (c) 2001-2007 Twisted Matrix Laboratories.

DATA_CNX_ALREADY_OPEN_START_XFR         = "125"
FILE_STATUS_OK_OPEN_DATA_CNX            = "150"

CMD_OK                                  = "200.1"
TYPE_SET_OK                             = "200.2"
ENTERING_PORT_MODE                      = "200.3"
CMD_NOT_IMPLMNTD_SUPERFLUOUS            = "202"
SYS_STATUS_OR_HELP_REPLY                = "211"
DIR_STATUS                              = "212"
FILE_STATUS                             = "213"
HELP_MSG                                = "214"
NAME_SYS_TYPE                           = "215"
SVC_READY_FOR_NEW_USER                  = "220.1"
WELCOME_MSG                             = "220.2"
SVC_CLOSING_CTRL_CNX                    = "221"
GOODBYE_MSG                             = "221"
DATA_CNX_OPEN_NO_XFR_IN_PROGRESS        = "225"
CLOSING_DATA_CNX                        = "226"
TXFR_COMPLETE_OK                        = "226"
ENTERING_PASV_MODE                      = "227"
ENTERING_EPSV_MODE                      = "229"
USR_LOGGED_IN_PROCEED                   = "230.1"     # v1 of code 230
GUEST_LOGGED_IN_PROCEED                 = "230.2"     # v2 of code 230
REQ_FILE_ACTN_COMPLETED_OK              = "250"
PWD_REPLY                               = "257.1"
MKD_REPLY                               = "257.2"

USR_NAME_OK_NEED_PASS                   = "331.1"     # v1 of Code 331
GUEST_NAME_OK_NEED_EMAIL                = "331.2"     # v2 of code 331
NEED_ACCT_FOR_LOGIN                     = "332"
REQ_FILE_ACTN_PENDING_FURTHER_INFO      = "350"

SVC_NOT_AVAIL_CLOSING_CTRL_CNX          = "421.1"
TOO_MANY_CONNECTIONS                    = "421.2"
CANT_OPEN_DATA_CNX                      = "425"
CNX_CLOSED_TXFR_ABORTED                 = "426"
REQ_ACTN_ABRTD_FILE_UNAVAIL             = "450"
REQ_ACTN_ABRTD_LOCAL_ERR                = "451"
REQ_ACTN_ABRTD_INSUFF_STORAGE           = "452"

SYNTAX_ERR                              = "500"
SYNTAX_ERR_IN_ARGS                      = "501"
CMD_NOT_IMPLMNTD                        = "502"
BAD_CMD_SEQ                             = "503"
CMD_NOT_IMPLMNTD_FOR_PARAM              = "504"
# v1 of code 530 - please log in
NOT_LOGGED_IN                           = "530.1"
# v2 of code 530 - authorization failure
AUTH_FAILURE                            = "530.2"
NEED_ACCT_FOR_STOR                      = "532"
# no such file or directory
FILE_NOT_FOUND                          = "550.1"
PERMISSION_DENIED                       = "550.2"     # permission denied
# anonymous users can't alter filesystem
ANON_USER_DENIED                        = "550.3"
# rmd called on a path that is not a directory
IS_NOT_A_DIR                            = "550.4"
REQ_ACTN_NOT_TAKEN                      = "550.5"
FILE_EXISTS                             = "550.6"
IS_A_DIR                                = "550.7"
PAGE_TYPE_UNK                           = "551"
EXCEEDED_STORAGE_ALLOC                  = "552"
FILENAME_NOT_ALLOWED                    = "553"


RESPONSE = {
    # -- 100's --
    DATA_CNX_ALREADY_OPEN_START_XFR:    '125 Data connection already open, starting transfer',
    FILE_STATUS_OK_OPEN_DATA_CNX:       '150 File status okay; about to open data connection.',

    # -- 200's --
    CMD_OK:                             '200 Command OK',
    TYPE_SET_OK:                        '200 Type set to %s.',
    ENTERING_PORT_MODE:                 '200 PORT OK',
    SYS_STATUS_OR_HELP_REPLY:           '211 System status reply',
    DIR_STATUS:                         '212 %s',
    FILE_STATUS:                        '213 %s',
    HELP_MSG:                           '214 help: %s',
    NAME_SYS_TYPE:                      '215 UNIX Type: L8',
    WELCOME_MSG:                        "220 %s",
    SVC_READY_FOR_NEW_USER:             '220 Service ready',
    GOODBYE_MSG:                        '221 Goodbye.',
    DATA_CNX_OPEN_NO_XFR_IN_PROGRESS:   '225 data connection open, no transfer in progress',
    CLOSING_DATA_CNX:                   '226 Abort successful',
    TXFR_COMPLETE_OK:                   '226 Transfer Complete.',
    ENTERING_PASV_MODE:                 '227 Entering Passive Mode (%s).',
    # where is epsv defined in the rfc's?
    ENTERING_EPSV_MODE:                 '229 Entering Extended Passive Mode (|||%s|).',
    USR_LOGGED_IN_PROCEED:              '230 User logged in, proceed',
    GUEST_LOGGED_IN_PROCEED:            '230 Anonymous login ok, access restrictions apply.',
    #i.e. CWD completed ok
    REQ_FILE_ACTN_COMPLETED_OK:         '250 Requested File Action Completed OK',
    PWD_REPLY:                          '257 "%s"',

    # -- 300's --
    USR_NAME_OK_NEED_PASS:              '331 Password required for %s.',
    GUEST_NAME_OK_NEED_EMAIL:           '331 Guest login ok, type your email address as password.',

    REQ_FILE_ACTN_PENDING_FURTHER_INFO: '350 Requested file action pending further information.',

    # -- 400's --
    CANT_OPEN_DATA_CNX:                 "425 Can't open data connection.",
    CNX_CLOSED_TXFR_ABORTED:            '426 Transfer aborted.  Data connection closed.',

    # -- 500's --
    SYNTAX_ERR:                         "500 Syntax error: %s",
    SYNTAX_ERR_IN_ARGS:                 '501 syntax error in argument(s) %s.',
    CMD_NOT_IMPLMNTD:                   "502 Command '%s' not implemented",
    BAD_CMD_SEQ:                        '503 Incorrect sequence of commands: %s',
    CMD_NOT_IMPLMNTD_FOR_PARAM:         "504 Not implemented for parameter '%s'.",
    NOT_LOGGED_IN:                      '530 Please login with USER and PASS.',
    AUTH_FAILURE:                       '530 Sorry, Authentication failed.',
    FILE_NOT_FOUND:                     '550 %s: No such file or directory.',
    PERMISSION_DENIED:                  '550 %s: Permission denied.',
}


class FTPIhandlerLoader(IHandlerLoader):
    name = "ftpdownload"

    @classmethod
    def start(cls):
        return ftpdownloadhandler("dionaea.download.offer")


class FTPService(ServiceLoader):
    name = "ftp"

    @classmethod
    def start(cls, addr,  iface=None):
        daemon = ftpd()
        daemon.chroot(g_dionaea.config()['modules']['python']['ftp']['root'])
        daemon.bind(addr, 21, iface=iface)
        daemon.listen()
        return daemon


class ftpd(connection):
    UNAUTH, INAUTH, AUTHED, RENAMING = range(4)
    def __init__ (self, proto='tcp'):
        connection.__init__(self, proto)
        logger.debug("ftp test")
        self.state = self.UNAUTH
        self.user = 'bar'
        self.dtp = None
        self.cwd = '/'
        self.basedir = '/tmp/ranz'
        self.dtp = None
        self.dtf = None
        self.limits = {}#{ '_out' : 8192 }

    def chroot(self, p):
        self.basedir = p

    def sendline(self, data):
        self.send(data + '\r\n')

    def reply(self, key, *args):
        msg = RESPONSE[key] % args
        self.sendline(msg)


    def handle_origin(self, parent):
        logger.debug("setting basedir to %s" % parent.basedir)
        self.basedir = parent.basedir

    def handle_established(self):
        self.processors()
        self.reply(WELCOME_MSG, "Welcome to the ftp service")

    def handle_io_in(self, data):
        #		try:
        #			data = data.decode()
        #		except UnicodeDecodeError:
        #			logger.warn("error decoding")
        #		logger.debug("io_in" + data)
        logger.debug(data)
        lastsep = data.rfind(b"\n")
        if lastsep == -1:
            logger.debug("data without linebreak")
            return 0
        lastsep += 1 # add last \n
        logger.debug("input size %i, can do %i" % (len(data), lastsep))
        data = data[:lastsep]
        lines = data.splitlines(0)
        for line in lines:
            logger.debug("processing line '%s'" % line)
            if len(line) == 0:
                continue
            space = line.find(b' ')
            if space != -1:
                cmd = line[:space]
                args = (line[space + 1:],)
            else:
                cmd = line
                args = ()
            logger.warn("cmd '%s'" % cmd)
            r = self.processcmd(cmd, args)
            if isinstance(r,tuple):
                self.reply(*r)
            elif r is not None:
                self.reply(r)
        return lastsep

    def processcmd(self, cmd, args):
        logger.debug("cmd '%s'" % cmd)
        l = [i.decode() for i in args]

        cmd = cmd.upper()
        if self.state == self.UNAUTH:
            if cmd != b'USER':
                return NOT_LOGGED_IN
            self.ftp_USER(*args)
        elif self.state == self.INAUTH:
            if cmd != b'PASS':
                return (BAD_CMD_SEQ, "PASS required after USER")
            self.ftp_PASS(*l)
        method = getattr(self, "ftp_" + cmd.decode(), None)
        if method is not None:
            return method(*l)
        else:
            return (CMD_NOT_IMPLMNTD, cmd.decode())


    def ftp_USER(self, username):
        if not username:
            return (SYNTAX_ERR, 'USER requires an argument')
        self.state = self.INAUTH
        self.user = username
        if username == 'anonymous':
            return GUEST_NAME_OK_NEED_EMAIL
        else:
            return (USR_NAME_OK_NEED_PASS, username)

    def ftp_PASS(self, password):
        if not password:
            return (SYNTAX_ERR, 'PASS requires an argument')
        self.state = self.AUTHED
        if self.user == 'anonymous':
            return GUEST_LOGGED_IN_PROCEED
        else:
            return USR_LOGGED_IN_PROCEED

    def ftp_FEAT(self):
        self.send('211-Features:\r\n' +
                  ' PASV\r\n' +
                  ' PORT\r\n' +
                  '211 End\r\n')
        return None

    def ftp_PORT(self, address):
        if self.dtf:
            self.dtf.close()
            self.dtf = None
        if self.dtp:
            self.dtp.close()
            self.dtp = None
        addr = list(map(int, address.split(',')))
        ip = '%d.%d.%d.%d' % tuple(addr[:4])
        port = addr[4] << 8 | addr[5]
        logger.debug("PORT cmd for port %i" % port)
        if self.remote.host != ip and "::ffff:" + self.remote.host != ip:
            logger.warn("Potential FTP Bounce Scan detected")
            return None
        self.dtp = ftpdataconnect(ip, port, self)
        return None

    def ftp_PASV(self):
        if self.dtf:
            self.dtf.close()
            self.dtf = None
        if self.dtp:
            self.dtp.close()
            self.dtp = None
        self.dtf = ftpdatalisten(host=self.local.host, port=0, ctrl=self)
        host = self.dtf.local.host
        port = self.dtf.local.port
        self.reply(ENTERING_PASV_MODE, encodeHostPort(host, port))

    def ftp_QUIT(self):
        self.reply(GOODBYE_MSG)
        self.close()

    def real_path(self, p=None):
        if p:
            name = os.path.join(self.cwd, p)
        else:
            name = self.cwd

        if len(name) >= 1 and name[0] == '/':
            name = name[1:]
        name = os.path.join(self.basedir, name)
        name = os.path.normpath(name)
        return name

    def ftp_RETR(self, p):
        if not p:
            return (SYNTAX_ERR_IN_ARGS, RETR)

        name = self.real_path(p)

        if not name.startswith(self.basedir):
            return (PERMISSION_DENIED, p)

        if os.path.exists(name) and os.path.isfile(name):
            if self.dtp:
                if self.dtp.status == 'established':
                    self.reply(FILE_STATUS_OK_OPEN_DATA_CNX)
                    self.dtp.send_file(name)
                else:
                    logger.warn("dtp state %s %s:%i <-> %s:%i!" %
                                (self.dtp.status,
                                 self.dtp.remote.host, self.dtp.remote.port,
                                 self.dtp.local.host, self.dtp.local.port))
            else:
                logger.warn("no dtp on %s:%i <-> %s:%i!" %
                            (self.dtp.remote.host, self.dtp.remote.port,
                             self.dtp.local.host, self.dtp.local.port))
        else:
            return (FILE_NOT_FOUND, p)

    def ftp_STOR(self, p):
        if not p:
            return (SYNTAX_ERR_IN_ARGS, STOR)

        file = self.real_path(p)
        if os.path.exists(file):
            return (PERMISSION_DENIED, p)

        if not file.startswith(self.basedir):
            return (PERMISSION_DENIED, p)

        if self.dtp:
            if self.dtp.status == 'established':
                self.reply(FILE_STATUS_OK_OPEN_DATA_CNX)
                self.dtp.recv_file(file)
            else:
                logger.warn("dtp state %s %s:%i <-> %s:%i!" %
                            (self.dtp.status,
                             self.dtp.remote.host, self.dtp.remote.port,
                             self.dtp.local.host, self.dtp.local.port))
        else:
            logger.warn("no dtp on %s:%i <-> %s:%i!" %
                        (self.dtp.remote.host, self.dtp.remote.port,
                         self.dtp.local.host, self.dtp.local.port))


    def ftp_TYPE(self, t):
        if t == 'I':
            return (TYPE_SET_OK, 'I')
        else:
            return (CMD_NOT_IMPLMNTD_FOR_PARAM, t)

    def ftp_LIST(self, p=None):
        name = self.real_path(p)

        if not name.startswith(self.basedir):
            return (FILE_NOT_FOUND, p)

        if os.path.exists(name):
            if self.dtp:
                if self.dtp.status == 'established':
                    self.reply(FILE_STATUS_OK_OPEN_DATA_CNX)
                    self.dtp.send_list(name, len(name)+1)
                else:
                    logger.warn("dtp state %s %s:%i <-> %s:%i!" %
                                (self.dtp.status,
                                 self.dtp.remote.host, self.dtp.remote.port,
                                 self.dtp.local.host, self.dtp.local.port))
            else:
                logger.warn("no dtp on %s:%i <-> %s:%i!" %
                            (self.dtp.remote.host, self.dtp.remote.port,
                             self.dtp.local.host, self.dtp.local.port))
        else:
            return (PERMISSION_DENIED, p)

    def ftp_PWD(self):
        return (PWD_REPLY, self.cwd)

    def ftp_CWD(self, p):
        cwd = self.real_path(p)

        if not cwd.startswith(self.basedir):
            return (FILE_NOT_FOUND, p)
        else:
            self.cwd = cwd[len(self.basedir):]
            if self.cwd == "":
                self.cwd = "/"

        if os.path.exists(cwd) and os.path.isdir(cwd):
            return REQ_FILE_ACTN_COMPLETED_OK
        else:
            return (PERMISSION_DENIED, p)

    def ftp_PBSZ(self, arg):
        return CMD_OK

    def ftp_SYST(self):
        return NAME_SYS_TYPE

    def ftp_SIZE(self, p):
        if not p:
            return (FILE_NOT_FOUND,p)

        file = self.real_path(p)

        if not file.startswith(self.basedir):
            return (FILE_NOT_FOUND, p)

        if os.path.exists(file) and os.path.isfile(file):
            return (FILE_STATUS, str(stat(file).st_size))
        return (FILE_NOT_FOUND,p)

    def ftp_MDTM(self, p):
        if not p:
            return (FILE_NOT_FOUND,p)
        file = self.real_path(p)

        if not file.startswith(self.basedir):
            return (FILE_NOT_FOUND, p)

        if os.path.exists(file) and os.path.isfile(file):
            return (FILE_STATUS, time.strftime('%Y%m%d%H%M%S', time.gmtime(stat(file).st_mtime)))
        return (FILE_NOT_FOUND,p)

    def ftp_RMD(self, p):
        if not p:
            return (FILE_NOT_FOUND,p)
        dir = self.real_path(p)

        if not dir.startswith(self.basedir):
            return (FILE_NOT_FOUND, p)

        if os.path.exists(dir) and os.path.isdir(dir):
            os.rmdir(dir)
            return REQ_FILE_ACTN_COMPLETED_OK
        return (FILE_NOT_FOUND,p)

    def ftp_MKD(self, p):
        if not p:
            return (FILE_NOT_FOUND,p)
        dir = self.real_path(p)

        if not dir.startswith(self.basedir):
            return (FILE_NOT_FOUND, p)

        if os.path.isdir(dir):
            return (PERMISSION_DENIED, p)
        os.mkdir(dir)
        return REQ_FILE_ACTN_COMPLETED_OK



    def handle_error(self, err):
        pass

    def handle_disconnect(self):
        if self.dtf:
            self.dtf.close()
            self.dtf = None
        if self.dtp:
            self.dtp.close()
            self.dtp = None
        return 0


def encodeHostPort(host, port):
    numbers = host.split('.') + [str(port >> 8), str(port % 256)]
    return ','.join(numbers)


from os import stat
from stat import *
import time
import io

class ftpdatacon(connection):
    def __init__ (self, ctrl=None):
        connection.__init__(self,'tcp')
        self.ctrl = ctrl
        self.mode = None

    def handle_error (self, err):
        if self.ctrl:
            self.ctrl.reply(CANT_OPEN_DATA_CNX)

    def send_list(self, p, rm):
        def ls(f, r):
            logger.debug("stat %s" % f)
            name = f[r:]
            s=stat(f)
            size = s.st_size
            directory = S_ISDIR(s.st_mode)
            permissions = S_IMODE(s[ST_MODE])
            hardlinks = s.st_nlink
            modified = s.st_mtime
            owner = s.st_uid
            group = s.st_gid
            def formatMode(mode):
                return ''.join([mode & (256 >> n) and 'rwx'[n % 3] or '-' for n in range(9)])

            def formatDate(mtime):
                now = time.gmtime()
                info = {
                    'month': mtime.tm_mon,
                    'day': mtime.tm_mday,
                    'year': mtime.tm_year,
                    'hour': mtime.tm_hour,
                    'minute': mtime.tm_min
                }
                if now.tm_year != mtime.tm_year:
                    return '%(month)s %(day)02d %(year)5d' % info
                else:
                    return '%(month)s %(day)02d %(hour)02d:%(minute)02d' % info

            format = ('%(directory)s%(permissions)s%(hardlinks)4d '
                      '%(owner)-9s %(group)-9s %(size)15d %(date)12s '
                      '%(name)s')
            return format % {
                'directory': directory and 'd' or '-',
                'permissions': formatMode(permissions),
                'hardlinks': hardlinks,
                'owner': owner,
                'group': group,
                'size': size,
                'date': formatDate(time.gmtime(modified)),
                'name': name}
        self.mode = 'list'
        if os.path.isdir(p):
            self.data = [ls(os.path.join(p,f), rm) for f in os.listdir(p)]
        elif os.path.isfile(p):
            self.data = [ls(p)]
        logger.debug("p %s len %i" % (p, len(self.data)) )
        if len(self.data) > 0:
            self.off = 0
            self.off = self.off + 1
            self.send(self.data[self.off-1] + '\r\n')
        else:
            self.close()
            if self.ctrl:
                self.ctrl.dtp = None
                self.ctrl.reply(TXFR_COMPLETE_OK)


    def recv_file(self, p):
        logger.debug(p)
        self.mode = 'recv_file'
        self.file = io.open(p, 'wb+')
        print(self.file)

    def send_file(self, p):
        self.mode = 'file'
        self.file = io.open(p, 'rb')
        w = self.file.read(1024)
        self.send(w)
        if len(w) < 1024:
            self.file.close()
            self.mode = None
            self.close()
            if self.ctrl:
                self.ctrl.reply(TXFR_COMPLETE_OK)
                self.ctrl.dtp = None

    def handle_io_in(self, data):
        if self.mode == "recv_file":
            self.file.write(data)
            return len(data)

    def handle_io_out(self):
        logger.debug("io_out")
        if self.mode == 'list':
            if self.off < len(self.data):
                self.off = self.off + 1
                self.send(self.data[self.off - 1] + '\r\n')
            else:
                self.close()
                if self.ctrl:
                    self.ctrl.dtp = None
                    self.ctrl.reply(TXFR_COMPLETE_OK)

        elif self.mode == 'file':
            w = self.file.read(1024)
            self.send(w)
            if len(w) < 1024:
                self.mode = None
                self.close()
                self.file.close()
                if self.ctrl:
                    self.ctrl.dtp = None
                    self.ctrl.reply(TXFR_COMPLETE_OK)


    def handle_disconnect(self):
        if self.ctrl:
            if self.ctrl.dtf:
                self.ctrl.dtf = None
            if self.ctrl.dtp:
                self.ctrl.dtp = None
            if self.mode == 'file' and self.file:
                self.file.close()
            if self.mode == 'recv_file' and self.file:
                self.file.close()
                self.ctrl.reply(TXFR_COMPLETE_OK)
        return 0

    def handle_origin(self, parent):
        pass
#		if parent.limits._out:
#			self._out.limit = parent.limits._out

class ftpdataconnect(ftpdatacon):
    def __init__ (self, host, port, ctrl):
        ftpdatacon.__init__(self,ctrl)
        self.connect(host,port)
    def handle_established(self):
        logger.debug("DATA connection established")
        self.ctrl.reply(ENTERING_PORT_MODE)

class ftpdatalisten(ftpdatacon):
    def __init__ (self, host=None, port=None, ctrl=None):
        ftpdatacon.__init__(self,ctrl)
        if host is not None:
            self.bind(host,port)
            self.listen(1)
            if ctrl.limits:
                self._out.throttle = ctrl.limits['_out']
    def handle_established(self):
        logger.debug("DATA connection established")
    def handle_origin(self, parent):
        ftpdatacon.handle_origin(self,parent)
        logger.debug("Meeting parent")
        self.ctrl = parent.ctrl
        self.ctrl.dtp = self
        self.ctrl.dtf = None
        parent.ctrl = None
        parent.close()


# ftp client
import re
import random
_linesep_regexp = re.compile(b"\r?\n")

class ftpctrl(connection):
    def __init__(self, ftp):
        connection.__init__(self, 'tcp')
        self.ftp = ftp
        self.state = 'NONE'
        self.timeouts.sustain = 60

    def handle_established(self):
        logger.debug("FTP CTRL connection established")

    def handle_io_in(self, data):
        dlen = len(data)
        lines = _linesep_regexp.split(data)#.decode('UTF-8'))

        remain = lines.pop()
        dlen = dlen - len(remain)

        for line in lines:
            logger.debug("FTP LINE: " + str(line))
            c = int(line[:3])
            s = line[3:4]
            if self.state == 'NONE':
                if c == 220 and s != b'-':
                    self.cmd('USER ' + self.ftp.user)
                    self.state = 'USER'
            elif self.state == 'USER' or self.state == 'PASS':
                if self.state == 'USER' and c == 331 and s != b'-':
                    self.cmd('PASS ' + self.ftp.passwd)
                    self.state = 'PASS'
                if c == 230 and s != b'-':
                    if self.ftp.mode == 'binary':
                        self.cmd('TYPE I')
                        self.state = 'TYPE'
                    else:
                        port = self.ftp.makeport()
                        self.cmd('PORT ' + port)
                        self.state = 'PORT'
            elif self.state == 'TYPE':
                if (c >= 200 and c < 300) and s != b'-':
                    port = self.ftp.makeport()
                    self.cmd('PORT ' + port)
                    self.state = 'PORT'
            elif self.state == 'PORT':
                if c == 200 and s != b'-':
                    self.cmd('RETR ' + self.ftp.file)
                    self.state = 'RETR'
                else:
                    logger.warn("PORT command failed")
            elif self.state == 'RETR':
                if (c > 200 and c < 300)  and s != b'-':
                    self.cmd('QUIT')
                    self.state = 'QUIT'
                    self.ftp.ctrldone()

        return dlen

    def cmd(self, cmd):
        logger.debug("FTP CMD: '" + cmd +"'")
        self.send(cmd + '\r\n')

    def handle_error(self, err):
        self.ftp.fail()
        return False

    def handle_disconnect(self):
        if self.state != 'QUIT':
            self.ftp.fail()
        return False

    def handle_timeout_idle(self):
        return False

    def handle_timeout_sustain(self):
        return False

class ftpdata(connection):
    def __init__(self, ftp=None):
        connection.__init__(self, 'tcp')
        self.ftp = ftp
        self.timeouts.listen = 10


    def handle_established(self):
        logger.debug("FTP DATA established")
        self.timeouts.idle = 30
        self.fileobj = tempfile.NamedTemporaryFile(delete=False, prefix='ftp-', suffix=g_dionaea.config(
        )['downloads']['tmp-suffix'], dir=g_dionaea.config()['downloads']['dir'])

    def handle_origin(self, parent):
        self.ftp = parent.ftp
        self.ftp.dataconn = self
        self.ftp.datalistener.close()
        self.ftp.datalistener = None

    def handle_io_in(self, data):
        self.fileobj.write(data)
        return len(data)

    def handle_timeout_idle(self):
        self.fileobj.unlink(self.fileobj.name)
        self.fileobj = None
        self.ftp.fail()
        return False

    def handle_disconnect(self):
        logger.debug("received %i bytes" %(self._in.accounting.bytes))
        if hasattr(self, 'fileobj')and self.fileobj != None:
            #		print(type(self.file))
            #		print(self.file)
            self.fileobj.close()
            icd = incident("dionaea.download.complete")
            icd.path = self.fileobj.name
            icd.con = self.ftp.con
            icd.url = self.ftp.url
            icd.report()
            self.fileobj.unlink(self.fileobj.name)
            self.ftp.dataconn = None
            self.ftp.datadone()
        return False

    def handle_timeout_listen(self):
        self.ftp.fail()
        return False

class ftp:
    def __init__(self):
        self.ctrl = ftpctrl(self)

    def download(self, con, user, passwd, host, port, file, mode, url):
        self.user = user
        self.passwd = passwd
        self.host = host
        self.port = port
        self.file = file
        self.mode = mode
        self.con = con
        self.url = url

        if con:
            self.local = con.local.host
            self.ctrl.bind(self.local, 0)
            self.con.ref()

        self.ctrl.connect(host, port)
        self.dataconn = None
        self.datalistener = None

        if con:
            i=incident("dionaea.connection.link")
            i.parent = con
            i.child = self.ctrl
            i.report()

    def makeport(self):
        self.datalistener = ftpdata(ftp=self)
        try:
            portrange = g_dionaea.config()['modules']['python'][
                'ftp']['active-ports']
            (minport, maxport) = portrange.split('-')
            minport = int(minport)
            maxport = int(maxport)
        except:
            minport = 62001
            maxport = 63000

        try:
            # for NAT setups
            host = g_dionaea.config()['modules']['python'][
                'ftp']['active-host']
            if host == '0.0.0.0':
                host = self.ctrl.local.host
                logger.info("datalisten host %s" % host)
            else:
                import socket
                host = socket.gethostbyname(host)
                logger.info("resolved host %s" % host)
        except:
            host = self.ctrl.local.host
            logger.info("except datalisten host %s" % self.ctrl.local.host)


        # NAT, use a port range which is forwarded to your honeypot
        ports = list(
            filter(lambda port: ((port >> 4) & 0xf) != 0, range(minport, maxport)))
        random.shuffle(ports)
        port = None
        for port in ports:
            self.datalistener.bind(self.ctrl.local.host, port)
            if self.datalistener.listen() == True:
                port = self.datalistener.local.port
                i=incident("dionaea.connection.link")
                i.parent = self.ctrl
                i.child = self.datalistener
                i.report()
                break
        hbytes = host.split('.')
        pbytes = [repr(port//256), repr(port%256)]
        bytes = hbytes + pbytes
        port = ','.join(bytes)
        logger.debug("PORT CMD %s" % (port))
        return port

    def ctrldone(self):
        logger.info("SUCCESS DOWNLOADING FILE")
        self.done()

    def datadone(self):
        logger.info("FILE received")
        self.done()

    def done(self):
        if self.ctrl and self.ctrl.state == 'QUIT' and self.dataconn == None:
            logger.info("proceed processing file!")
            self.ctrl = None
            self.finish()

    def fail(self):
        self.finish()

    def finish(self):
        if self.con:
            self.con.unref()
            self.con = None
        if self.ctrl != None:
            self.ctrl.close()
            self.ctrl = None
        if self.datalistener and self.datalistener != None:
            self.datalistener.close()
            self.datalistener = None
        if self.dataconn and self.dataconn != None:
            self.dataconn.close()
            self.dataconn = None

class ftpdownloadhandler(ihandler):
    def __init__(self, path):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)
    def handle_incident(self, icd):
        url = icd.url
        p = urllib.parse.urlsplit(url)
        print(p)
        if p.scheme == 'ftp':
            logger.info("do download")
            try:
                con = icd.con
            except AttributeError:
                con = None

            if hasattr(icd,'ftpmode'):
                ftpmode = icd.ftpmode
            else:
                ftpmode = 'binary'

            f = ftp()
            f.download(
                con, p.username, p.password, p.hostname, p.port, p.path, ftpmode, url)
