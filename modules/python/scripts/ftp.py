#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
# Copyright (c) 2016 PhiBo
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
from dionaea import ServiceLoader
from dionaea.core import connection, ihandler, g_dionaea, incident
import logging
import os
from os import stat
from stat import *
import time
import io


logger = logging.getLogger('ftp')
logger.setLevel(logging.DEBUG)

#
# Parts of the following definitions are taken from twisted
# MIT licensed code, gpl compatible
# Copyright (c) 2001-2007 Twisted Matrix Laboratories.

RESPONSE = {
    # -- 100's --
    "data_cnx_already_open_start_xfr":    "125 Data connection already open, starting transfer",
    "file_status_ok_open_data_cnx":       "150 File status okay; about to open data connection.",

    # -- 200's --
    "cmd_ok":                             "200 Command OK",
    "type_set_ok":                        "200 Type set to {mode}.",
    "entering_port_mode":                 '200 PORT OK',
    "sys_status_or_help_reply":           '211 System status reply',
    "dir_status":                         '212 %s',
    "file_status":                        '213 {value}',
    #"help_msg":                           '214 help: %s',
    "name_sys_type":                      '215 UNIX Type: L8',
    "welcome_msg":                        "220 Welcome to the ftp service",
    "svc_ready_for_new_user":             '220 Service ready',
    "goodbye_msg":                        '221 Goodbye.',
    "data_cnx_open_no_xfr_in_progress":   '225 data connection open, no transfer in progress',
    "closing_data_cnx":                   '226 Abort successful',
    "txfr_complete_ok":                   '226 Transfer Complete.',
    "entering_pasv_mode":                 '227 Entering Passive Mode ({host}).',
    # where is epsv defined in the rfc's?
    #"entering_epsv_mode":                 '229 Entering Extended Passive Mode (|||%s|).',
    "usr_logged_in_proceed":              '230 User logged in, proceed',
    "guest_logged_in_proceed":            '230 Anonymous login ok, access restrictions apply.',
    #i.e. CWD completed ok
    "req_file_actn_completed_ok":         '250 Requested File Action Completed OK',
    "pwd_reply":                          "257 \"{cwd}\"",

    # -- 300's --
    "usr_name_ok_need_pass":              '331 Password required for {username}.',
    "guest_name_ok_need_email":           '331 Guest login ok, type your email address as password.',

    "req_file_actn_pending_further_info": '350 Requested file action pending further information.',

    # -- 400's --
    "cant_open_data_cnx":                 "425 Can't open data connection.",
    "cnx_closed_txfr_aborted":            '426 Transfer aborted.  Data connection closed.',

    # -- 500's --
    "syntax_error_pass_requires_arg":     "500 Syntax error: PASS requires an argument",
    "syntax_error_user_requires_arg":     "500 Syntax error: USER requires an argument",
    "syntax_err_in_args":                 '501 syntax error in argument(s) {command}.',
    "cmd_not_implmntd":                   "502 Command '{command}' not implemented",
    "bad_cmd_seq_pass_after_user":        "503 Incorrect sequence of commands: PASS required after USER",
    "cmd_not_implmntd_for_param":         "504 Not implemented for parameter '{param}'.",
    "not_logged_in":                      '530 Please login with USER and PASS.',
    "auth_failure":                       '530 Sorry, Authentication failed.',
    "file_not_found":                     '550 {filename}: No such file or directory.',
    "permission_denied":                  '550 {path}: Permission denied.',
}


class FTPService(ServiceLoader):
    name = "ftp"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        if config is None:
            config = {}

        daemon = FTPd()
        daemon.apply_config(config)
        daemon.bind(addr, 21, iface=iface)
        daemon.listen()
        return daemon


class FTPd(connection):
    UNAUTH, INAUTH, AUTHED, RENAMING = range(4)

    protocol_name = "ftpd"
    shared_config_values = (
        "basedir",
        "response_msgs"
    )

    def __init__(self, proto='tcp'):
        connection.__init__(self, proto)
        logger.debug("ftp test")
        self.state = self.UNAUTH
        self.user = 'bar'
        self.dtp = None
        self.cwd = '/'
        self.basedir = '/tmp/ranz'
        self.dtp = None
        self.dtf = None
        self.limits = {}  # { '_out' : 8192 }
        # Copy default response messages
        self.response_msgs = dict(RESPONSE.items())

    def apply_config(self, config):
        self.basedir = config.get("root")
        self.response_msgs.update(config.get("response_messages", {}))

    def chroot(self, p):
        self.basedir = p

    def sendline(self, data):
        self.send(data + '\r\n')

    def reply(self, name, **kwargs):
        msg = self.response_msgs.get(name, "")
        self.sendline(msg.format(**kwargs))

    def handle_origin(self, parent):
        logger.debug("setting basedir to %s" % parent.basedir)
        self.basedir = parent.basedir

    def handle_established(self):
        self.processors()
        self.reply("welcome_msg")

    def handle_io_in(self, data):
        # try:
        #     data = data.decode()
        # except UnicodeDecodeError:
        #     logger.warn("error decoding")
        #     logger.debug("io_in" + data)

        logger.debug(data)
        lastsep = data.rfind(b"\n")
        if lastsep == -1:
            logger.debug("data without linebreak")
            return 0

        lastsep += 1  # add last \n
        logger.debug("input size %i, can do %i", len(data), lastsep)
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
            self.processcmd(cmd, args)
        return lastsep

    def processcmd(self, cmd, args):
        logger.debug("cmd '%s'" % cmd)
        l = [i.decode() for i in args]

        i = incident("dionaea.modules.python.ftp.command")
        i.con = self
        i.command = cmd
        i.arguments = l
        i.report()

        cmd = cmd.upper()
        if self.state == self.UNAUTH:
            if cmd != b'USER':
                self.reply("not_logged_in")
                return
            self.ftp_USER(*l)
        elif self.state == self.INAUTH:
            if cmd != b'PASS':
                self.reply("bad_cmd_seq_pass_after_user")
                return
            self.ftp_PASS(*l)
        else:
            method = getattr(self, "ftp_" + cmd.decode(), None)
            if method is not None:
                msg = method(*l)
                if isinstance(msg, str):
                    self.error("Returning messages is deprecated please report so we can fix it")
                    self.sendline(msg)
            else:
                self.reply("cmd_not_implmntd", command=cmd.decode())

    def ftp_USER(self, username):
        if not username:
            self.reply("syntax_error_user_requires_arg")
            return

        self.state = self.INAUTH
        self.user = username
        if username == "anonymous":
            self.reply("guest_name_ok_need_email")
            return
        else:
            self.reply("usr_name_ok_need_pass", username=username)
            return

    def ftp_PASS(self, password):
        if not password:
            self.reply("syntax_error_pass_requires_arg")
            return

        i = incident("dionaea.modules.python.ftp.login")
        i.con = self
        i.username = self.user
        i.password = password
        i.report()

        self.state = self.AUTHED
        if self.user == "anonymous":
            self.reply("guest_logged_in_proceed")
        else:
            self.reply("usr_logged_in_proceed")

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
        self.dtp = FTPDataConnect(ip, port, self)
        return None

    def ftp_PASV(self):
        if self.dtf:
            self.dtf.close()
            self.dtf = None
        if self.dtp:
            self.dtp.close()
            self.dtp = None
        self.dtf = FTPDataListen(host=self.local.host, port=0, ctrl=self)
        host = self.dtf.local.host
        port = self.dtf.local.port
        self.reply("entering_pasv_mode", host=encodeHostPort(host, port))

    def ftp_QUIT(self):
        self.reply("goodbye_msg")
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
            self.reply("syntax_err_in_args", command="RETR")
            return

        name = self.real_path(p)
        if not name.startswith(self.basedir):
            self.reply("permission_denied", path=p)
            return

        if os.path.exists(name) and os.path.isfile(name):
            if self.dtp:
                if self.dtp.status == 'established':
                    self.reply("file_status_ok_open_data_cnx")
                    self.dtp.send_file(name)
                else:
                    logger.warn(
                        "dtp state %s %s:%i <-> %s:%i!",
                        self.dtp.status,
                        self.dtp.remote.host,
                        self.dtp.remote.port,
                        self.dtp.local.host,
                        self.dtp.local.port
                    )
            else:
                logger.warn(
                    "no dtp on %s:%i <-> %s:%i!",
                    self.dtp.remote.host,
                    self.dtp.remote.port,
                    self.dtp.local.host,
                    self.dtp.local.port
                )
        else:
            self.reply("file_not_found", filename=p)

    def ftp_STOR(self, p):
        if not p:
            self.reply("syntax_err_in_args", command="STOR")
            return

        file = self.real_path(p)
        if os.path.exists(file):
            self.reply("permission_denied", path=p)
            return

        if not file.startswith(self.basedir):
            self.reply("permission_denied", path=p)
            return

        if self.dtp:
            if self.dtp.status == 'established':
                self.reply("file_status_ok_open_data_cnx")
                self.dtp.recv_file(file)
            else:
                logger.warn(
                    "dtp state %s %s:%i <-> %s:%i!",
                    self.dtp.status,
                    self.dtp.remote.host,
                    self.dtp.remote.port,
                    self.dtp.local.host,
                    self.dtp.local.port
                )
        else:
            logger.warn(
                "no dtp on %s:%i <-> %s:%i!",
                self.dtp.remote.host,
                self.dtp.remote.port,
                self.dtp.local.host,
                self.dtp.local.port
            )

    def ftp_TYPE(self, t):
        if t == 'I':
            self.reply("type_set_ok", mode="I")
            return
        else:
            self.reply("cmd_not_implmntd_for_param", param=t)
            return

    def ftp_LIST(self, p=None):
        name = self.real_path(p)

        if not name.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        if os.path.exists(name):
            if self.dtp:
                if self.dtp.status == 'established':
                    self.reply("file_status_ok_open_data_cnx")
                    self.dtp.send_list(name, len(name)+1)
                else:
                    logger.warn(
                        "dtp state %s %s:%i <-> %s:%i!",
                        self.dtp.status,
                        self.dtp.remote.host,
                        self.dtp.remote.port,
                        self.dtp.local.host,
                        self.dtp.local.port
                    )
            else:
                logger.warn(
                    "no dtp on %s:%i <-> %s:%i!",
                    self.dtp.remote.host,
                    self.dtp.remote.port,
                    self.dtp.local.host,
                    self.dtp.local.port
                )
        else:
            self.reply("permission_denied", path=p)

    def ftp_PWD(self):
        self.reply("pwd_reply", cwd=self.cwd)

    def ftp_CWD(self, p):
        cwd = self.real_path(p)

        if not cwd.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        self.cwd = cwd[len(self.basedir):]
        if self.cwd == "":
            self.cwd = "/"

        if os.path.exists(cwd) and os.path.isdir(cwd):
            self.reply("req_file_actn_completed_ok")
            return

        self.reply("permission_denied", path=p)

    def ftp_PBSZ(self, arg):
        self.reply("cmd_ok")

    def ftp_SYST(self):
        self.reply("name_sys_type")

    def ftp_SIZE(self, p):
        if not p:
            self.reply("file_not_found", filename=p)
            return

        file = self.real_path(p)

        if not file.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        if os.path.exists(file) and os.path.isfile(file):
            self.reply("file_status", value=str(stat(file).st_size))
            return

        self.reply("file_not_found", filename=p)

    def ftp_MDTM(self, p):
        if not p:
            self.reply("file_not_found", filename=p)
            return

        file = self.real_path(p)
        if not file.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        if os.path.exists(file) and os.path.isfile(file):
            self.reply(
                "file_status",
                value=time.strftime('%Y%m%d%H%M%S', time.gmtime(stat(file).st_mtime))
            )
            return

        self.reply("file_not_found", filename=p)

    def ftp_RMD(self, p):
        if not p:
            self.reply("file_not_found", filename=p)
            return

        dir = self.real_path(p)
        if not dir.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        if os.path.exists(dir) and os.path.isdir(dir):
            os.rmdir(dir)
            self.reply("req_file_actn_completed_ok")
            return

        self.reply("file_not_found", filename=p)

    def ftp_MKD(self, p):
        if not p:
            self.reply("file_not_found", filename=p)
            return

        dir = self.real_path(p)
        if not dir.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        if os.path.isdir(dir):
            self.reply("permission_denied", path=p)
            return

        os.mkdir(dir)
        self.reply("req_file_actn_completed_ok")

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


class FTPDataCon(connection):
    def __init__(self, ctrl=None):
        connection.__init__(self, 'tcp')
        self.ctrl = ctrl
        self.mode = None
        self.file = None

    def handle_error(self, err):
        if self.ctrl:
            self.ctrl.reply("cant_open_data_cnx")

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

            format = (
                '%(directory)s%(permissions)s%(hardlinks)4d '
                '%(owner)-9s %(group)-9s %(size)15d %(date)12s '
                '%(name)s'
            )
            return format % {
                'directory': directory and 'd' or '-',
                'permissions': formatMode(permissions),
                'hardlinks': hardlinks,
                'owner': owner,
                'group': group,
                'size': size,
                'date': formatDate(time.gmtime(modified)),
                'name': name
            }

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
                self.ctrl.reply("txfr_complete_ok")

    def recv_file(self, p):
        logger.debug(p)
        self.mode = 'recv_file'
        self.file = io.open(p, 'wb+')
        print(self.file)

    def send_file(self, p):
        self.mode = "file"
        self.file = open(p, "rb")
        self.handle_io_out()

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
                    self.ctrl.reply("txfr_complete_ok")

        elif self.mode == "file":
            w = self.file.read(1024)
            self.send(w)
            if len(w) < 1024 and self.mode is not None:
                self.mode = None
                self.close()
                self.file.close()
                if self.ctrl:
                    self.ctrl.dtp = None
                    self.ctrl.reply("txfr_complete_ok")

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
                self.ctrl.reply("txfr_complete_ok")
        return 0

    def handle_origin(self, parent):
        pass
        # if parent.limits._out:
        #     self._out.limit = parent.limits._out


class FTPDataConnect(FTPDataCon):
    protocol_name = "ftpdataconnect"

    def __init__(self, host, port, ctrl):
        FTPDataCon.__init__(self, ctrl)
        self.connect(host, port)

    def handle_established(self):
        logger.debug("DATA connection established")
        self.ctrl.reply("entering_port_mode")


class FTPDataListen(FTPDataCon):
    protocol_name = "ftpdatalisten"

    def __init__(self, host=None, port=None, ctrl=None):
        FTPDataCon.__init__(self, ctrl)
        if host is not None:
            self.bind(host, port)
            self.listen(1)
            if ctrl.limits:
                self._out.throttle = ctrl.limits['_out']

    def handle_established(self):
        logger.debug("DATA connection established")

    def handle_origin(self, parent):
        FTPDataCon.handle_origin(self, parent)
        logger.debug("Meeting parent")
        self.ctrl = parent.ctrl
        self.ctrl.dtp = self
        self.ctrl.dtf = None
        parent.ctrl = None
        parent.close()
