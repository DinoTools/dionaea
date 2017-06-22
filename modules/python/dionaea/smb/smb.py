#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2010  Markus Koetter & Tan Kean Siong
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

from dionaea.core import incident, connection, g_dionaea

import traceback
import hashlib
import logging
import os
import tempfile
from uuid import UUID

from .include.smbfields import *
from .rpcservices import __shares__
from .include.gssapifields import GSSAPI,SPNEGO, NegTokenTarg
from .include.ntlmfields import NTLMSSP_Header, NTLM_Negotiate, NTLM_Challenge, NTLMSSP_REQUEST_TARGET
from .include.packet import Raw
from .include.asn1.ber import BER_len_dec, BER_len_enc, BER_identifier_dec
from .include.asn1.ber import BER_CLASS_APP, BER_CLASS_CON,BER_identifier_enc
from .include.asn1.ber import BER_Exception
from dionaea.util import calculate_doublepulsar_opcode, xor


smblog = logging.getLogger('SMB')

STATE_START = 0
STATE_SESSIONSETUP = 1
STATE_TREECONNECT = 2
STATE_NTCREATE = 3
STATE_NTWRITE = 4
STATE_NTREAD = 5

registered_services = {}

def register_rpc_service(service):
    uuid = service.uuid
    registered_services[uuid] = service


class smbd(connection):
    shared_config_values = [
        "config"
    ]

    def __init__ (self, proto="tcp", config=None):
        connection.__init__(self,"tcp")
        self.state = {
            'lastcmd': None,
            'readcount': 0,
            'stop': False,
        }
        self.buf = b''
        self.buf2 = b''  # ms17-010 SMB_COM_TRANSACTION2
        self.outbuf = None
        self.fids = {}
        self.printer = b'' # spoolss file "queue"

        self.config = None

    def apply_config(self, config=None):
        # Avoid import loops
        from .extras import SmbConfig
        self.config = SmbConfig(config=config)
        # Set the global OS_TYPE value
        # ToDo: This is a quick and dirty hack
        from . import rpcservices
        rpcservices.__shares__ = self.config.shares
        rpcservices.OS_TYPE = self.config.os_type

    def handle_established(self):
        #		self.timeouts.sustain = 120
        self.timeouts.idle = 120
#		self._in.accounting.limit  = 2000*1024
#		self._out.accounting.limit = 2000*1024
        self.processors()

    def handle_io_in(self,data):
        try:
            p = NBTSession(data, _ctx=self)
        except:
            t = traceback.format_exc()
            smblog.error(t)
            return len(data)

        if len(data) < (p.LENGTH+4):
            #we probably do not have the whole packet yet -> return 0
            smblog.info('=== SMB did not get enough data')
            return 0

        if p.TYPE == 0x81:
            self.send(NBTSession(TYPE=0x82).build())
            return len(data)
        elif p.TYPE != 0:
            # we currently do not handle anything else
            return len(data)

        if p.haslayer(SMB_Header) and p[SMB_Header].Start != b'\xffSMB':
            # not really SMB Header -> bail out
            smblog.error('=== not really SMB')
            self.close()
            return len(data)

        p.show()
        r = None

        # this is one of the things you have to love, it violates the spec, but
        # has to work ...
        if p.haslayer(SMB_Sessionsetup_ESEC_AndX_Request) and p.getlayer(SMB_Sessionsetup_ESEC_AndX_Request).WordCount == 13:
            smblog.debug("recoding session setup request!")
            p.getlayer(SMB_Header).decode_payload_as(
                SMB_Sessionsetup_AndX_Request2)
            x = p.getlayer(SMB_Sessionsetup_AndX_Request2)
            x.show()

        r = self.process(p)
        smblog.debug("packet: %s" % p.summary())

        if p.haslayer(Raw):
            smblog.warning("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()

#		i = incident("dionaea.module.python.smb.info")
#		i.con = self
#		i.direction = 'in'
#		i.data = p.summary()
#		i.report()

        if self.state['stop']:
            smblog.info("faint death.")
            return len(data)

        if r:
            smblog.debug("response: %s" % r.summary())
            r.show()

#			i = incident("dionaea.module.python.smb.info")
#			i.con = self
#			i.direction = 'out'
#			i.data = r.summary()
#			i.report()

#			r.build()
            #r.show2()
            self.send(r.build())
        else:
            smblog.error('process() returned None.')

        if p.haslayer(Raw):
            smblog.warning("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()
            # some rest seems to be not parsed correctly
            # could be start of some other packet, junk, or failed packet dissection
            # TODO: recover from this...
            return len(data) - len(p.getlayer(Raw).load)

        return len(data)

    def process(self, p):
        r = ''
        rp = None
#		self.state['readcount'] = 0
        # if self.state == STATE_START and p.getlayer(SMB_Header).Command ==
        # 0x72:
        rstatus = 0
        smbh = p.getlayer(SMB_Header)
        Command = smbh.Command
        if Command == SMB_COM_NEGOTIATE:
            # Negociate Protocol -> Send response that supports minimal features in NT LM 0.12 dialect
            # (could be randomized later to avoid detection - but we need more dialects/options support)
            r = SMB_Negociate_Protocol_Response(
                OemDomainName=self.config.oem_domain_name + "\0",
                ServerName=self.config.server_name + "\0"
            )
            # we have to select dialect
            c = 0
            tmp = p.getlayer(SMB_Negociate_Protocol_Request_Counts)
            while c < len(tmp.Requests):
                request = tmp.Requests[c]
                if request.BufferData.decode('ascii').find('NT LM 0.12') != -1:
                    break
                c += 1

            r.DialectIndex = c

#			r.Capabilities = r.Capabilities & ~CAP_EXTENDED_SECURITY
            if not p.Flags2 & SMB_FLAGS2_EXT_SEC:
                r.Capabilities = r.Capabilities & ~CAP_EXTENDED_SECURITY

        # elif self.state == STATE_SESSIONSETUP and
        # p.getlayer(SMB_Header).Command == 0x73:
        elif Command == SMB_COM_SESSION_SETUP_ANDX:
            if p.haslayer(SMB_Sessionsetup_ESEC_AndX_Request):
                r = SMB_Sessionsetup_ESEC_AndX_Response(
                    NativeOS=self.config.native_os + "\0",
                    NativeLanManager=self.config.native_lan_manager + "\0",
                    PrimaryDomain=self.config.primary_domain
                )
                ntlmssp = None
                sb = p.getlayer(
                    SMB_Sessionsetup_ESEC_AndX_Request).SecurityBlob

                if sb.startswith(b"NTLMSSP"):
                    # GSS-SPNEGO without OID
                    ntlmssp = NTLMSSP_Header(sb)
                    ntlmssp.show()
                    # FIXME what is a proper reply?
                    # currently there windows calls Sessionsetup_AndX2_request
                    # after this one with bad reply
                    if ntlmssp.MessageType == 1:
                        r.Action = 0
                        ntlmnegotiate = ntlmssp.getlayer(NTLM_Negotiate)
                        rntlmssp = NTLMSSP_Header(MessageType=2)
                        rntlmchallenge = NTLM_Challenge(
                            NegotiateFlags=ntlmnegotiate.NegotiateFlags)
#						if ntlmnegotiate.NegotiateFlags & NTLMSSP_REQUEST_TARGET:
#							rntlmchallenge.TargetNameFields.Offset = 0x38
#							rntlmchallenge.TargetNameFields.Len = 0x1E
#							rntlmchallenge.TargetNameFields.MaxLen = 0x1E

                        rntlmchallenge.ServerChallenge = b"\xa4\xdf\xe8\x0b\xf5\xc6\x1e\x3a"
                        rntlmssp = rntlmssp / rntlmchallenge
                        rntlmssp.show()
                        raw = rntlmssp.build()
                        r.SecurityBlob = raw
                        rstatus = 0xc0000016 # STATUS_MORE_PROCESSING_REQUIRED
                elif sb.startswith(b"\x04\x04") or sb.startswith(b"\x05\x04"):
                    # GSSKRB5 CFX wrapping
                    # FIXME is this relevant at all?
                    pass
                else:
                    # (hopefully) the SecurityBlob is prefixed with
                    # * BER encoded identifier
                    # * BER encoded length of the data
                    cls,pc,tag,sb = BER_identifier_dec(sb)
                    l,sb = BER_len_dec(sb)
                    if cls == BER_CLASS_APP and pc > 0 and tag == 0:
                        # NTLM NEGOTIATE
                        #
                        # reply NTML CHALLENGE
                        # SMB_Header.Status = STATUS_MORE_PROCESSING_REQUIRED
                        # SMB_Sessionsetup_ESEC_AndX_Response.SecurityBlob is
                        # \xa1 BER_length NegTokenTarg where
                        # NegTokenTarg.responseToken is NTLM_Header / NTLM_Challenge
                        gssapi = GSSAPI(sb)
                        sb = gssapi.getlayer(Raw).load
                        cls,pc,tag,sb = BER_identifier_dec(sb)
                        l,sb = BER_len_dec(sb)
                        spnego = SPNEGO(sb)
                        spnego.show()
                        sb = spnego.NegotiationToken.mechToken.__str__()
                        try:
                            cls,pc,tag,sb = BER_identifier_dec(sb)
                        except BER_Exception as e:
                            smblog.warning("BER Exception", exc_info=True)
                            return rp
                        l,sb = BER_len_dec(sb)
                        ntlmssp = NTLMSSP_Header(sb)
                        ntlmssp.show()
                        if ntlmssp.MessageType == 1:
                            r.Action = 0
                            ntlmnegotiate = ntlmssp.getlayer(NTLM_Negotiate)
                            rntlmssp = NTLMSSP_Header(MessageType=2)
                            rntlmchallenge = NTLM_Challenge(
                                NegotiateFlags=ntlmnegotiate.NegotiateFlags)
                            rntlmchallenge.TargetInfoFields.Offset = rntlmchallenge.TargetNameFields.Offset = 0x30
#							if ntlmnegotiate.NegotiateFlags & NTLMSSP_REQUEST_TARGET:
#								rntlmchallenge.TargetNameFields.Offset = 0x38
#								rntlmchallenge.TargetNameFields.Len = 0x1E
#								rntlmchallenge.TargetNameFields.MaxLen = 0x1E
                            rntlmchallenge.ServerChallenge = b"\xa4\xdf\xe8\x0b\xf5\xc6\x1e\x3a"
                            rntlmssp = rntlmssp / rntlmchallenge
                            rntlmssp.show()
                            negtokentarg = NegTokenTarg(
                                negResult=1,supportedMech='1.3.6.1.4.1.311.2.2.10')
                            negtokentarg.responseToken = rntlmssp.build()
                            negtokentarg.mechListMIC = None
                            raw = negtokentarg.build()
                            #r.SecurityBlob = b'\xa1' + BER_len_enc(len(raw)) + raw
                            r.SecurityBlob = BER_identifier_enc(
                                BER_CLASS_CON,1,1) + BER_len_enc(len(raw)) + raw
                            # STATUS_MORE_PROCESSING_REQUIRED
                            rstatus = 0xc0000016
                    elif cls == BER_CLASS_CON and pc == 1 and tag == 1:
                        # NTLM AUTHENTICATE
                        #
                        # reply
                        # \xa1 BER_length NegTokenTarg('accepted')
                        negtokentarg = NegTokenTarg(sb)
                        negtokentarg.show()
                        ntlmssp = NTLMSSP_Header(
                            negtokentarg.responseToken.val)
                        ntlmssp.show()
                        rnegtokentarg = NegTokenTarg(
                            negResult=0, supportedMech=None)
                        raw = rnegtokentarg.build()
                        #r.SecurityBlob = b'\xa1' + BER_len_enc(len(raw)) + raw
                        r.SecurityBlob = BER_identifier_enc(
                            BER_CLASS_CON,1,1) + BER_len_enc(len(raw)) + raw
            elif p.haslayer(SMB_Sessionsetup_AndX_Request2):
                r = SMB_Sessionsetup_AndX_Response2(
                    NativeOS=self.config.native_os + "\0",
                    NativeLanManager=self.config.native_lan_manager + "\0",
                    PrimaryDomain=self.config.primary_domain + "\0"
                )
            else:
                smblog.warning("Unknown Session Setup Type used")

        elif Command == SMB_COM_TREE_CONNECT_ANDX:
            r = SMB_Treeconnect_AndX_Response()
            h = p.getlayer(SMB_Treeconnect_AndX_Request)
#			print ("Service : %s" % h.Path)

            # for SMB_Treeconnect_AndX_Request.Flags = 0x0008
            if h.Flags & 0x08:
                r = SMB_Treeconnect_AndX_Response_Extended()

            # get Path as ascii string
            f,v = h.getfield_and_val('Path')
            Service = f.i2repr(h,v)

            # compile Service from the last part of path
            # remove \\
            if Service.startswith('\\\\'):
                Service = Service[1:]
            Service = Service.split('\\')[-1]
            if Service[-1] == '\x00':
                Service = Service[:-1]
            if Service[-1] == '$':
                Service = Service[:-1]
            r.Service = Service + '\x00'

            # specific for NMAP smb-enum-shares.nse support
            if h.Path == b'nmap-share-test\0':
                r = SMB_Treeconnect_AndX_Response2(
                    NativeOS=self.config.native_os + "\0",
                    NativeLanManager=self.config.native_lan_manager + "\0",
                    PrimaryDomain=self.config.primary_domain + "\0"
                )
                rstatus = 0xc00000cc #STATUS_BAD_NETWORK_NAME
            elif h.Path == b'ADMIN$\0' or h.Path == b'C$\0':
                r = SMB_Treeconnect_AndX_Response2(
                    NativeOS=self.config.native_os + "\0",
                    NativeLanManager=self.config.native_lan_manager + "\0",
                    PrimaryDomain=self.config.primary_domain + "\0"
                )
                rstatus = 0xc0000022 #STATUS_ACCESS_DENIED
            # support for CVE-2017-7494 Samba SMB RCE
            elif h.Path[-6:] == b'share\0':
                smblog.info('Possible CVE-2017-7494 Samba SMB RCE attempts..')
                r.AndXOffset = 0
                r.Service = "A:\0"
                r.NativeFileSystem = "NTFS\0"
        elif Command == SMB_COM_TREE_DISCONNECT:
            r = SMB_Treedisconnect()
        elif Command == SMB_COM_CLOSE:
            r = p.getlayer(SMB_Close)
            if p.FID in self.fids and self.fids[p.FID] is not None:
                self.fids[p.FID].close()
                fileobj = self.fids[p.FID]
                icd = incident("dionaea.download.complete")
                icd.path = fileobj.name
                icd.url = "smb://" + self.remote.host
                icd.con = self
                icd.report()
                os.unlink(self.fids[p.FID].name)
                del self.fids[p.FID]
                r = SMB_Close_Response()
        elif Command == SMB_COM_LOGOFF_ANDX:
            r = SMB_Logoff_AndX()
        elif Command == SMB_COM_NT_CREATE_ANDX:
            # FIXME return NT_STATUS_OBJECT_NAME_NOT_FOUND=0xc0000034
            # for writes on IPC$
            # this is used to distinguish between file shares and devices by nmap smb-enum-shares
            # requires mapping of TreeConnect ids to names/objects
            r = SMB_NTcreate_AndX_Response()
            h = p.getlayer(SMB_NTcreate_AndX_Request)
            r.FID = 0x4000
            while r.FID in self.fids:
                r.FID += 0x200
            if h.FileAttributes & (SMB_FA_HIDDEN|SMB_FA_SYSTEM|SMB_FA_ARCHIVE|SMB_FA_NORMAL):
                # if a normal file is requested, provide a file

                dionaea_config = g_dionaea.config().get("dionaea")
                download_dir = dionaea_config.get("download.dir")
                download_suffix = dionaea_config.get("download.suffix", ".tmp")
                self.fids[r.FID] = tempfile.NamedTemporaryFile(
                    delete=False,
                    prefix="smb-",
                    suffix=download_suffix,
                    dir=download_dir
                )

                # get pretty filename
                f,v = h.getfield_and_val('Filename')
                filename = f.i2repr(h,v)
                for j in range(len(filename)):
                    if filename[j] != '\\' and filename[j] != '/':
                        break
                filename = filename[j:]

                i = incident("dionaea.download.offer")
                i.con = self
                i.url = "smb://%s/%s" % (self.remote.host, filename)
                i.report()
                smblog.info("OPEN FILE! %s" % filename)

            elif h.FileAttributes & SMB_FA_DIRECTORY:
                pass
            else:
                self.fids[r.FID] = None
        elif Command == SMB_COM_OPEN_ANDX:
            h = p.getlayer(SMB_Open_AndX_Request)
            r = SMB_Open_AndX_Response()
            r.FID = 0x4000
            while r.FID in self.fids:
                r.FID += 0x200

            dionaea_config = g_dionaea.config().get("dionaea")
            download_dir = dionaea_config.get("download.dir")
            download_suffix = dionaea_config.get("download.suffix", ".tmp")

            self.fids[r.FID] = tempfile.NamedTemporaryFile(
                delete=False,
                prefix="smb-",
                suffix=download_suffix,
                dir=download_dir
            )

            # get pretty filename
            f,v = h.getfield_and_val('FileName')
            filename = f.i2repr(h,v)
            for j in range(len(filename)):
                if filename[j] != '\\' and filename[j] != '/':
                    break
            filename = filename[j:]

            i = incident("dionaea.download.offer")
            i.con = self
            i.url = "smb://%s/%s" % (self.remote.host, filename)
            i.report()
            smblog.info("OPEN FILE! %s" % filename)

        elif Command == SMB_COM_ECHO:
            r = p.getlayer(SMB_Header).payload
        elif Command == SMB_COM_WRITE_ANDX:
            r = SMB_Write_AndX_Response()
            h = p.getlayer(SMB_Write_AndX_Request)
            r.CountLow = h.DataLenLow
            if h.FID in self.fids and self.fids[h.FID] is not None:
                smblog.warning("WRITE FILE!")
                self.fids[h.FID].write(h.Data)
            else:
                self.buf += h.Data
#				self.process_dcerpc_packet(p.getlayer(SMB_Write_AndX_Request).Data)
                if len(self.buf) >= 10:
                    # we got the dcerpc header
                    inpacket = DCERPC_Header(self.buf[:10])
                    smblog.debug("got header")
                    inpacket = DCERPC_Header(self.buf)
                    smblog.debug("FragLen %i len(self.buf) %i" %
                                 (inpacket.FragLen, len(self.buf)))
                    if inpacket.FragLen == len(self.buf):
                        outpacket = self.process_dcerpc_packet(self.buf)
                        if outpacket is not None:
                            outpacket.show()
                            self.outbuf = outpacket.build()
                        self.buf = b''
        elif Command == SMB_COM_WRITE:
            h = p.getlayer(SMB_Write_Request)
            if h.FID in self.fids and self.fids[h.FID] is not None:
                smblog.warning("WRITE FILE!")
                self.fids[h.FID].write(h.Data)
            r = SMB_Write_Response(CountOfBytesWritten = h.CountOfBytesToWrite)
        elif Command == SMB_COM_READ_ANDX:
            r = SMB_Read_AndX_Response()
            h = p.getlayer(SMB_Read_AndX_Request)
            # self.outbuf should contain response buffer now
            if not self.outbuf:
                if self.state['stop']:
                    smblog.debug('drop dead!')
                else:
                    smblog.error('dcerpc processing failed. bailing out.')
                return rp

            rdata = SMB_Data()
            outbuf = self.outbuf
            outbuflen = len(outbuf)
            smblog.debug("MaxCountLow %i len(outbuf) %i readcount %i" %(
                h.MaxCountLow, outbuflen, self.state['readcount']) )
            if h.MaxCountLow < outbuflen-self.state['readcount']:
                rdata.ByteCount = h.MaxCountLow
                newreadcount = self.state['readcount']+h.MaxCountLow
            else:
                newreadcount = 0
                self.outbuf = None

            rdata.Bytes = outbuf[
                self.state['readcount'] : self.state['readcount'] + h.MaxCountLow ]
            rdata.ByteCount = len(rdata.Bytes)+1
            r.DataLenLow = len(rdata.Bytes)
            smblog.debug("readcount %i len(rdata.Bytes) %i" %
                         (self.state['readcount'], len(rdata.Bytes)) )
            r /= rdata

            self.state['readcount'] = newreadcount

        elif Command == SMB_COM_TRANSACTION:
            h = p.getlayer(SMB_Trans_Request)
            r = SMB_Trans_Response()
            rdata = SMB_Data()

            TransactionName = h.TransactionName
            if type(TransactionName) == bytes:
                if smbh.Flags2 & SMB_FLAGS2_UNICODE:
                    TransactionName = TransactionName.decode('utf-16')
                else:
                    TransactionName = TransactionName.decode('ascii')

            if TransactionName[-1] == '\0':
                TransactionName = TransactionName[:-1]

#			print("'{}' == '{}' => {} {} {}".format(TransactionName, '\\PIPE\\',
#				TransactionName == '\\PIPE\\', type(TransactionName) == type('\\PIPE\\'),
#				len(TransactionName)) )


            if TransactionName == '\\PIPE\\LANMAN':
                # [MS-RAP].pdf - Remote Administration Protocol
                rapbuf = bytes(h.Param)
                rap = RAP_Request(rapbuf)
                rap.show()
                rout = RAP_Response()
                coff = 0
                if rap.Opcode == RAP_OP_NETSHAREENUM:
                    (InfoLevel,ReceiveBufferSize) = struct.unpack(
                        "<HH",rap.Params)
                    print("InfoLevel {} ReceiveBufferSize {}".format(
                        InfoLevel, ReceiveBufferSize) )
                    if InfoLevel == 1:
                        l = len(__shares__)
                        rout.OutParams = struct.pack("<HH", l, l)
                    rout.OutData = b""
                    comments = []
                    for i in __shares__:
                        rout.OutData += struct.pack("<13sxHHH",
                                                    i, # NetworkName
                                                    # Pad
                                                    # Type
                                                    __shares__[i][
                                                        'type'] & 0xff,
                                                    # RemarkOffsetLow
                                                    coff + len(__shares__)*20,
                                                    0x0101) # RemarkOffsetHigh
                        comments.append(__shares__[i]['comment'])
                        coff += len(__shares__[i]['comment']) + 1
                    rout.show()
                outpacket = rout
                self.outbuf = outpacket.build()
                dceplen = len(self.outbuf) + coff

                r.TotalParamCount = 8 # Status|Convert|Count|Available
                r.TotalDataCount = dceplen

                r.ParamCount = 8 # Status|Convert|Count|Available
                r.ParamOffset = 56

                r.DataCount = dceplen
                r.DataOffset = 64

                rdata.ByteCount = dceplen
                rdata.Bytes = self.outbuf + \
                    b''.join(c.encode('ascii') + b'\x00' for c in comments)


            elif TransactionName == '\\PIPE\\':
                if socket.htons(h.Setup[0]) == TRANS_NMPIPE_TRANSACT:
                    outpacket = self.process_dcerpc_packet(
                        p.getlayer(DCERPC_Header))

                    if not outpacket:
                        if self.state['stop']:
                            smblog.debug('drop dead!')
                        else:
                            smblog.error('dcerpc processing failed. bailing out.')
                        return rp
                    self.outbuf = outpacket.build()
                    dceplen = len(self.outbuf)

                    r.TotalDataCount = dceplen
                    r.DataCount = dceplen

                    rdata.ByteCount = dceplen
                    rdata.Bytes = self.outbuf

                if socket.htons(h.Setup[0]) == TRANS_NMPIPE_PEEK:
                    SetupCount = h.SetupCount
                    if SetupCount > 0:
                        smblog.info('MS17-010 - SMB RCE exploit scanning..')
                        r = SMB_Trans_Response_Simple()
                        # returned #STATUS_INSUFF_SERVER_RESOURCE as we not being patched
                        rstatus = 0xc0000205  # STATUS_INSUFF_SERVER_RESOURCES

            r /= rdata
        elif Command == SMB_COM_TRANSACTION2:
            h = p.getlayer(SMB_Trans2_Request)
            if h.Setup[0] == SMB_TRANS2_SESSION_SETUP:
                smblog.info('Possible DoublePulsar connection attempts..')
                # determine DoublePulsar opcode and command
                # https://zerosum0x0.blogspot.sg/2017/04/doublepulsar-initial-smb-backdoor-ring.html
                # The opcode list is as follows:
                # 0x23 = ping
                # 0xc8 = exec
                # 0x77 = kil
                op = calculate_doublepulsar_opcode(h.Timeout)
                op2 = hex(op)[-2:]
                oplist = [('23','ping'), ('c8','exec'), ('77','kill')]
                for fid,command in oplist:
                    if op2 == fid:
                        smblog.info("DoublePulsar request opcode: %s command: %s" % (op2, command))
                if op2 != '23' and op2 != 'c8' and op2 != '77':
                    smblog.info("unknown opcode: %s" % op2)

                # make sure the payload size not larger than 10MB
                if len(self.buf2) > 10485760:
                    self.buf2 = ''
                elif len(self.buf2) == 0 and h.DataCount == 4096:
                    self.buf2 = self.buf2 + h.Data
                elif len(self.buf2) != 0 and h.DataCount == 4096:
                    self.buf2 = self.buf2 + h.Data
                elif len(self.buf2) != 0 and h.DataCount < 4096:
                    smblog.info('DoublePulsar payload receiving..')
                    self.buf2 = self.buf2 + h.Data
                    key = bytearray([0x52, 0x73, 0x36, 0x5E])
                    xor_output = xor(self.buf2, key)
                    hash_buf2 = hashlib.md5(self.buf2);
                    smblog.info('DoublePulsar payload - MD5 (before XOR decryption): %s' % (hash_buf2.hexdigest()))
                    hash_xor_output = hashlib.md5(xor_output);
                    smblog.info('DoublePulsar payload - MD5 (after XOR decryption ): %s' % (hash_xor_output.hexdigest()))

                    # payload = some data(shellcode or code to load the executable) + executable itself
                    # try to locate the executable and remove the prepended data
                    # now, we will have the executable itself
                    offset = 0
                    for i, c in enumerate(xor_output):
                        if ((xor_output[i] == 0x4d and xor_output[i + 1] == 0x5a) and xor_output[i + 2] == 0x90):
                            offset = i
                            smblog.info('DoublePulsar payload - MZ header found...')
                            break

                    # save the captured payload/gift/evil/buddy to disk
                    smblog.info('DoublePulsar payload - Save to disk')

                    dionaea_config = g_dionaea.config().get("dionaea")
                    download_dir = dionaea_config.get("download.dir")
                    download_suffix = dionaea_config.get("download.suffix", ".tmp")

                    fp = tempfile.NamedTemporaryFile(
                        delete=False,
                        prefix="smb-",
                        suffix=download_suffix,
                        dir=download_dir
                    )
                    fp.write(xor_output[offset:])
                    fp.close()
                    self.buf2 = b''
                    xor_output = b''

                    icd = incident("dionaea.download.complete")
                    icd.path = fp.name
                    # We need the url for logging
                    icd.url = ""
                    icd.con = self
                    icd.report()
                    os.unlink(fp.name)

                r = SMB_Trans2_Response()
                rstatus = 0xc0000002  # STATUS_NOT_IMPLEMENTED
            elif h.Setup[0] == SMB_TRANS2_FIND_FIRST2:
                r = SMB_Trans2_FIND_FIRST2_Response()
            else:
                r = SMB_Trans2_Response()

        elif Command == SMB_COM_DELETE:
            h = p.getlayer(SMB_Delete_Request)
            r = SMB_Delete_Response()
        elif Command == SMB_COM_TRANSACTION2_SECONDARY:
            h = p.getlayer(SMB_Trans2_Secondary_Request)
            # TODO: need some extra works
            pass
        elif Command == SMB_COM_NT_TRANSACT:
            h = p.getlayer(SMB_NT_Trans_Request)
            r = SMB_NT_Trans_Response()
            rstatus = 0x00000000  # STATUS_SUCCESS
        else:
            smblog.error('...unknown SMB Command. bailing out.')
            p.show()

        if r:
            smbh = SMB_Header(Status=rstatus)
            smbh.Command = r.smb_cmd
            smbh.Flags2 = p.getlayer(SMB_Header).Flags2
#			smbh.Flags2 = p.getlayer(SMB_Header).Flags2 & ~SMB_FLAGS2_EXT_SEC
            smbh.MID = p.getlayer(SMB_Header).MID
            smbh.PID = p.getlayer(SMB_Header).PID
            # Deception for DoublePulsar, we fix the XOR key first as 0x5273365E
            # WannaCry will use the XOR key to encrypt and deliver next payload, so we can decode easily later
            if Command == SMB_COM_TRANSACTION2:
                h = p.getlayer(SMB_Trans2_Request)
                if h.Setup[0] == SMB_TRANS2_SESSION_SETUP:
                    smbh.MID = p.getlayer(SMB_Header).MID + 16
                    smbh.Signature = 0x000000009cf9c567
            rp = NBTSession()/smbh/r

        if Command in SMB_Commands:
            self.state['lastcmd'] = SMB_Commands[
                p.getlayer(SMB_Header).Command]
        else:
            self.state['lastcmd'] = "UNKNOWN"
        return rp

    def process_dcerpc_packet(self, buf):
        if not isinstance(buf, DCERPC_Header):
            smblog.debug("got buf, make DCERPC_Header")
            dcep = DCERPC_Header(buf)
        else:
            dcep = buf

        outbuf = None

        smblog.debug("data")
        try:
            dcep.show()
        except:
            return None
        if dcep.AuthLen > 0:
            #			print(dcep.getlayer(Raw).underlayer.load)
            #			dcep.getlayer(Raw).underlayer.decode_payload_as(DCERPC_Auth_Verfier)
            dcep.show()

        if dcep.PacketType == 11: #bind
            outbuf = DCERPC_Header()/DCERPC_Bind_Ack()
            outbuf.CallID = dcep.CallID
            c = 0
            outbuf.CtxItems = [DCERPC_Ack_CtxItem()
                               for i in range(len(dcep.CtxItems))]
            while c < len(dcep.CtxItems): #isinstance(tmp, DCERPC_CtxItem):
                tmp = dcep.CtxItems[c]
                ctxitem = outbuf.CtxItems[c]
                service_uuid = UUID(bytes_le=tmp.UUID)
                transfersyntax_uuid = UUID(bytes_le=tmp.TransferSyntax)
                ctxitem.TransferSyntax = tmp.TransferSyntax #[:16]
                ctxitem.TransferSyntaxVersion = tmp.TransferSyntaxVersion
                if str(transfersyntax_uuid) == '8a885d04-1ceb-11c9-9fe8-08002b104860':
                    if service_uuid.hex in registered_services:
                        service = registered_services[service_uuid.hex]
                        smblog.info("Found a registered UUID (%s). Accepting Bind for %s" %
                                    (service_uuid , service.__class__.__name__))
                        self.state['uuid'] = service_uuid.hex
                        # Copy Transfer Syntax to CtxItem
                        ctxitem.AckResult = 0
                        ctxitem.AckReason = 0
                    else:
                        smblog.warning(
                            "Attempt to register %s failed, UUID does not exist or is not implemented",
                            service_uuid
                        )
                else:
                    smblog.warning(
                        "Attempt to register %s failed, TransferSyntax %s is unknown",
                        service_uuid,
                        transfersyntax_uuid
                    )
                i = incident("dionaea.modules.python.smb.dcerpc.bind")
                i.con = self
                i.uuid = str(service_uuid)
                i.transfersyntax = str(transfersyntax_uuid)
                i.report()
                c += 1
            outbuf.NumCtxItems = c
            outbuf.FragLen = len(outbuf.build())
            smblog.debug("dce reply")
            outbuf.show()
        elif dcep.PacketType == 0: #request
            resp = None
            if 'uuid' in self.state:
                service = registered_services[self.state['uuid']]
                resp = service.processrequest(service, self, dcep.OpNum, dcep)
                i = incident("dionaea.modules.python.smb.dcerpc.request")
                i.con = self
                i.uuid = str(UUID(bytes=bytes.fromhex(self.state['uuid'])))
                i.opnum = dcep.OpNum
                i.report()
            else:
                smblog.info("DCERPC Request without pending action")
            if not resp:
                self.state['stop'] = True
            outbuf = resp
        else:
            # unknown DCERPC packet -> logcrit and bail out.
            smblog.error('unknown DCERPC packet. bailing out.')
        return outbuf

    def handle_timeout_idle(self):
        return False

    def handle_disconnect(self):
        for i in self.fids:
            if self.fids[i] is not None:
                self.fids[i].close()
                os.unlink(self.fids[i].name)
                del self.fids[i]
        return 0

class epmapper(smbd):
    def __init__ (self):
        connection.__init__(self,"tcp")
        smbd.__init__(self)

    def handle_io_in(self,data):
        try:
            p = DCERPC_Header(data)
        except:
            t = traceback.format_exc()
            smblog.error(t)
            return len(data)

        if len(data) < p.FragLen:
            smblog.warning("epmapper - not enough data")
            return 0

        smblog.debug("packet: %s" % p.summary())

        r = self.process_dcerpc_packet(p)

        if self.state['stop']:
            smblog.info("faint death.")
            return len(data)

        if not r or r is None:
            smblog.error('dcerpc processing failed. bailing out.')
            return len(data)

        smblog.debug("response: %s" % r.summary())
        r.show()
        self.send(r.build())

        if p.haslayer(Raw):
            smblog.warning("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()

        return len(data)


from . import rpcservices
import inspect
services = inspect.getmembers(rpcservices, inspect.isclass)
for name, servicecls in services:
    if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
        register_rpc_service(servicecls())
