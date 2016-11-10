#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2015  Tan Kean Siong
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

import logging

from dionaea.core import connection, incident
from dionaea.pptp.include import packets

logger = logging.getLogger('pptp')


class pptpd(connection):
    shared_config_values = ["firmware_revision", "hostname", "vendor_name"]
    IDLE, ESTABLISHED = range(2)

    def __init__(self):
        connection.__init__(self, "tcp")
        self.buf = b''
        self.pending_packet_type = None
        self.state = self.IDLE
        self.firmware_revision = 1
        self.hostname = ""
        self.vendor_name = ""

    def _handle_controll_message(self, message_type, data):
        if self.state == self.ESTABLISHED:
            if message_type == packets.PPTP_CTRMSG_TYPE_OUTGOINGCALL_REQUEST:
                p = packets.PPTP_OutgoingCall_Request(data)
                p.show()
                r = packets.PPTP_OutgoingCall_Reply()
                r.show()
                self.send(r.build())
                return len(data)
            elif message_type == packets.CTRMSG_TYPE_CALLCLEAR_REQUEST:
                p = packets.PPTP_CallClear_Request(data)
                p.show()
                r = packets.CallDisconnectNotify()
                r.ResultCode = 4
                r.show()
                self.state = self.IDLE
                self.send(r.build())
                return len(data)
            else:
                logger.warning("Unexpected control message type %d", message_type)
        return len(data)

    def apply_config(self, config):
        if config is None:
            logger.warning("No config provided. Using default values")
            return
        self.firmware_revision = config.get("firmware_revision", self.firmware_revision)
        self.hostname = config.get("hostname", self.hostname)
        self.vendor_name = config.get("vendor_name", self.vendor_name)

    def handle_established(self):
        self.timeouts.idle = 120
        self.processors()

    def handle_io_in(self, data):
        if self.state == self.IDLE:
            p = packets.PPTP_StartControlConnection_Request(data)
            p.show()
            if p.Length == 0:
                logger.warn("Bad PPTP Packet, Length = 0")
                return len(data)

            i = incident("dionaea.modules.python.pptp.connect")
            i.con = self
            logger.debug("pptp remote hostname: %s", p.HostName)
            i.firmware_revision = p.FirmwareRevision
            i.max_channels = p.MaxChannels
            i.protocol_version = p.ProtocolVersion
            i.remote_hostname = p.HostName
            i.vendor_name = p.VendorName
            i.report()
            self.state = self.ESTABLISHED
            r = packets.PPTP_StartControlConnection_Reply()
            r.FirmwareRevision = self.firmware_revision
            r.HostName = self.hostname
            r.VendorName = self.vendor_name
            r.show()
            self.send(r.build())
            return len(data)
        elif self.state == self.ESTABLISHED:
            p = packets.BaseControllMessage(data)
            if p.MessageType == 0x01:
                return self._handle_controll_message(p.ControlMessageType, data)

            logger.warning("Wrong message type %d", p.MessageType)
            return len(data)

        return len(data)

    def handle_timeout_idle(self):
        return False

    def handle_disconnect(self):
        return False
