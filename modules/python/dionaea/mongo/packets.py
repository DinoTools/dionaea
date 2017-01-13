#                               Dionaea
#                           - catches bugs -
#
# Copyright (C) 2017 PhiBo (DinoTools)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


from dionaea.smb.include.packet import Packet, bind_bottom_up
from dionaea.smb.include.fieldtypes import ByteField, StrNullField, LEIntField, PacketLenField, LELongField


class MsgHeader(Packet):
    name="Wire Protocol Message Header"
    fields_desc = [
        LEIntField("messageLength", 0),
        LEIntField("requestID", 0),
        LEIntField("responseTo", 0),
        LEIntField("opCode", 0)
    ]

    def post_build(self, p, pay):
        self.messageLength = len(pay) + 16
        p = self.do_build()
        return p + pay


class MsgQuery(Packet):
    name = "Wire Protocol OP_QUERY"
    fields_desc = [
        LEIntField("flags", 0),
        StrNullField("fullCollectionName", ""),
        LEIntField("numberToSkip", 0),
        LEIntField("numberToReturn", 0)
    ]


class MsgReply(Packet):
    name = " Wire Protocol OP_REPLY"
    fields_desc = [
        LEIntField("responseFlags", 0),
        LELongField("cursorID", 0),
        LEIntField("startingFrom", 0),
        LEIntField("numberReturned", 0)
    ]
