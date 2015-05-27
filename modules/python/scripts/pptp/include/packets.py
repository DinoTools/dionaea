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

from dionaea.smb.include.packet import *
from dionaea.smb.include.fieldtypes import *

#PPTP Control Message Types
PPTP_CTRMSG_TYPE_STARTCTRCON_REQUEST = 0x01
PPTP_CTRMSG_TYPE_STARTCTRCON_REPLY   = 0x02
PPTP_CTRMSG_TYPE_OUTGOINGCALL_REQUEST = 0x07
PPTP_CTRMSG_TYPE_OUTGOINGCALL_REPLY = 0x08

#PPP Link Control Protocol Types
PPP_LCP_Configuration_Request = 0x01

# https://www.ietf.org/rfc/rfc2637.txt
class PPTP_StartControlConnection_Request(Packet):
	name="PPTP Start-Control-Connection-Request"
	controlmessage_type = PPTP_CTRMSG_TYPE_STARTCTRCON_REQUEST
	fields_desc =[
		XShortField("Length",0),
		XShortField("MessageType",0),
		XIntField("MagicCookie",0),
		XShortField("ControlMessageType",0),
		XShortField("Reserved",0),
		XShortField("ProtocolVersion",0),
		XShortField("Reserved",0),
		
		XIntField("FramingCapabilites",0),
		XIntField("BearerCapabilites",0),
		XShortField("MaxChannels",0),
		XShortField("FirmwareRevision",0),
		StrFixedLenField("HostName", "", 64),
		StrFixedLenField("VendorName", "", 64),
	]

class PPTP_StartControlConnection_Reply(Packet):
	name="PPTP Start-Control-Connection-Reply"
	controlmessage_type = PPTP_CTRMSG_TYPE_STARTCTRCON_REPLY
	fields_desc =[
		XShortField("Length",0x9c),
		XShortField("MessageType",0x01),
		XIntField("MagicCookie",0x1a2b3c4d),
		XShortField("ControlMessageType",0x02),
		XShortField("Reserved",0),
		LEShortField("ProtocolVersion",0x01),
		ByteField("ResultCode",0x01),
		ByteField("ErrorCode",0x00),
		LEIntField("FramingCapabilites",0),
		LEIntField("BearerCapabilites",0),
		XShortField("MaxChannels",1),
		XShortField("FirmwareRevision",1),
		StrFixedLenField("HostName", "", 64),
		StrFixedLenField("VendorName", "", 64),
	]

class PPTP_OutgoingCall_Request(Packet):
	name="PPTP Outgoing-Call-Request"
	controlmessage_type = PPTP_CTRMSG_TYPE_OUTGOINGCALL_REQUEST
	fields_desc =[
		XShortField("Length",0),
		XShortField("MessageType",0),
		XIntField("MagicCookie",0),
		XShortField("ControlMessageType",0),
		XShortField("Reserved",0),
		XShortField("CallID",0),
		XShortField("CallSerialNumber",0),
		XIntField("MinBPS",0),
		XIntField("MaxBPS",0),
		XIntField("BearerType",0),
		XIntField("FramingType",0),
		XShortField("PacketWindowSize",0),
		XShortField("PacketProcessingDelay",0),
		XShortField("PacketNumberLength",0),
		XShortField("Reserved",0),
		StrFixedLenField("PhoneNumber", "", 64),
		StrFixedLenField("Subaddress", "", 64),
	]

class PPTP_OutgoingCall_Reply(Packet):
	name="PPTP Outgoing-Call-Reply"
	controlmessage_type = PPTP_CTRMSG_TYPE_OUTGOINGCALL_REPLY
	fields_desc =[
		XShortField("Length",0x20),
		XShortField("MessageType",0x01),
		XIntField("MagicCookie",0x1a2b3c4d),
		XShortField("ControlMessageType",0x08),
		XShortField("Reserved",0),
		XShortField("CallID",0x480),
		XShortField("PeerCallID",0),
		ByteField("ResultCode",0x01),
		ByteField("ErrorCode",0x00),
		XShortField("CauseCode",0),
		XIntField("ConnectSpeed",0x05F5E100),
		XShortField("PacketWindowSize",0x2000),
		XShortField("PacketProcessingDelay",0),
		XShortField("PacketNumberLength",0),
		XShortField("PhysicalChannelID",0),
	]

class PPTP(Packet):
	name="PPTP"
	fields_desc =[
		ByteField("Address",0),
		ByteField("Control",0),
		XShortField("Protocol",0),
	]

class PPP_LCP_Configuration_Request(Packet):
	name="PPP LCP_Configuration_Request"
	controlmessage_type = PPP_LCP_Configuration_Request
	fields_desc =[
		ByteField("Code",0),
		ByteField("Identifier",0),
		XShortField("Length",0),
		StrFixedLenField("Options", b"", length_from=lambda pkt: pkt.Length-4),
	]

