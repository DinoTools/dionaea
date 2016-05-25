#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2010  Markus Koetter
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

from .packet import *
from .fieldtypes import *


# [MS-NLMP].pdf
#
# 2.2.2.5 NEGOTIATE

NTLMSSP_NEGOTIATE_UNICODE					= 0x00000001 # A
NTLMSSP_NEGOTIATE_OEM						= 0x00000002 # B
NTLMSSP_REQUEST_TARGET						= 0x00000004 # C
NTLMSSP_UNUSED_00000008						= 0x00000008 # r10
NTLMSSP_NEGOTIATE_SIGN						= 0x00000010 # D
NTLMSSP_NEGOTIATE_SEAL						= 0x00000020 # E
NTLMSSP_NEGOTIATE_DATAGRAM					= 0x00000040 # F
NTLMSSP_NEGOTIATE_LM_KEY					= 0x00000080 # G
NTLMSSP_UNUSED_00000100						= 0x00000100 # r9
NTLMSSP_NEGOTIATE_NTLM						= 0x00000200 # H
NTLMSSP_UNKNOWN_00000400					= 0x00000400 # r8
NTLMSSP_NEGOTIATE_ANON						= 0x00000800 # J
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED		= 0x00001000 # K
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED	= 0x00002000 # L
NTLMSSP_UNUSED_00004000						= 0x00004000 # r7
NTLMSSP_NEGOTIATE_ALWAYS_SIGN				= 0x00008000 # M
NTLMSSP_TARGET_TYPE_DOMAIN					= 0x00010000 # N
NTLMSSP_TARGET_TYPE_SERVER					= 0x00020000 # O
NTLMSSP_UNUNSED_00040000					= 0x00040000 # r6
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY	= 0x00080000 # P
NTLMSSP_NEGOTIATE_IDENTIFY					= 0x00100000 # Q
NTLMSSP_UNUSED_00200000						= 0x00200000 # r5
NTLMSSP_REQUEST_NON_NT_SESSION_KEY			= 0x00400000 # R
NTLMSSP_NEGOTIATE_TARGET_INFO				= 0x00800000 # S
NTLMSSP_UNUSED_01000000						= 0x01000000 # r4
NTLMSSP_NEGOTIATE_VERSION					= 0x02000000 #
NTLMSSP_UNUSED_04000000						= 0x04000000 #
NTLMSSP_UNUSED_08000000						= 0x08000000 #
NTLMSSP_UNUSED_10000000						= 0x10000000 #
NTLMSSP_NEGOTIATE_128						= 0x20000000 #
NTLMSSP_NEGOTIATE_KEY_EXCH					= 0x40000000 #
NTLMSSP_NEGOTIATE_56						= 0x80000000 #


NTLMSSP_Flags = [
    "NEGOTIATE_UNICODE",
    "NEGOTIATE_OEM",
    "REQUEST_TARGET",
    "UNUSED_00000008",
    "NEGOTIATE_SIGN",
    "NEGOTIATE_SEAL",
    "NEGOTIATE_DATAGRAM",
    "NEGOTIATE_LM_KEY",
    "UNUSED_00000100",
    "NEGOTIATE_NTLM",
    "UNKNOWN_00000400",
    "NEGOTIATE_ANON",
    "NEGOTIATE_OEM_DOMAIN_SUPPLIED",
    "NEGOTIATE_OEM_WORKSTATION_SUPPLIED",
    "UNUSED_00004000",
    "NEGOTIATE_ALWAYS_SIGN",
    "TARGET_TYPE_DOMAIN",
    "TARGET_TYPE_SERVER",
    "UNUNSED_00040000",
    "NEGOTIATE_EXTENDED_SESSIONSECURITY",
    "NEGOTIATE_IDENTIFY",
    "UNUSED_00200000",
    "REQUEST_NON_NT_SESSION_KEY",
    "NEGOTIATE_TARGET_INFO",
    "UNUSED_01000000",
    "NEGOTIATE_VERSION",
    "UNUSED_04000000",
    "UNUSED_08000000",
    "UNUSED_10000000",
    "NEGOTIATE_128",
    "NEGOTIATE_KEY_EXCH",
    "NEGOTIATE_56"
]

class NTLM_Value(Packet):
    name = "NTLM Value"
    fields_desc = [
        LEShortField("Len",0),
        LEShortField("MaxLen",0),
        LEIntField("Offset",0),
    ]

class LM_Response(Packet):
    name = "LM Response"
    fields_desc = [
        StrFixedLenField("Response", "", 24),
    ]

class LMv2_Response(Packet):
    name = "LMv2 Response"
    fields_desc = [
        StrFixedLenField("Response", "", 16),
        StrFixedLenField("ChallengeFromClient", "", 8),
    ]

class NTLM_Response(Packet):
    name = "NTLM Response"
    fields_desc = [
        StrFixedLenField("Response", "", 24),
    ]

class NTLMv2_Client_Challenge(Packet):
    name = "NTLMv2 Client Challenge"
    fields_desc = [
        ByteField("RespType", 0x01),
        ByteField("HiRespType", 0x01),
        ShortField("Reserved1", 0),
        IntField("Reserved2", 0),
        NTTimeField("TimeStamp",datetime.datetime.now()),
        StrFixedLenField("ChallengeFromClient", "", 8),
        IntField("Reserved3", 0),
        # FIXME AvPairs until MsAvEOL
    ]

class NTLMv2_Response(Packet):
    name = "NTLMv2 Response"
    fields_desc = [
        StrFixedLenField("Response", "", 16),
        PacketField("Client_Challenge", 0, NTLMv2_Client_Challenge)
    ]

class NTLMSSP_Message_Signature(Packet):
    name = "NTLMSSP Message Signature"
    fields_desc = [
        IntField("Version",0x01),
        # FIXME conditional it not NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        IntField("RandomPad",0x01),
        IntField("Checksum",0x0), # FIXME conditional if not ... 8 bytes
        IntField("SeqNum",0x01),
    ]

class NTLM_Version(Packet):
    name = "NTLM Version"
    fields_desc = [
        # Set to Windows 5.1 Build 2600 NLMPv15
        ByteField("ProductMajorVersion",5),
        ByteField("ProductMinorVersion",1),
        LEShortField("ProductBuild",2600),
        StrFixedLenField("Reserved", "\0\0\0", 3),
        ByteField("NTLMRevisionCurrent",15),
    ]

AV_Pair_Ids = {
    0: "MsvAvEOL",
    1: "MsvAvNbComputerName",
    2: "MsvAvNbDomainName",
    3: "MsvAvDnsComputerName",
    4: "MsvAvDnsDomainName",
    5: "MsvAvDnsTreeName",
    6: "MsvAvFlags",
    7: "MsvAvTimestamp",
    8: "MsAvRestrictions",
    9: "MsvAvTargetName",
    10: "MsvChannelBindings"
}

class AV_PAIR(Packet):
    name = "AV Pair"
    fields_desc = [
        LEShortEnumField("Id",0,AV_Pair_Ids),
        FieldLenField("Len", 0, fmt='<H', length_of="Value"),
        StrLenField("Value", "", length_from=lambda x:x.Len),
    ]


class NTLMSSP_Header(Packet):
    name = "NTLMSSP Header"
    fields_desc = [
        StrFixedLenField("Signature", "NTLMSSP\0", 8),
        #		XLEIntField("MessageType",0x01000000),
        EnumField("MessageType",0, {
            1:"Negotiate",
            2:"Challenge",
            3:"Authenticate",
        }, fmt = "<I"),
    ]

class NTLM_Negotiate(Packet):
    name = "NTLM Negotiate"
    fields_desc = [
        FlagsField("NegotiateFlags", 0, -32, NTLMSSP_Flags),
        PacketField("DomainNameFields",0,NTLM_Value),
        PacketField("WorkStationFields",0,NTLM_Value),
        ConditionalField(PacketField("Version",0,NTLM_Version),
                         lambda x: x.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION),
        StrField("Payload","")
    ]


class NTLM_Challenge(Packet):
    name = "NTLM Challenge"
    fields_desc = [
        PacketField("TargetNameFields",NTLM_Value(),NTLM_Value),
        FlagsField("NegotiateFlags", 0, -32, NTLMSSP_Flags),
        StrFixedLenField("ServerChallenge","",8),
        StrFixedLenField("Reserved","",8),
        PacketField("TargetInfoFields",NTLM_Value(),NTLM_Value),
        #		PacketField("Version",0,NTLM_Version),
        ConditionalField(PacketField("Version",NTLM_Version(
        ),NTLM_Version), lambda x: x.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION),
        #		ConditionalField(StrFixedLenField("TargetFieldString","HOMEUSER-3AF6FE".encode('utf16')[2:],30), lambda x: x.NegotiateFlags & NTLMSSP_REQUEST_TARGET),
        StrField("Payload","")
        #PacketField("AVPair1",AV_PAIR(),AV_PAIR),
        #PacketField("AVPair2",AV_PAIR(),AV_PAIR),
        #PacketField("AVPair3",AV_PAIR(),AV_PAIR),
        #PacketField("AVPair4",AV_PAIR(),AV_PAIR),
        #PacketField("AVPair5",AV_PAIR(),AV_PAIR),
        #PacketField("AVPair6",AV_PAIR(),AV_PAIR),
    ]

class NTLM_Authenticate(Packet):
    name = "NTLM Authenticate"
    fields_desc = [
        PacketField("LmChallengeResponseFields",0,NTLM_Value),
        PacketField("NtChallengeResponseFields",0,NTLM_Value),
        PacketField("DomainNameFields",0,NTLM_Value),
        PacketField("UserNameFields",0,NTLM_Value),
        PacketField("WorkstationFields",0,NTLM_Value),
        PacketField("EncryptedRandomSessionKeyFields",0,NTLM_Value),
        FlagsField("NegotiateFlags", 0, -32, NTLMSSP_Flags),
        #		PacketField("Version",0,NTLM_Version),
        ConditionalField(PacketField("Version",NTLM_Version(
        ),NTLM_Version), lambda x: x.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION),
        StrFixedLenField("MIC","",16),
        StrField("Payload",""),
    ]

bind_bottom_up(NTLMSSP_Header, NTLM_Negotiate, MessageType = lambda x: x==1)
bind_bottom_up(NTLMSSP_Header, NTLM_Challenge, MessageType = lambda x: x==2)
bind_bottom_up(NTLMSSP_Header, NTLM_Authenticate, MessageType = lambda x: x==3)


bind_top_down(NTLMSSP_Header, NTLM_Challenge, MessageType = 2)
