#********************************************************************************
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
#*  This file was part of Scapy
#*  See http://www.secdev.org/projects/scapy for more informations
#*  Copyright (C) Philippe Biondi <phil@secdev.org>
#*  This program is published under a GPLv2 license
#*******************************************************************************

from .asn1.asn1 import ASN1_Class_UNIVERSAL
from .asn1.asn1 import ASN1_SEQUENCE
from .asn1.asn1 import ASN1_Codecs
from .asn1.ber import BERcodec_SEQUENCE
from .asn1packet import ASN1_Packet
from .asn1fields import ASN1F_SEQUENCE, ASN1F_OID, ASN1F_optionnal
from .asn1fields import ASN1F_CHOICE, ASN1F_SEQUENCE_OF, ASN1F_STRING
from .asn1fields import ASN1F_ENUMERATED

class ASN1_Class_NegTokenInitValue(ASN1_Class_UNIVERSAL):
    name = "NegTokenInitValue"
    MechTypes = 0xa0
    reqFlags = 0xa1
    mechToken = 0xa2
    mechListMIC = 0xa3

# MechTypes
class ASN1_NegTokenInitValue_MechTypes(ASN1_SEQUENCE):
    tag = ASN1_Class_NegTokenInitValue.MechTypes

class ASN1F_NegTokenInitValue_MechTypes(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_NegTokenInitValue.MechTypes

class BERcodec_NegTokenInitValue_MechTypes(BERcodec_SEQUENCE):
    tag = ASN1_Class_NegTokenInitValue.MechTypes

# reqFlags
class ASN1_NegTokenInitValue_reqFlags(ASN1_SEQUENCE):
    tag = ASN1_Class_NegTokenInitValue.reqFlags

class ASN1F_NegTokenInitValue_reqFlags(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_NegTokenInitValue.reqFlags

class BERcodec_NegTokenInitValue_reqFlags(BERcodec_SEQUENCE):
    tag = ASN1_Class_NegTokenInitValue.reqFlags

# mechToken
class ASN1_NegTokenInitValue_mechToken(ASN1_SEQUENCE):
    tag = ASN1_Class_NegTokenInitValue.mechToken

class ASN1F_NegTokenInitValue_mechToken(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_NegTokenInitValue.mechToken

class BERcodec_NegTokenInitValue_mechToken(BERcodec_SEQUENCE):
    tag = ASN1_Class_NegTokenInitValue.mechToken


# MechType Packet
class MechType(ASN1_Packet):
    name = "MechType"
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_OID("oid","1.1.1")

class NegTokenInit(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
#        ASN1F_optionnal(ASN1F_NegTokenInitValue_MechTypes(ASN1F_SEQUENCE_OF("MechTypes",[MechType()],MechType)))
        ASN1F_optionnal(ASN1F_NegTokenInitValue_MechTypes(ASN1F_SEQUENCE_OF("MechTypes",[],MechType))),
#        ASN1F_optionnal(ASN1F_NegTokenInitValue_reqFlags(ASN1F_BIT_STRING("reqFlags",""))),
        ASN1F_optionnal(ASN1F_NegTokenInitValue_mechToken(ASN1F_STRING("mechToken","",""))),
#        ASN1F_optionnal(ASN1F_STRING("mechListMIC","")),
        )



#NegTokenTarg ::= SEQUENCE {
#    negResult      [0] ENUMERATED {
#                            accept_completed    (0),
#                            accept_incomplete   (1),
#                            reject              (2) }          OPTIONAL,
#    supportedMech  [1] MechType                                OPTIONAL,
#    responseToken  [2] OCTET STRING                            OPTIONAL,
#    mechListMIC    [3] OCTET STRING                            OPTIONAL
#}
#

NegTokenTarg_negResults = {
    0: "completed",
    1: "incomplete",
    2: "reject"
}

class ASN1_Class_NegTokenTargValue(ASN1_Class_UNIVERSAL):
    name = "NegTokenTargValue"
    negResult     = 0xa0
    supportedMech = 0xa1
    responseToken = 0xa2
    mechListMIC   = 0xa3

# negResult
class ASN1_NegTokenTargValue_negResult(ASN1_SEQUENCE):
    tag = ASN1_Class_NegTokenTargValue.negResult

class ASN1F_NegTokenTargValue_negResult(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_NegTokenTargValue.negResult

class BERcodec_NegTokenTargValue_negResult(BERcodec_SEQUENCE):
    tag = ASN1_Class_NegTokenTargValue.negResult

# supportedMech
class ASN1_NegTokenTargValue_supportedMech(ASN1_SEQUENCE):
    tag = ASN1_Class_NegTokenTargValue.supportedMech

class ASN1F_NegTokenTargValue_supportedMech(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_NegTokenTargValue.supportedMech

class BERcodec_NegTokenTargValue_supportedMech(BERcodec_SEQUENCE):
    tag = ASN1_Class_NegTokenTargValue.supportedMech

# responseToken
class ASN1_NegTokenTargValue_responseToken(ASN1_SEQUENCE):
    tag = ASN1_Class_NegTokenTargValue.responseToken

class ASN1F_NegTokenTargValue_responseToken(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_NegTokenTargValue.responseToken

class BERcodec_NegTokenTargValue_responseToken(BERcodec_SEQUENCE):
    tag = ASN1_Class_NegTokenTargValue.responseToken

# mechListMIC
class ASN1_NegTokenTargValue_mechListMIC(ASN1_SEQUENCE):
    tag = ASN1_Class_NegTokenTargValue.mechListMIC

class ASN1F_NegTokenTargValue_mechListMIC(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_NegTokenTargValue.mechListMIC

class BERcodec_NegTokenTargValue_mechListMIC(BERcodec_SEQUENCE):
    tag = ASN1_Class_NegTokenTargValue.mechListMIC

class NegTokenTarg(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_optionnal(ASN1F_NegTokenTargValue_negResult(ASN1F_ENUMERATED("negResult",1,NegTokenTarg_negResults))),
        ASN1F_optionnal(ASN1F_NegTokenTargValue_supportedMech(ASN1F_OID("supportedMech","1"))),
        ASN1F_optionnal(ASN1F_NegTokenTargValue_responseToken(ASN1F_STRING("responseToken",None))),
        ASN1F_optionnal(ASN1F_NegTokenTargValue_mechListMIC(ASN1F_STRING("mechListMIC",None)))
    )


class SPNEGO(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_CHOICE("NegotiationToken", NegTokenInit(), NegTokenTarg, NegTokenInit)

class GSSAPI(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_OID("oid",".")


