#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
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

import logging
from uuid import UUID

rpclog = logging.getLogger('rpcservices')

class RPCService:
	uuid = ''
	version_major = 0
	version_minor = 0
#	syntax = UUID('8a885d04-1ceb-11c9-9fe8-08002b104860').hex
	ops = {}
	vulns = {}

	@classmethod
	def processrequest(cls, service, con, opnum, p):
		if opnum in cls.ops:
			opname = cls.ops[opnum]
			method = getattr(cls, "handle_" + opname, None)
			if method != None:
				if opnum in cls.vulns:
					vulnname = cls.vulns[opnum]
					rpclog.info("Calling %s %s (%x) maybe %s exploit?" % ( service.__class__.__name__,  opname, opnum, vulnname ) )
				else:
					rpclog.info("Calling %s %s (%x)" % ( service.__class__.__name__,  opname, opnum ) )
				method(p)
		else:
			rpclog.info("Unknown RPC Call to %s %i" % ( service.__class__.__name__,  opnum) )

class ATSVC(RPCService):
	uuid = UUID('1ff70682-0a51-30e8-076d-740be8cee98b').hex


class AudioSrv(RPCService):
	uuid = UUID('3faf4738-3a21-4307-b46c-fdda9bb8c0d5').hex


class browser(RPCService):
	uuid = UUID('6bffd098-a112-3610-9833-012892020162').hex


class davclntrpc(RPCService):
	uuid = UUID('c8cb7687-e6d3-11d2-a958-00c04f682e16').hex


class DCOM(RPCService):
	uuid = UUID('4d9f4ab8-7d1c-11cf-861e-0020af6e7c57').hex

	ops = {
		0x00: "RemoteActivation",
	}
	vulns = {
		0x00: "MS03-26",
	}

	@classmethod
	def handle_RemoteActivation(cls, p):
		# MS03-026
		pass


class DnsServer(RPCService):
	uuid = UUID('50abc2a4-574d-40b3-9d66-ee4fd5fba076').hex


class DSSETUP(RPCService):
	uuid = UUID('3919286a-b10c-11d0-9ba8-00c04fd92ef5').hex

	ops = {
		0x09: "DsRolerUpgradeDownlevelServer"
	}
	vulns  = { 
		0x09: "MS04-11",
	}

	@classmethod
	def handle_DsRolerUpgradeDownlevelServer(cls, p):
		# MS04-011
		pass


class epmp(RPCService):
	uuid = UUID('e1af8308-5d1f-11c9-91a4-08002b14a0fa').hex


class eventlog(RPCService):
	uuid = UUID('82273fdc-e32a-18c3-3f78-827929dc23ea').hex


class GetUserToken(RPCService):
	uuid = UUID('a002b3a0-c9b7-11d1-ae88-0080c75e4ec1').hex


class ICertPassage(RPCService):
	uuid = UUID('91ae6020-9e3c-11cf-8d7c-00aa00c091be').hex


class ICertProtect(RPCService):
	uuid = UUID('0d72a7d4-6148-11d1-b4aa-00c04fb66ea0').hex


class InitShutdown(RPCService):
	uuid = UUID('894de0c0-0d55-11d3-a322-00c04fa321a1').hex


class IKeySvc(RPCService):
	uuid = UUID('8d0ffe72-d252-11d0-bf8f-00c04fd9126b').hex


class IPStoreProv(RPCService):
	uuid = UUID('c9378ff1-16f7-11d0-a0b2-00aa0061426a').hex


class ISeclogon(RPCService):
	uuid = UUID('12b81e99-f207-4a4c-85d3-77b42f76fd14').hex


class ISystemActivator(RPCService):
	uuid = UUID('000001a0-0000-0000-c000-000000000046').hex

	ops = {
		0x4: "RemoteCreateInstance"
	}
	vulns  = { 
		0x4: "MS04-12",
	}

	@classmethod
	def handle_RemoteCreateInstance(cls, p):
		# MS04-012
		pass

class IOXIDResolver(RPCService):
	uuid = UUID('99fcfec4-5260-101b-bbcb-00aa0021347a').hex


class llsrpc(RPCService):
	uuid = UUID('342cfd40-3c6c-11ce-a893-08002b2e9c6d').hex


class lsarpc(RPCService):
	uuid = UUID('12345778-1234-abcd-ef00-0123456789ab').hex


class msgsvcsend(RPCService):
	uuid = UUID('5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc').hex


class MSMQ(RPCService):
	uuid = UUID('fdb3a030-065f-11d1-bb9b-00a024ea5525').hex

	ops = {
		0x06: "QMCreateObjectInternal",
		0x09: "QMDeleteObject",
	}
	vulns = {
		0x06: "MS07-065",
		0x09: "MS05-017",
	}

	@classmethod
	def handle_QMCreateObjectInternal(cls, p):
		# MS07-065
		pass

	@classmethod
	def handle_QMDeleteObject(cls, p):
		# MS05-017
		pass


class netdfs(RPCService):
	uuid = UUID('4fc742e0-4a10-11cf-8273-00aa004ae673').hex


class netlogon(RPCService):
	uuid = UUID('12345678-1234-abcd-ef00-01234567cffb').hex


class nddeapi(RPCService):
	uuid = UUID('2f5f3220-c126-1076-b549-074d078619da').hex


class NWWKS(RPCService):
	uuid = UUID('e67ab081-9844-3521-9d32-834f038001c0').hex

	ops = {
		0x09: "NwOpenEnumNdsSubTrees",
		0x01: "NwChangePassword"
	}
	vulns  = { 
		0x09: "MS06-66",
		0x01: "MS06-66",
	}

	@classmethod
	def handle_NwOpenEnumNdsSubTrees(cls, p):
		# MS06-066
		pass

	@classmethod
	def handle_NwChangePassword(cls, p):
		# MS06-066
		pass


class NsiS(RPCService):
	uuid = UUID('d6d70ef0-0e3b-11cb-acc3-08002b1d29c4').hex


class PNP(RPCService):
	uuid = UUID('8d9f4e40-a03d-11ce-8f69-08003e30051b').hex

	ops = {
		0x36: "PNP_QueryResConfList",
	}
	vulns = {
		0x36: "MS05-39",
	}

	@classmethod
	def handle_PNP_QueryResConfList(cls, p):
		# MS05-39
		pass



class PolicyAgent(RPCService):
	uuid = UUID('d335b8f6-cb31-11d0-b0f9-006097ba4e54').hex


class pmapapi(RPCService):
	uuid = UUID('369ce4f0-0fdc-11d3-bde8-00c04f8eee78').hex


class RemoteAccess(RPCService):
	uuid = UUID('8f09f000-b7ed-11ce-bbd2-00001a181cad').hex


class samr(RPCService):
	uuid = UUID('12345778-1234-abcd-ef00-0123456789ac').hex


class SceSvc(RPCService):
	uuid = UUID('93149ca2-973b-11d1-8c39-00c04fb984f9').hex


class sfcapi(RPCService):
	uuid = UUID('83da7c00-e84f-11d2-9807-00c04f8ec850').hex


class spoolss(RPCService):
	uuid = UUID('12345678-1234-abcd-ef00-0123456789ab').hex


class SRVSVC(RPCService):
	uuid = UUID('4b324fc8-1670-01d3-1278-5a47bf6ee188').hex
	version_major = 0
	version_minor = 0

	ops = {
		0x0f: "NetShareEnumAll",
		0x1f: "NetPathCanonicalize",
		0x20: "NetCompare",
	}
	vulns  = { 
		0x1f: "MS08-67",
		0x20: "MS08-67",
	}

	@classmethod
	def handle_NetShareEnumAll(cls, p):
		pass

	@classmethod
	def handle_NetPathCanonicalize(cls, p):
		# MS08-067
		pass

	@classmethod
	def handle_NetPathCompare(cls, p):
		# MS08-067
		pass


class ssdpsrv(RPCService):
	uuid = UUID('4b112204-0e19-11d3-b42b-0000f81feb9f').hex


class SVCCTL(RPCService):
	uuid = UUID('367abb81-9844-35f1-ad32-98f038001003').hex


class tapsrv(RPCService):
	uuid = UUID('2f5f6520-ca46-1067-b319-00dd010662da').hex


class TerminalServerLicensing(RPCService):
	uuid = UUID('3d267954-eeb7-11d1-b94e-00c04fa3080d').hex


class trkwks(RPCService):
	uuid = UUID('300f3532-38cc-11d0-a3f0-0020af6b0add').hex


class w32time(RPCService):
	uuid = UUID('8fb6d884-2388-11d0-8c35-00c04fda2795').hex


class winipsec(RPCService):
	uuid = UUID('12345678-1234-abcd-ef00-0123456789ab').hex


class winreg(RPCService):
	uuid = UUID('338cd001-2244-31f1-aaaa-900038001003').hex


class winsif(RPCService):
	uuid = UUID('45f52c28-7f9f-101a-b52b-08002b2efabe').hex


class winstation_rpc(RPCService):
	uuid = UUID('5ca4a760-ebb1-11cf-8611-00a0245420ed').hex


class WKSSVC(RPCService):
	uuid = UUID('6bffd098-a112-3610-9833-46c3f87e345a').hex

	ops = {
		0x1b: "NetAddAlternateComputerName"
	}
	vulns  = { 
		0x1b: "MS04-11",
	}

	@classmethod
	def handle_NetAddAlternateComputerName(cls, p):
		# MS04-011
		pass




