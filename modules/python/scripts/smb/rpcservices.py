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


from dionaea import ndrlib
from .include.smbfields import DCERPC_Header, DCERPC_Response

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
				
				r = DCERPC_Header() / DCERPC_Response()
				data = method(p)
				if data is None:
					data = b''
				r.StubData = data
				r.CallID = p.CallID
				r.FragLen = 24 + len(data)
				print(data)
#				print(r.show())
				return r
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
	ops = {
		0x5: "ServerAlive2"
	}

	@classmethod
	def handle_ServerAlive2(cls, dce):

		# http://msdn.microsoft.com/en-us/library/cc226953%28PROT.10%29.aspx
		#
		#	[idempotent] error_status_t ServerAlive2(
		#	  [in] handle_t hRpc,
		#	  [out, ref] COMVERSION* pComVersion,
		#	  [out, ref] DUALSTRINGARRAY** ppdsaOrBindings,
		#	  [out, ref] DWORD* pReserved
		#	);
		p = ndrlib.Packer()

		# 3.2.2.5.1.6 COMVERSION
		# http://msdn.microsoft.com/en-us/library/cc226880%28PROT.10%29.aspx
		p.pack_short(5)
		p.pack_short(7)
		

		# ref
		p.pack_pointer(0x200008)

		# number of elements in array
		p.pack_long(11)

		# 2.2.1.19.2 DUALSTRINGARRAY
		# http://msdn.microsoft.com/en-us/library/cc226841%28PROT.10%29.aspx
		# typedef struct tagDUALSTRINGARRAY {
		#   unsigned short wNumEntries;
		#   unsigned short wSecurityOffset;
		#   [size_is(wNumEntries)] unsigned short aStringArray[];
		# } DUALSTRINGARRAY;

		# wNumEntries
		p.pack_short(11)
		
		# wSecurityOffset
		p.pack_short(10)

		# 1 2.2.1.19.3 STRINGBINDING
		# http://msdn.microsoft.com/en-us/library/cc226838%28PROT.10%29.aspx
		
		# wTowerId
		# http://www.opengroup.org/onlinepubs/9692999399/apdxi.htm#tagcjh_28
		p.pack_short(0x09) # DOD IP 

		# aNetworkAddr
		p.pack_raw('127.0.0.1\0\0'.encode('utf16')[2:]) # len = 20
		
		# 2.2.1.19.4 SECURITYBINDING
		# http://msdn.microsoft.com/en-us/library/cc226839%28PROT.10%29.aspx

		# wAuthnSvc
		# http://msdn.microsoft.com/en-us/library/cc243578%28PROT.10%29.aspx 
#		p.pack_short(0x00) # RPC_C_AUTHN_NONE
		p.pack_short(0x0A) # RPC_C_AUTHN_WINNT

		# reserved
		p.pack_short(0xffff)

		# aPrincName
		p.pack_raw('MUTTER\0\0'.encode('utf16')[2:])


		# reserved
		p.pack_pointer(0)
		p.pack_long(0)
		
		print(p.get_buffer())
		return p.get_buffer()


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

class MGMT(RPCService):
	uuid = UUID('afa8bd80-7d8a-11c9-bef4-08002b102989').hex

class samr(RPCService):
	""" [MS-SAMR]: Security Account Manager (SAM) Remote Protocol Specification (Client-to-Server)
	
	http://msdn.microsoft.com/en-us/library/cc245476%28v=PROT.13%29.aspx

	http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-SAMR%5D.pdf"""

	uuid = UUID('12345778-1234-abcd-ef00-0123456789ac').hex

	class SAMPR_HANDLE:
		# 2.2.3.2 SAMPR_HANDLE
		#
		# http://msdn.microsoft.com/en-us/library/cc245544%28v=PROT.10%29.aspx
		#
		# typedef [context_handle] void* SAMPR_HANDLE; 
		# 
		def __init__(self, p, handle=None):
			if isinstance(p,ndrlib.Packer):
				p.pack_raw(handle)
			elif isinstance(p,ndrlib.Unpacker):
				self.Value = p.unpack_raw(20)

	class RPC_SID_IDENTIFIER_AUTHORITY:
		# 2.4.1.1 RPC_SID_IDENTIFIER_AUTHORITY
		#
		# http://msdn.microsoft.com/en-us/library/cc230372%28PROT.10%29.aspx
		#
		# typedef struct _RPC_SID_IDENTIFIER_AUTHORITY {
		#   byte Value[6];
		# } RPC_SID_IDENTIFIER_AUTHORITY;
		#
		SID_AUTHORITY = {
			'NULL_SID_AUTHORITY'			: b'\x00\x00\x00\x00\x00\x00', 
			'WORLD_SID_AUTHORITY'			: b'\x00\x00\x00\x00\x00\x01', 
			'LOCAL_SID_AUTHORITY'			: b'\x00\x00\x00\x00\x00\x02', 
			'CREATOR_SID_AUTHORITY'			: b'\x00\x00\x00\x00\x00\x03', 
			'NON_UNIQUE_AUTHORITY'			: b'\x00\x00\x00\x00\x00\x04',
			'NT_AUTHORITY'				: b'\x00\x00\x00\x00\x00\x05', 
			'SECURITY_MANDATORY_LABEL_AUTHORITY'	: b'\x00\x00\x00\x00\x00\x10'
		}
		def __init__(self, p, value=None):
			if isinstance(p,ndrlib.Packer):
				if not self.SID_AUTHORITY.get(value) == None:
					p.pack_raw(self.SID_AUTHORITY[value])
			elif isinstance(p,ndrlib.Unpacker):
				self.Value = p.unpack_raw(6)

	class RPC_SID:
		# 2.4.2.2 RPC_SID
		# 
		# http://msdn.microsoft.com/en-us/library/cc230364%28PROT.10%29.aspx
		# 
		# typedef struct _RPC_SID {
		#   unsigned char Revision;
		#   unsigned char SubAuthorityCount;
		#   RPC_SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
		#   [size_is(SubAuthorityCount)] 
		#   unsigned long SubAuthority[];
		# } RPC_SID, 
		#  *PRPC_SID;
		#
		def __init__(self, p, value=None):
			if isinstance(p,ndrlib.Packer):
				# Revision
				p.pack_small(1)

				# SubAuthorityCount
				p.pack_small(4)

				# RPC_SID_IDENTIFIER_AUTHORITY
				samr.RPC_SID_IDENTIFIER_AUTHORITY(p, value)

				# SubAuthority
				p.pack_long(21)
				p.pack_long(606747145)
				p.pack_long(1364589140)
				p.pack_long(839522115)
			elif isinstance(p,ndrlib.Unpacker):
				self.Revision = p.unpack_small()
				self.SubAuthorityCount = p.unpack_small()
				self.IdentifierAuthority = samr.RPC_SID_IDENTIFIER_AUTHORITY(p,None)
				self.SubAuthority = []
				for i in range(self.SubAuthorityCount):
					self.SubAuthority.append(p.unpack_long())

	class RPC_UNICODE_STRING:
		# 2.3.5 RPC_UNICODE_STRING
		# 
		# http://msdn.microsoft.com/en-us/library/cc230365%28PROT.10%29.aspx
		# 
		# typedef struct _RPC_UNICODE_STRING {
		#   unsigned short Length;
		#   unsigned short MaximumLength;
		#   [size_is(MaximumLength/2), length_is(Length/2)] 
		# 	WCHAR* Buffer;
		# } RPC_UNICODE_STRING, 
		#  *PRPC_UNICODE_STRING;
		# 
		def __init__(self, p, data=None):
			if isinstance(p,ndrlib.Packer):
				p.pack_rpc_unicode_string(data)
			elif isinstance(p,ndrlib.Unpacker):
				self.Length = p.unpack_short()
				self.MaximumLength = p.unpack_short()
				self.Reference = p.unpack_pointer()
				self.Buffer = p.unpack_string()


	class SAMPR_RID_ENUMERATION:
		# 2.2.3.9 SAMPR_RID_ENUMERATION
		# 
		# http://msdn.microsoft.com/en-us/library/cc245560%28PROT.10%29.aspx
		#
		# typedef struct _SAMPR_RID_ENUMERATION {
		#   unsigned long RelativeId;
		#   RPC_UNICODE_STRING Name;
		# } SAMPR_RID_ENUMERATION, 
		#  *PSAMPR_RID_ENUMERATION;
		def __init__(self, p, Name=None):
			if isinstance(p,ndrlib.Packer):
				for i in range(len(Name)): 				
					#RelativeID
					p.pack_long(0)
					samr.RPC_UNICODE_STRING(p, Name[i])
					p.pack_pointer(0x11)

				for j in range(len(Name)):
					p.pack_string(Name[j].encode('utf16')[2:])
			elif isinstance(p,ndrlib.Unpacker):
				self.RelativeId = p.unpack_long()
				self.Name = RPC_UNICODE_STRING(p, Name)


	class SAMPR_ENUMERATION_BUFFER:
		# 2.2.3.10 SAMPR_ENUMERATION_BUFFER
		# 
		# http://msdn.microsoft.com/en-us/library/cc245561%28v=PROT.10%29.aspx
		# 
		# typedef struct _SAMPR_ENUMERATION_BUFFER {
		#     unsigned long EntriesRead;
				#    [size_is(EntriesRead)] PSAMPR_RID_ENUMERATION Buffer;
		# } SAMPR_ENUMERATION_BUFFER, 
		# *PSAMPR_ENUMERATION_BUFFER;
		def __init__(self, p, Buffer=None):
			if isinstance(p,ndrlib.Packer):
				# EntriesRead
				p.pack_long(len(Buffer))
				p.pack_pointer(0x4711)

				# maxcount as described by wireshark
				# the value need same as EntriesRead, I not sure why
				p.pack_long(len(Buffer))
 
				samr.SAMPR_RID_ENUMERATION(p, Buffer)
			elif isinstance(p,ndrlib.Unpacker):
				raise NotImplementedError

	ops = {
		1: "Close",
		5: "LookupDomain",
		6: "EnumDomains",
		7: "OpenDomain",
		13: "EnumDomainUsers",
		62: "Connect4",
		64: "Connect5"
	}

	@classmethod
	def handle_Connect4(cls, p):
		# 3.1.5.1.2 SamrConnect4 (Opnum 62)
		# 
		# http://msdn.microsoft.com/en-us/library/cc245746%28PROT.10%29.aspx
		# 
		# long SamrConnect4(
		#   [in, unique, string] PSAMPR_SERVER_NAME ServerName,
		#   [out] SAMPR_HANDLE* ServerHandle,
		#   [in] unsigned long ClientRevision,
		#   [in] unsigned long DesiredAccess
		# );
		x = ndrlib.Unpacker(p.StubData)
		PServerName = x.unpack_pointer()
		ServerName = x.unpack_string()
		print("ServerName %s" % ServerName)
		DesiredAccess = x.unpack_long()
		print("DesiredAccess %i" % DesiredAccess)
		ClientRevision = x.unpack_long()
		print("InVersion %i" % ClientRevision)

		r = ndrlib.Packer()

		# ServerHandle
		samr.SAMPR_HANDLE(r,b'01234567890123456789')

		# return 
		r.pack_long(0)

		return r.get_buffer()

	@classmethod
	def handle_Connect5(cls, p):
		# 3.1.5.1.1 SamrConnect5 (Opnum 64)
		# 
		# http://msdn.microsoft.com/en-us/library/cc245745%28PROT.10%29.aspx
		# 
		# long SamrConnect5(
		#   [in, unique, string] PSAMPR_SERVER_NAME ServerName,
		#   [in] unsigned long DesiredAccess,
		#   [in] unsigned long InVersion,
		#   [in, switch_is(InVersion)] SAMPR_REVISION_INFO* InRevisionInfo,
		#   [out] unsigned long* OutVersion,
		#   [out, switch_is(*OutVersion)] SAMPR_REVISION_INFO* OutRevisionInfo,
		#   [out] SAMPR_HANDLE* ServerHandle
		# );
		x = ndrlib.Unpacker(p.StubData)
		PServerName = x.unpack_pointer()
		ServerName = x.unpack_string()

		print("ServerName %s" % ServerName)
		DesiredAccess = x.unpack_long()

		print("DesiredAccess %i" % DesiredAccess)
		InVersion = x.unpack_long()
		print("InVersion %i" % InVersion)

		PInRevisionInfo = x.unpack_pointer()

		# 2.2.3.15 SAMPR_REVISION_INFO_V1
		# http://msdn.microsoft.com/en-us/library/cc245541%28v=PROT.10%29.aspx
		Revision = x.unpack_long()
		SupportedFeatures = x.unpack_long()

		print("Revision %i SupportedFeatures %i" % (Revision, SupportedFeatures))

		r = ndrlib.Packer()

		r.pack_pointer(0x1)
		r.pack_long(InVersion)

		r.pack_long(Revision)
		r.pack_long(SupportedFeatures)

		# ServerHandle
		samr.SAMPR_HANDLE(r,b'01234567890123456789')

		# return
		r.pack_long(0)

		return r.get_buffer()
	
	@classmethod
	def handle_EnumDomains(cls,p):
		#3.1.5.2.1 SamrEnumerateDomainsInSamServer (Opnum 6)
		#
		#http://msdn.microsoft.com/en-us/library/cc245755%28v=PROT.10%29.aspx
		#
		#long SamrEnumerateDomainsInSamServer(
  		#   [in] SAMPR_HANDLE ServerHandle,
  		#   [in, out] unsigned long* EnumerationContext,
  		#   [out] PSAMPR_ENUMERATION_BUFFER* Buffer,
  		#   [in] unsigned long PreferedMaximumLength,
  		#   [out] unsigned long* CountReturned
		#);
		x = ndrlib.Unpacker(p.StubData)
		ServerHandle = samr.SAMPR_HANDLE(x)
		print("ServerHandle %s" % ServerHandle)

		EnumerationContext = x.unpack_long()
		print("EnumerationContext %i" % EnumerationContext)
		
		PreferedMaximumLength = x.unpack_long()
		print("PreferedMaximumLength %i" % PreferedMaximumLength)
		
		r = ndrlib.Packer()
		r.pack_pointer(EnumerationContext)

		# PSAMPR_ENUMERATION_BUFFER* Buffer
		r.pack_pointer(0x0da260)
		samr.SAMPR_ENUMERATION_BUFFER(r, ['HOMEUSER-3AF6FE','Builtin'])

		# long* CountReturned
		r.pack_pointer(0x02)
		r.pack_long(0)

		return r.get_buffer()
	
	@classmethod
	def handle_LookupDomain(cls,p):	
		#3.1.5.11.1 SamrLookupDomainInSamServer (Opnum 5)
		#
		#http://msdn.microsoft.com/en-us/library/cc245711%28v=PROT.13%29.aspx
		#
		#long SamrLookupDomainInSamServer(
  		#[in] SAMPR_HANDLE ServerHandle,
  		#[in] PRPC_UNICODE_STRING Name,
 		#[out] PRPC_SID* DomainId
		#);
		x = ndrlib.Unpacker(p.StubData)
		ServerHandle = samr.SAMPR_HANDLE(x)
		Name = samr.RPC_UNICODE_STRING(x)
		r = ndrlib.Packer()
		r.pack_pointer(0x0da260)   #same as EnumDomain
		
		#Count as described by wireshark, I not sure why this needed
		r.pack_long(4)

		samr.RPC_SID(r,'NT_AUTHORITY')	
		r.pack_long(0)
		return r.get_buffer()
	
	@classmethod
	def handle_OpenDomain(cls, p):
		# 3.1.5.1.5 SamrOpenDomain (Opnum 7)
		# 
		# http://msdn.microsoft.com/en-us/library/cc245748%28v=PROT.10%29.aspx
		#
		# long SamrOpenDomain(
		#   [in] SAMPR_HANDLE ServerHandle,
		#   [in] unsigned long DesiredAccess,
		#   [in] PRPC_SID DomainId,
		#   [out] SAMPR_HANDLE* DomainHandle
		# );
		x = ndrlib.Unpacker(p.StubData)
		ServerHandle = samr.SAMPR_HANDLE(x)
		print("ServerHandle %s" % ServerHandle)

		DesiredAccess = x.unpack_long()
		print("DesiredAccess %i" % DesiredAccess)
		
		DomainId = samr.RPC_SID(x)	
	
		r = ndrlib.Packer()
		samr.SAMPR_HANDLE(r, b'11223344556677889900')
		r.pack_long(0)

		return r.get_buffer()
	
	@classmethod
	def handle_EnumDomainUsers(cls, p):
		#3.1.5.2.5 SamrEnumerateUsersInDomain (Opnum 13)
		#
		#http://msdn.microsoft.com/en-us/library/cc245759%28v=PROT.13%29.aspx
		#
		#long SamrEnumerateUsersInDomain(
  		#[in] SAMPR_HANDLE DomainHandle,
  		#[in, out] unsigned long* EnumerationContext,
  		#[in] unsigned long UserAccountControl,
  		#[out] PSAMPR_ENUMERATION_BUFFER* Buffer,
  		#[in] unsigned long PreferedMaximumLength,
  		#[out] unsigned long* CountReturned
		#)
		x = ndrlib.Unpacker(p.StubData)
		DomainHandle = samr.SAMPR_HANDLE(x)
		print("DomainHandle %s" % DomainHandle)
	
		EnumerationContext = x.unpack_long()
		print("EnumerationContext %i" % EnumerationContext)
		
		UserAccountControl = x.unpack_long()
		print("UserAccountControl %i" % UserAccountControl)

		PreferedMaximumLength = x.unpack_long()
		print("PreferedMaximumLength %i" % PreferedMaximumLength)

		r = ndrlib.Packer()
		r.pack_pointer(EnumerationContext)

		# PSAMPR_ENUMERATION_BUFFER* Buffer
		r.pack_pointer(0x0da260)
		samr.SAMPR_ENUMERATION_BUFFER(r, ['Administrator','Guest','HelpAssistant','SUPPORT_388945a0'])
		# long* CountReturned
		r.pack_pointer(0x04)
		r.pack_long(0)

		return r.get_buffer()

	@classmethod
	def handle_Close(cls, p):
		#3.1.5.13.1 SamrCloseHandle (Opnum 1)		
		#
		#http://msdn.microsoft.com/en-us/library/cc245722%28v=PROT.13%29.aspx
		#
		#long SamrCloseHandle(
  		#[in, out] SAMPR_HANDLE* SamHandle
		#);
		x = ndrlib.Unpacker(p.StubData)
		SamHandle = samr.SAMPR_HANDLE(x)
		print("SamHandle %s" % SamHandle)
		
		r = ndrlib.Packer()
		samr.SAMPR_HANDLE(r, b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0')
		r.pack_long(0)

		return r.get_buffer()

class SceSvc(RPCService):
	uuid = UUID('93149ca2-973b-11d1-8c39-00c04fb984f9').hex


class sfcapi(RPCService):
	uuid = UUID('83da7c00-e84f-11d2-9807-00c04f8ec850').hex


class spoolss(RPCService):
	uuid = UUID('12345678-1234-abcd-ef00-0123456789ab').hex


class SRVSVC(RPCService):
	""" [MS-SRVS]: Server Service Remote Protocol Specification

	http://msdn.microsoft.com/en-us/library/cc247080%28v=PROT.13%29.aspx

	http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-SRVS%5D.pdf 

	"""
	uuid = UUID('4b324fc8-1670-01d3-1278-5a47bf6ee188').hex
	version_major = 0
	version_minor = 0

	ops = {
		0x0e: "NetShareAdd",
		0x0f: "NetShareEnum",
		0x1f: "NetPathCanonicalize",
		0x20: "NetPathCompare",
	}
	vulns  = { 
		0x1f: "MS08-67",
		0x20: "MS08-67",
	}

	@classmethod
	def handle_NetShareEnum(cls, p):

		x = ndrlib.Unpacker(p.StubData)

		# 3.1.4.8 NetrShareEnum (Opnum 15)
		# 
		# http://msdn.microsoft.com/en-us/library/cc247276%28PROT.10%29.aspx
		#
		#	NET_API_STATUS NetrShareEnum(
		#	  [in, string, unique] SRVSVC_HANDLE ServerName,
		#	  [in, out] LPSHARE_ENUM_STRUCT InfoStruct,
		#	  [in] DWORD PreferedMaximumLength,
		#	  [out] DWORD* TotalEntries,
		#	  [in, out, unique] DWORD* ResumeHandle
		#	);

		# 2.2.1.1 SRVSVC_HANDLE
		# 
		# http://msdn.microsoft.com/en-us/library/cc247105%28PROT.10%29.aspx
		# 
		# 	typedef [handle, string] WCHAR* SRVSVC_HANDLE; 

		srvsvc_handle_ref = x.unpack_pointer()
		srvsvc_handle = x.unpack_string()

		# 2.2.4.38 SHARE_ENUM_STRUCT
		# 
		# http://msdn.microsoft.com/en-us/library/cc247161%28PROT.10%29.aspx
		# 
		#	typedef struct _SHARE_ENUM_STRUCT {
		#	  DWORD Level;
		#	  [switch_is(Level)] SHARE_ENUM_UNION ShareInfo;
		#	} SHARE_ENUM_STRUCT, 
		#	 *PSHARE_ENUM_STRUCT, 
		#	 *LPSHARE_ENUM_STRUCT;

		infostruct_level = x.unpack_long()
		infostruct_share = x.unpack_long()
		
		# typedef 
		# [switch_type(DWORD)] 
		#   union _SHARE_ENUM_UNION {
		#   [case(0)] 
		# 	SHARE_INFO_0_CONTAINER* Level0;
		#   [case(1)] 
		# 	SHARE_INFO_1_CONTAINER* Level1;
		#   [case(2)] 
		# 	SHARE_INFO_2_CONTAINER* Level2;
		#   [case(501)] 
		# 	SHARE_INFO_501_CONTAINER* Level501;
		#   [case(502)] 
		# 	SHARE_INFO_502_CONTAINER* Level502;
		#   [case(503)] 
		# 	SHARE_INFO_503_CONTAINER* Level503;
		# } SHARE_ENUM_UNION;

		count = 0
		buffer = 0
		if infostruct_share == 1:
			# 2.2.4.33 SHARE_INFO_1_CONTAINER
 			# 
			# http://msdn.microsoft.com/en-us/library/cc247157%28PROT.10%29.aspx
 			# 
			# typedef struct _SHARE_INFO_1_CONTAINER {
			#   DWORD EntriesRead;
			#   [size_is(EntriesRead)] LPSHARE_INFO_1 Buffer;
			# } SHARE_INFO_1_CONTAINER;
			ptr = x.unpack_pointer()
			count = x.unpack_long()
			buffer = x.unpack_pointer()

		if infostruct_share == 502:
			# 2.2.4.36 SHARE_INFO_502_CONTAINER
			#
			# http://msdn.microsoft.com/en-us/library/cc247160%28PROT.13%29.aspx
			#
			# typedef struct _SHARE_INFO_502_CONTAINER {
			#   DWORD EntriesRead;
			#   [size_is(EntriesRead)] LPSHARE_INFO_502_I Buffer;
			# } SHARE_INFO_502_CONTAINER,
			ctr = x.unpack_pointer()
			ptr = x.unpack_pointer()
			count = x.unpack_long()
			buffer = x.unpack_pointer()
		
		preferdmaxlen = x.unpack_long()
		
		# ResumeHandle
		resumehandleptr = x.unpack_pointer()
		resumehandle = 0
		if resumehandleptr != 0:
			resumehandle = x.unpack_long()
		
		print("srvsvc_handle_ref %x srvsvc_handle %s infostruct_level %i count %i buffer %x preferdmaxlen %i  resumehandleptr %x resumehandle %i" % (
			srvsvc_handle_ref,
			srvsvc_handle,
			infostruct_level,
			count,
			buffer,
			preferdmaxlen,
			resumehandleptr,
			resumehandle) )


		# compile reply
		r = ndrlib.Packer()
		r.pack_long(infostruct_level)

		# 2.2.4.33 SHARE_INFO_1_CONTAINER

		if infostruct_level == 1:
		
			# EntriesRead
			r.pack_long(1)
			r.pack_pointer(0x23456)
		
			# 2.2.4.23 SHARE_INFO_1
			# 
			# http://msdn.microsoft.com/en-us/library/cc247147%28PROT.10%29.aspx
			# 
			# typedef struct _SHARE_INFO_1 {
			#   [string] wchar_t* shi1_netname;
			#   DWORD shi1_type;
			#   [string] wchar_t* shi1_remark;
			# } SHARE_INFO_1, 
			#  *PSHARE_INFO_1, 
			#  *LPSHARE_INFO_1;
		
			# http://msdn.microsoft.com/en-us/library/cc247150%28PROT.10%29.aspx

			# Count
			r.pack_long(2)

			# pointer 
			r.pack_pointer(0x99999)

			# Max Count
			r.pack_long(2)

			# Buffer[0]
			r.pack_pointer(0x34567)
			r.pack_long(0x00000000) # STYPE_DISKTREE
			r.pack_pointer(0x45678)
		
			# Buffer[0]
			r.pack_pointer(0x343567)
			r.pack_long(0x00000000) # STYPE_DISKTREE
			r.pack_pointer(0x45678)

			r.pack_string('test\0'.encode('utf16')[2:])
			r.pack_string('es geht test\0'.encode('utf16')[2:])

			r.pack_string('test2\0'.encode('utf16')[2:])
			r.pack_string('es geht test\0'.encode('utf16')[2:])

			
		if infostruct_level == 502:

			# EntriesRead
			r.pack_long(502)
			r.pack_pointer(0x23456)

			# 2.2.4.26 SHARE_INFO_502_I
			#
			# http://msdn.microsoft.com/en-us/library/cc247150%28v=PROT.13%29.aspx
			#
			# typedef struct _SHARE_INFO_502_I {
			#  [string] WCHAR* shi502_netname;
			#  DWORD shi502_type;
			#  [string] WCHAR* shi502_remark;
			#  DWORD shi502_permissions;
			#  DWORD shi502_max_uses;
			#  DWORD shi502_current_uses;
			#  [string] WCHAR* shi502_path;
			#  [string] WCHAR* shi502_passwd;
			#  DWORD shi502_reserved;
			#  [size_is(shi502_reserved)] unsigned char* shi502_security_descriptor;
			#} SHARE_INFO_502_I, 
			# *PSHARE_INFO_502_I, 
			# *LPSHARE_INFO_502_I;

			# Count
			r.pack_long(2)

			# pointer 
			r.pack_pointer(0x99999)

			# Max Count
			r.pack_long(2)

			# Buffer[0]
			r.pack_pointer(0x34567)
			r.pack_long(0x00000000) # STYPE_DISKTREE
			r.pack_pointer(0x45678) # remark
			r.pack_long(0)		# permissions
			r.pack_long(0xffffffff) # max_uses
			r.pack_long(1)		# current_uses
			r.pack_pointer(0x78654) # path
			r.pack_pointer(0) 	# passwd
			r.pack_long(0) 		# reserved
			r.pack_pointer(0)	# security descriptor

			# Buffer[1]
			r.pack_pointer(0x343567)
			r.pack_long(0x00000000) # STYPE_DISKTREE
			r.pack_pointer(0x45678)
			r.pack_long(0)
			r.pack_long(0xffffffff)
			r.pack_long(1)
			r.pack_pointer(0x78654)
			r.pack_pointer(0)
			r.pack_long(0)
			r.pack_pointer(0)

			r.pack_string_fix('test\0'.encode('utf16')[2:])
			r.pack_string_fix('es geht test\0'.encode('utf16')[2:])
			r.pack_string_fix('C:\0'.encode('utf16')[2:])

			r.pack_string_fix('test2\0'.encode('utf16')[2:])
			r.pack_string_fix('es geht test\0'.encode('utf16')[2:])
			r.pack_string_fix('C:\WINDOWS\0'.encode('utf16')[2:])

		# total entries
		r.pack_long(2)

		# resume handle
		r.pack_pointer(0x47123123)		
		r.pack_long(0)

		r.pack_long(0)
		return r.get_buffer()



	@classmethod
	def handle_NetPathCanonicalize(cls, p):
		# MS08-067
		#	WERROR srvsvc_NetPathCanonicalize(
		#		[in,unique]   [string,charset(UTF16)] uint16 *server_unc,
		#		[in]   [string,charset(UTF16)] uint16 path[],
		#		[out]  [size_is(maxbuf)] uint8 can_path[],
		#		[in]   uint32 maxbuf,
		#		[in]   [string,charset(UTF16)] uint16 prefix[],
		#		[in,out,ref] uint32 *pathtype,
		#		[in]    uint32 pathflags
		#		);
		x = ndrlib.Unpacker(p.StubData)
		ref        = x.unpack_pointer()
		server_unc = x.unpack_string()
		path       = x.unpack_string()
		maxbuf     = x.unpack_long()
		prefix     = x.unpack_string()
		pathtype   = x.unpack_long()
		pathflags  = x.unpack_long()
		print("ref 0x%x server_unc %s path %s maxbuf %s prefix %s pathtype %i pathflags %i" % (ref, server_unc, path, maxbuf, prefix, pathtype, pathflags))

		r = ndrlib.Packer()
#		r.pack_long(pathflags)
#		r.pack_long(0)
#		r.pack_long(0)
		r.pack_long(pathtype)
		r.pack_long(0)
		r.pack_string(path)
		

		return r.get_buffer()

	@classmethod
	def handle_NetPathCompare(cls, p):
		# MS08-067
		#	WERROR srvsvc_NetPathCompare(
		#		[in,unique]   [string,charset(UTF16)] uint16 *server_unc,
		#		[in]   [string,charset(UTF16)] uint16 path1[],
		#		[in]   [string,charset(UTF16)] uint16 path2[],
		#		[in]    uint32 pathtype,
		#		[in]    uint32 pathflags
		#		);
		p = ndrlib.Unpacker(p.StubData)
		ref        = p.unpack_pointer()
		server_unc = p.unpack_string()
		path1       = p.unpack_string()
		path2     = p.unpack_string()
		pathtype   = p.unpack_long()
		pathflags  = p.unpack_long()
		print("ref 0x%x server_unc %s path1 %s path2 %s pathtype %i pathflags %i" % (ref, server_unc, path1.decode('utf-16'), path2.decode('utf-16'), pathtype, pathflags))
		r = ndrlib.Packer()
		x = (path1 > path2) - (path1 < path2) 
		if x < 0:
			r.pack_long( 0 )
		else:
			r.pack_long( 0 )
#		r.pack_long( x )
		return r.get_buffer()

	@classmethod
	def handle_NetShareAdd(cls, p):
		#3.1.4.7 NetrShareAdd (Opnum 14)
		#
		#http://msdn.microsoft.com/en-us/library/cc247275%28v=PROT.10%29.aspx
		#
		#NET_API_STATUS NetrShareAdd(
  		#[in, string, unique] SRVSVC_HANDLE ServerName,
		#  [in] DWORD Level,
		#  [in, switch_is(Level)] LPSHARE_INFO InfoStruct,
		#  [in, out, unique] DWORD* ParmErr
		#);
		p = ndrlib.Unpacker(p.StubData)
		srvsvc_handle_ref = p.unpack_pointer()
		srvsvc_handle = p.unpack_string()
		infostruct_level = p.unpack_long()
		infostruct_share = p.unpack_long()

		#2.2.4.24 SHARE_INFO_2
		#
		#http://msdn.microsoft.com/en-us/library/cc247148%28v=PROT.13%29.aspx
		#
		#typedef struct _SHARE_INFO_2 {
		#  [string] wchar_t* shi2_netname;
		#  DWORD shi2_type;
		#  [string] wchar_t* shi2_remark;
		#  DWORD shi2_permissions;
		#  DWORD shi2_max_uses;
		#  DWORD shi2_current_uses;
		#  [string] wchar_t* shi2_path;
		#  [string] wchar_t* shi2_passwd;
		#} SHARE_INFO_2

		if infostruct_share == 2:
			ref = p.unpack_pointer()
			netname = p.unpack_pointer()
			sharetype = p.unpack_long()
			remark = p.unpack_long()
			permission = p.unpack_long()
			max_use = p.unpack_long()
			current_use = p.unpack_long()
			path = p.unpack_pointer()
			passwd = p.unpack_pointer()
			share_name = p.unpack_string()
			share_comment = p.unpack_string()
			share_path = p.unpack_string()
		
		ptr_parm = p.unpack_pointer()
		error = p.unpack_long()

		r = ndrlib.Packer()
		r.pack_pointer(0x324567)
		r.pack_long(0)
		r.pack_long(0)
		return r.get_buffer()

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




