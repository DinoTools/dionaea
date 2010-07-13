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
from time import time, localtime, altzone

from dionaea import ndrlib
from .include.smbfields import DCERPC_Header, DCERPC_Response

rpclog = logging.getLogger('rpcservices')


class DCERPCValueError(Exception):
	"""Raised when an a value is passed to a dcerpc operation which is invalid"""

	def __init__(self, varname, reason, value):
		self.varname = varname
		self.reason = reason
		self.value = value
	def __str__(self):
		return "%s is %s (%s)" % (self.varname, self.reason, self.value)


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

				try:
					data = method(p)
				except DCERPCValueError as e:
					rpclog.warn("DCERPCValueError %s" % e)
					return None

				if data is None:
					data = b''
				r.StubData = data
				r.AllocHint = len(data)
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

class RPC_C_AUTHN:
	# http://msdn.microsoft.com/en-us/library/ms692656%28VS.85%29.aspx
	# seems globally used
	NONE = 0
	DCE_PRIVATE = 1
	DCE_PUBLIC = 2
	DEC_PUBLIC = 4
	GSS_NEGOTIATE = 9
	WINNT = 10
	GSS_SCHANNEL = 14
	GSS_KERBEROS = 16
	DEFAULT = 0xFFFFFFFF

class NCACN:
	# http://www.opengroup.org/onlinepubs/9692999399/apdxi.htm#tagtcjh_51
	UDP =8
	IP = 9

class IOXIDResolver(RPCService):
	"""[MS-DCOM]: Distributed Component Object Model (DCOM) Remote Protocol Specification

	http://msdn.microsoft.com/en-us/library/cc226801%28PROT.10%29.aspx"""


	uuid = UUID('99fcfec4-5260-101b-bbcb-00aa0021347a').hex
	ops = {
		0x5: "ServerAlive2"
	}

	class COMVERSION:
		# typedef struct tagCOMVERSION {
		# 	unsigned short MajorVersion;
		# 	unsigned short MinorVersion;
		# } COMVERSION;

		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.MajorVersion = 5
				self.MinorVersion = 7

		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_short(self.MajorVersion)
				self.__packer.pack_short(self.MinorVersion)

		def size(self):
			return 4

	class DUALSTRINGARRAY:
		# 2.2.1.19.2 DUALSTRINGARRAY
		# 
		# http://msdn.microsoft.com/en-us/library/cc226841%28PROT.10%29.aspx
		# 
		# typedef struct tagDUALSTRINGARRAY {
		# 	unsigned short wNumEntries;
		# 	unsigned short wSecurityOffset;
		# 	[size_is(wNumEntries)] unsigned short aStringArray[];
		# } DUALSTRINGARRAY;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.NumEntries = 0
				self.SecurityOffset = 0
				self.StringArray = []

		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.NumEntries=self.SecurityOffset=0
				for x in self.StringArray:
					print("x %s %i" % (x, x.size()))
					xs = x.size()
					if isinstance(x, IOXIDResolver.STRINGBINDING):
						self.SecurityOffset += xs
					self.NumEntries += xs
				self.__packer.pack_short(int((self.NumEntries+4)/2))
				self.__packer.pack_short(int((self.SecurityOffset+2)/2))

				for i in self.StringArray:
					if isinstance(i, IOXIDResolver.STRINGBINDING):
						i.pack()
				self.__packer.pack_raw(b'\0\0')

				for i in self.StringArray:
					if isinstance(i, IOXIDResolver.SECURITYBINDING):
						i.pack()
				self.__packer.pack_raw(b'\0\0')
				

		def size(self):
			return 2 + 2 + sum([x.size() for x in self.StringArray]) + 2 + 2

					
	class STRINGBINDING:
		# 2.2.1.19.3 STRINGBINDING
		# 
		# http://msdn.microsoft.com/en-us/library/cc226838%28PROT.10%29.aspx
		# 
		# fixmetypdef struct {
		# 	unsigned short wTowerId
		# 	char *aNetworkAddr
		# } STRINGBINDING;
		#
		# TowerId -> http://www.opengroup.org/onlinepubs/9692999399/apdxi.htm#tagcjh_28

			
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.TowerId = NCACN.IP 
				self.NetworkAddr = ''

		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_short(self.TowerId)
				self.__packer.pack_raw(self.NetworkAddr.encode('utf16')[2:])
				self.__packer.pack_raw(b'\0\0')

		def size(self):
			return 2 + len(self.NetworkAddr.encode('utf16')[2:]) + 2

	class SECURITYBINDING:
		# 2.2.1.19.4 SECURITYBINDING
		# 
		# http://msdn.microsoft.com/en-us/library/cc226839%28PROT.10%29.aspx
		# 
		# fixmetypedef struct {
		# 	unsigned short wAuthnSvc
		#	unsigned short Reserved
		#	wchar_t aPrincName

		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.AuthnSvc = RPC_C_AUTHN.GSS_NEGOTIATE
				self.Reserved = 0xffff
				self.PrincName = 'none'

		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_short(self.AuthnSvc)
				if self.AuthnSvc != RPC_C_AUTHN.NONE:
					self.__packer.pack_short(self.Reserved)
					self.__packer.pack_raw(self.PrincName.encode('utf16')[2:])
					self.__packer.pack_raw(b'\0\0')

		def size(self):
			return 2 + 2 + len(self.PrincName.encode('utf16')[2:]) + 2

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

		# prepare values

		ComVersion = IOXIDResolver.COMVERSION(p)

		# the DUALSTRINGARRAY
		dsa = IOXIDResolver.DUALSTRINGARRAY(p)

		s = IOXIDResolver.STRINGBINDING(p)
		s.NetworkAddr = '127.0.0.1'
		dsa.StringArray.append(s)

		s = IOXIDResolver.STRINGBINDING(p)
		s.NetworkAddr = '127.0.0.2'
		dsa.StringArray.append(s)

		s = IOXIDResolver.SECURITYBINDING(p)
		s.AuthnSvc = RPC_C_AUTHN.GSS_NEGOTIATE
		s.PrincName = "OEMCOMPUTER"	# fixme: config value?
		dsa.StringArray.append(s)
		
		# we are done, pack it

		# ComVersion
		ComVersion.pack()

		# pointer to DUALSTRINGARRAY
		p.pack_pointer(0x200008)

		# DUALSTRINGARRAY size
		p.pack_long(int(dsa.size()/2))

		# DUALSTRINGARRAY
		dsa.pack()
				
		# reserved
		p.pack_pointer(0x4711)
		p.pack_long(0)
		
		return p.get_buffer()


class llsrpc(RPCService):
	uuid = UUID('342cfd40-3c6c-11ce-a893-08002b2e9c6d').hex


class lsarpc(RPCService):
	uuid = UUID('12345778-1234-abcd-ef00-0123456789ab').hex

	class LSAPR_HANDLE:
		# 2.2.2.1 LSAPR_HANDLE
		#
		# http://msdn.microsoft.com/en-us/library/cc234257%28v=PROT.10%29.aspx
		#
		#typedef [context_handle] void* LSAPR_HANDLE;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Handle = b''
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Value = p.unpack_raw(20)
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_raw(self.Handle)

	class LSAPR_OBJECT_ATTRIBUTES:
		# 2.2.9 LSAPR_OBJECT_ATTRIBUTES
		#
		#http://help.outlook.com/en-us/140/cc234450%28PROT.10%29.aspx
		#
		#typedef struct _LSAPR_OBJECT_ATTRIBUTES {
		#  unsigned long Length;
		#  unsigned char* RootDirectory;
		#  PSTRING ObjectName;
		#  unsigned long Attributes;
		#  PLSAPR_SECURITY_DESCRIPTOR SecurityDescriptor;
		#  PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
		#} LSAPR_OBJECT_ATTRIBUTES, 
		# *PLSAPR_OBJECT_ATTRIBUTES;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				pass
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Length = self.__packer.unpack_long()
				print("Length = %i" % self.Length)
				self.RootDirectory = self.__packer.unpack_short()
				print("RootDirectory = %x" % self.RootDirectory)
				self.ObjectName = self.__packer.unpack_pointer()
				print("ObjectName = %x" % self.ObjectName)
				self.Attributes = self.__packer.unpack_long()
				self.SecurityDescriptor = self.__packer.unpack_pointer()
				self.SecurityQualityOfService = self.__packer.unpack_pointer()

	class LSA_TRANSLATED_SID:
		#http://msdn.microsoft.com/en-us/library/dd424381.aspx
		#
		#typedef struct {
		#  SID_NAME_USE Use;
		#  ULONG RelativeId;
		#  LONG DomainIndex;
		#} LSA_TRANSLATED_SID, 
		# *PLSA_TRANSLATED_SID;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Use = 0
				self.RelativeId = 0
				self.DomainIndex = 0
			elif isinstance(self.__packer,ndrlib.Unpacker):
				pass
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_short(self.Use)
				self.__packer.pack_long(self.RelativeId)
				self.__packer.pack_long(self.DomainIndex)
				# unknown
				self.__packer.pack_long(0)

	class LSAPR_TRANSLATED_SIDS:
		# 2.2.15 LSAPR_TRANSLATED_SIDS
		#
		#http://msdn.microsoft.com/en-us/library/cc234457%28PROT.10%29.aspx
		#
		#typedef struct _LSAPR_TRANSLATED_SIDS {
		#  [range(0,1000)] unsigned long Entries;
		#  [size_is(Entries)] PLSA_TRANSLATED_SID Sids;
		#} LSAPR_TRANSLATED_SIDS, 
		# *PLSAPR_TRANSLATED_SIDS;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Entries = 0
				self.Pointer = 0x3456
				self.MaxCount = 0
				self.Data = []
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Entries = self.__packer.unpack_long()
				print("Entries = %i" % self.Entries)
				self.Pointer = self.__packer.unpack_pointer()
				self.MaxCount = self.__packer.unpack_long()
				if self.Entries != 0:
					Sids = LSA_TRANSLATED_SID(self.__packer)
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_long(self.Entries)
				print("Entries = %i" % self.Entries)
				self.__packer.pack_pointer(self.Pointer)
				self.__packer.pack_long(self.Entries)
				for i in range(self.Entries):
					Sids = lsarpc.LSA_TRANSLATED_SID(self.__packer)
					Sids.pack()
									

	class LSAPR_TRUST_INFORMATION:
		#2.2.11 LSAPR_TRUST_INFORMATION
		#
		#http://msdn.microsoft.com/en-us/library/cc234452%28PROT.10%29.aspx
		#
		#typedef struct _LSAPR_TRUST_INFORMATION {
		#  RPC_UNICODE_STRING Name;
		#  PRPC_SID Sid;
		#} LSAPR_TRUST_INFORMATION, 
		# *PLSAPR_TRUST_INFORMATION;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Name = []
				self.Entries = 0
				self.RelativeId = 0
				self.Pointer = 0x11
			elif isinstance(self.__packer,ndrlib.Unpacker):
				pass
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				# MaxCount,needed as the element of NDR array
				self.__packer.pack_long(self.Entries)
				
				#  RPC_UNICODE_STRING Name;
				for i in range(self.Entries): 				
					b = samr.RPC_UNICODE_STRING(self.__packer)
					b.Data = self.Name[i]
					b.pack()
				# Pointer to RPC_UNICODE_STRING buffer
				self.__packer.pack_long(self.Pointer)
				# Pointer to RPC_SID buffer
				self.__packer.pack_long(self.Pointer)
				for j in range(self.Entries):
					self.__packer.pack_string(self.Name[j].encode('utf16')[2:])
				#  PRPC_SID Sid	;
				sid = samr.RPC_SID(self.__packer)
				sid.Value = 'NT_AUTHORITY'
				sid.SubAuthority = ['32','544']
				sid.SubAuthorityCount = len(sid.SubAuthority)
				
				# Maxcount, needed as the element of NDR array
				self.__packer.pack_long(sid.SubAuthorityCount)
				sid.pack()


	class LSAPR_REFERENCED_DOMAIN_LIST:
		# 2.2.12 LSAPR_REFERENCED_DOMAIN_LIST
		#
		#http://msdn.microsoft.com/en-us/library/cc234453%28PROT.13%29.aspx
		#
		#typedef struct _LSAPR_REFERENCED_DOMAIN_LIST {
		#  unsigned long Entries;
		#  [size_is(Entries)] PLSAPR_TRUST_INFORMATION Domains;
		#  unsigned long MaxEntries;
		#} LSAPR_REFERENCED_DOMAIN_LIST, 
		# *PLSAPR_REFERENCED_DOMAIN_LIST;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Entries = 0
				self.MaxEntries = 0
				self.Data = []
				self.Pointer = 0x4567
			elif isinstance(self.__packer,ndrlib.Unpacker):
				pass
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_long(self.Entries)
				for i in range(self.Entries):
					# Pointer
					self.__packer.pack_long(self.Pointer)
					# MaxEntries
					self.__packer.pack_long(0)
					Domains = lsarpc.LSAPR_TRUST_INFORMATION(self.__packer)
					Domains.Name = self.Data
					Domains.Entries = self.Entries
					Domains.pack()

	class LSAPR_SID_INFORMATION:
		# 2.2.17 LSAPR_SID_INFORMATION
		#
		# http://msdn.microsoft.com/en-us/library/cc234459%28v=PROT.10%29.aspx
		#
		#typedef struct _LSAPR_SID_INFORMATION {
		#  PRPC_SID Sid;
		#} LSAPR_SID_INFORMATION, 
		# *PLSAPR_SID_INFORMATION
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				pass
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Count = self.__packer.unpack_long()
				Sid = samr.RPC_SID(self.__packer)
		def pack(self):
			if isinstance(self.__packer, ndrlib.Packer):
				pass

	class LSAPR_SID_ENUM_BUFFER:
		# 2.2.18 LSAPR_SID_ENUM_BUFFER
		# 
		# http://msdn.microsoft.com/en-us/library/cc234460%28PROT.10%29.aspx
		# 
		#typedef struct _LSAPR_SID_ENUM_BUFFER {
		#  [range(0,20480)] unsigned long Entries;
		#  [size_is(Entries)] PLSAPR_SID_INFORMATION SidInfo;
		#} LSAPR_SID_ENUM_BUFFER, 
		# *PLSAPR_SID_ENUM_BUFFER;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				pass
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Entries = self.__packer.unpack_long()
				self.Pointer = self.__packer.unpack_pointer()
				self.MaxCount = self.__packer.unpack_long()
				for i in range(self.MaxCount):
					self.Reference = self.__packer.unpack_pointer()
				for j in range(self.MaxCount):
					SidInfo = lsarpc.LSAPR_SID_INFORMATION(self.__packer)

		def pack(self):
			if isinstance(self.__packer, ndrlib.Packer):
				pass
				
	class LSAPR_TRANSLATED_NAME_EX:
		#2.2.21 LSAPR_TRANSLATED_NAME_EX
		#
		#http://msdn.microsoft.com/en-us/library/cc234463%28v=PROT.13%29.aspx
		#
		#typedef struct _LSAPR_TRANSLATED_NAME_EX {
		#  SID_NAME_USE Use;
		#  RPC_UNICODE_STRING Name;
		#  long DomainIndex;
		#  unsigned long Flags;
		#} LSAPR_TRANSLATED_NAME_EX, 
		# *PLSAPR_TRANSLATED_NAME_EX;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				#2.2.13 SID_NAME_USE
				#http://msdn.microsoft.com/en-us/library/cc234454%28v=PROT.13%29.aspx
				self.Use = 8 #SidTypeUnknown
				self.Flags = 0
				self.DomainIndex = 0
				self.Data = []
				self.Pointer = 0x11
				self.Entries = 0
			elif isinstance(self.__packer,ndrlib.Unpacker):
				pass
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				for i in range(self.Entries):
					self.__packer.pack_short(self.Use)
					Name = samr.RPC_UNICODE_STRING(self.__packer)
					# Empty String
					Name.Data = self.Data
					self.__packer.pack_pointer(0x00)
					Name.pack()	
					self.__packer.pack_long(self.DomainIndex)
					self.__packer.pack_long(self.Flags)


	class LSAPR_TRANSLATED_NAMES_EX:
		#2.2.22 LSAPR_TRANSLATED_NAMES_EX
		#
		#http://msdn.microsoft.com/en-us/library/cc234464%28PROT.13%29.aspx
		#
		#typedef struct _LSAPR_TRANSLATED_NAMES_EX {
		#  [range(0,20480)] unsigned long Entries;
		#  [size_is(Entries)] PLSAPR_TRANSLATED_NAME_EX Names;
		#} LSAPR_TRANSLATED_NAMES_EX, 
		# *PLSAPR_TRANSLATED_NAMES_EX;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Entries = 0
				self.Data = []
				self.Pointer = 0x6879
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Entries = self.__packer.unpack_long()
				self.Pointer = self.__packer.unpack_pointer()
				if self.Entries != 0:
					Sids = LSA_TRANSLATED_Name_EX(self.__packer)
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_long(self.Entries)
				self.__packer.pack_pointer(self.Pointer)
				self.__packer.pack_long(self.Entries)
				Names = lsarpc.LSAPR_TRANSLATED_NAME_EX(self.__packer)
				Names.Entries = self.Entries
				Names.pack()
			
	ops = {
		0: "Close",
		44: "OpenPolicy",
		57: "LookupSids2",
		58: "LookupNames2"
	}

	@classmethod
	def handle_OpenPolicy(cls,p):
		# 3.1.4.4.1 LsarOpenPolicy2 (Opnum 44)
		#
		# http://msdn.microsoft.com/en-us/library/cc234337%28PROT.10%29.aspx
		#
		#NTSTATUS LsarOpenPolicy2(
		#  [in, unique, string] wchar_t* SystemName,
		#  [in] PLSAPR_OBJECT_ATTRIBUTES ObjectAttributes,
		#  [in] ACCESS_MASK DesiredAccess,
		#  [out] LSAPR_HANDLE* PolicyHandle
		#);

		x = ndrlib.Unpacker(p.StubData)
		PSystemName = x.unpack_pointer()
		SystemName = x.unpack_string()
		print("ServerName %s" % SystemName)

		ObjectAttributes = lsarpc.LSAPR_OBJECT_ATTRIBUTES(x)
		DesiredAccess = x.unpack_long()

		r = ndrlib.Packer()
		PolicyHandle = lsarpc.LSAPR_HANDLE(r)
		PolicyHandle.Handle = b'01234567890123456789'
		PolicyHandle.pack()

		# return 
		r.pack_long(0)

		return r.get_buffer()

	@classmethod
	def handle_LookupNames2(cls,p):
		# 3.1.4.7 LsarLookupNames2 (Opnum 58)
		#
		# http://msdn.microsoft.com/en-us/library/cc234494%28PROT.13%29.aspx
		#
		#NTSTATUS LsarLookupNames2(
		#  [in] LSAPR_HANDLE PolicyHandle,
		#  [in, range(0,1000)] unsigned long Count,
		#  [in, size_is(Count)] PRPC_UNICODE_STRING Names,
		#  [out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
		#  [in, out] PLSAPR_TRANSLATED_SIDS_EX TranslatedSids,
		#  [in] LSAP_LOOKUP_LEVEL LookupLevel,
		#  [in, out] unsigned long* MappedCount,
		#  [in] unsigned long LookupOptions,
		#  [in] unsigned long ClientRevision
		#);

		x = ndrlib.Unpacker(p.StubData)
		PolicyHandle = lsarpc.LSAPR_HANDLE(x)
		Count = x.unpack_long()

		# Maxcount, needed as the element of NDR array
		MaxCount = x.unpack_long()
		Names = samr.RPC_UNICODE_STRING(x,MaxCount)
		TranslatedSids = lsarpc.LSAPR_TRANSLATED_SIDS(x)

		LookupLevel = x.unpack_short()
		MappedCount = x.unpack_long()
		LookupOptions = x.unpack_long()
		ClientRevision = x.unpack_long()

		r = ndrlib.Packer()
		r.pack_pointer(0x23456)
		
		ReferenceDomains = lsarpc.LSAPR_REFERENCED_DOMAIN_LIST(r)
		ReferenceDomains.Data = ['HOMEUSER-3AF6FE']
		ReferenceDomains.Entries = len(ReferenceDomains.Data)
		ReferenceDomains.pack()

		Sids = lsarpc.LSAPR_TRANSLATED_SIDS(r)
		Sids.Entries = Count
		Sids.pack()

		# MappedCount 
		r.pack_long(3)
		# Return
		r.pack_pointer(0x00000107) #STATUS_SOME_NOT_MAPPED

		return r.get_buffer()

	@classmethod
	def handle_LookupSids2(cls,p):
		# 3.1.4.10 LsarLookupSids2 (Opnum 57)
		#
		# http://msdn.microsoft.com/en-us/library/cc234487%28PROT.13%29.aspx
		#
		#NTSTATUS LsarLookupSids2(
		#  [in] LSAPR_HANDLE PolicyHandle,
		#  [in] PLSAPR_SID_ENUM_BUFFER SidEnumBuffer,
		#  [out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
		#  [in, out] PLSAPR_TRANSLATED_NAMES_EX TranslatedNames,
		#  [in] LSAP_LOOKUP_LEVEL LookupLevel,
		#  [in, out] unsigned long* MappedCount,
		#  [in] unsigned long LookupOptions,
		#  [in] unsigned long ClientRevision
		#);

		x = ndrlib.Unpacker(p.StubData)
		PolicyHandle = lsarpc.LSAPR_HANDLE(x)
		SidEnumBuffer = lsarpc.LSAPR_SID_ENUM_BUFFER(x)
		print("EntriesRead = %i" % SidEnumBuffer.Entries)
		TranslatedNames = lsarpc.LSAPR_TRANSLATED_NAMES_EX(x)
		
		LookupLevel = x.unpack_short()
		MappedCount = x.unpack_long()
		LookupOptions = x.unpack_long()
		ClientRevision = x.unpack_long()
		print ("LookupLevel %i MappedCount %i LookupOptions %i ClientRevision %i" %(LookupLevel,MappedCount,LookupOptions,ClientRevision))
		
		r = ndrlib.Packer()
		r.pack_pointer(0x23456)
		
		ReferenceDomains = lsarpc.LSAPR_REFERENCED_DOMAIN_LIST(r)
		ReferenceDomains.Data = ['HOMEUSER-3AF6FE']
		ReferenceDomains.Entries = len(ReferenceDomains.Data)
		ReferenceDomains.pack()

		# Nmap smb-enum-users.nse scanning will simply return none of the element has translated, ugly but it works for the moment
		TranslatedNames = lsarpc.LSAPR_TRANSLATED_NAMES_EX(r)
		TranslatedNames.Entries = SidEnumBuffer.Entries
		TranslatedNames.pack()

		# return 
		r.pack_long(0)
		r.pack_pointer(0xc0000073) #STATUS_NONE_MAPPED

		return r.get_buffer()
	
	@classmethod
	def handle_Close(cls,p):
		#3.1.4.3 LsarClose (Opnum 0)
		#
		#http://msdn.microsoft.com/en-us/library/cc234490%28v=PROT.13%29.aspx
		#
		#NTSTATUS LsarClose(
		#  [in, out] LSAPR_HANDLE* ObjectHandle
		#);
		x = ndrlib.Unpacker(p.StubData)
		ObjectHandle = lsarpc.LSAPR_HANDLE(x)
		print("ObjectHandle %s" % ObjectHandle)
		
		r = ndrlib.Packer()
		s = lsarpc.LSAPR_HANDLE(r)
		s.Handle =  b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
		s.pack()
		r.pack_long(0)

		return r.get_buffer()


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
	""" Remote Management Interface
	http://www.opengroup.org/onlinepubs/9629399/apdxq.htm """

	uuid = UUID('afa8bd80-7d8a-11c9-bef4-08002b102989').hex
	ops = { 
		0 : "inq_if_ids",
		1 : "inq_stats",
		2 : "is_server_listening",
		3 : "stop_server_listening",
		4 : "inq_princ_name"
	}
# As I lack a way to verify the code, this is commented, maybe samba4 smbtorture can help out
	class handle_t:
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				pass
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.handle = self.__packer.unpack_short()

	class uuid_t:
		# typedef struct {
		# 	unsigned32          time_low;
		# 	unsigned16          time_mid;
		# 	unsigned16          time_hi_and_version;
		# 	unsigned8           clock_seq_hi_and_reserved;
		# 	unsigned8           clock_seq_low;
		# 	byte                node[6];
		# } uuid_t, *uuid_p_t;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer = p
				self.time_low = 0
				self.time_mid = 1
				self.time_hi_and_version = 2
				self.clock_seq_hi_and_reserved = 3
				self.clock_seq_low = 4
				self.node = b"56789a"

		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_long(self.time_low)
				self.__packer.pack_short(self.time_mid)
				self.__packer.pack_short(self.time_hi_and_version)
				self.__packer.pack_small(self.clock_seq_hi_and_reserved)
				self.__packer.pack_small(self.clock_seq_low)
				self.__packer.pack_raw(self.node)
		def __str__(self):
			return "123455"

	class rpc_if_id_t:
		# typedef struct {
		# 	uuid_t                  uuid;
		# 	unsigned16              vers_major;
		# 	unsigned16              vers_minor;
		# } rpc_if_id_t;
		# typedef [ptr] rpc_if_id_t *rpc_if_id_p_t;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.uuid = MGMT.uuid_t(p)
				self.vers_major = 0
				self.vers_minor = 1
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.uuid.pack()
				self.__packer.pack_short(self.vers_major)
				self.__packer.pack_short(self.vers_minor)
		def show(self):
			print("uuid %s %i.%i" % (self.uuid, self.vers_major, self.vers_minor))

	class rpc_if_id_vector_t:
		# typedef struct {
		# 	unsigned32              count;
		# 	[size_is(count)]
		# 	rpc_if_id_p_t           if_id[*];
		# } rpc_if_id_vector_t;
		# typedef [ptr] rpc_if_id_vector_t *rpc_if_id_vector_p_t;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.count = 0
				self.if_id = []
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.count = len(self.if_id)
				self.__packer.pack_long(self.count)
				self.__packer.pack_long(self.count) # maybe array size?
				# pointers ...
				for i in self.if_id:
					self.__packer.pack_pointer(65)
				# the if_id_vectors
				for i in self.if_id:
					i.pack()

		def show(self, indent=0):
			print("rpc_if_id_vector_t")
			print("count %i", len(self.if_id))
			for i in self.if_id:
				i.show()
	@classmethod
	def handle_inq_if_ids(cls, p):
		# 
		# void rpc__mgmt_inq_if_ids
		# (
		# 	[in]        handle_t                binding_handle,
		# 	[out]       rpc_if_id_vector_p_t    *if_id_vector,
		# 	[out]       error_status_t          *status
		# );
		r = ndrlib.Packer()
		r.pack_pointer(0x4747)
		v = MGMT.rpc_if_id_vector_t(r)
		v.if_id.append(MGMT.rpc_if_id_t(r))
		v.show()
		v.pack()
		r.pack_long(0) # return value
		return r.get_buffer()

	@classmethod
	def handle_inq_stats(cls, p):
		pass

	@classmethod
	def handle_is_server_listening(cls, p):
		pass

	@classmethod
	def handle_stop_server_listening(cls, p):
		pass

	@classmethod
	def handle_inq_princ_name(cls, p):
		# void rpc__mgmt_inq_princ_name
		# (
		#     [in]        handle_t                binding_handle,
		#     [in]        unsigned32              authn_proto,
		#     [in]        unsigned32              princ_name_size,
		#     [out, string, size_is(princ_name_size)]       
		#                 char                    princ_name[],
		#     [out]       error_status_t          *status
		# );
		x = ndrlib.Unpacker(p.StubData)
		handle = MGMT.handle_t(x)
#		authn_proto = x.unpack_long()
#		princ_name_size = x.unpack_long()

		r = ndrlib.Packer()
		r.pack_string(b"oemcomputer")
#		r.pack_long(0)
#		r.pack_long(0)
		return r.get_buffer()




		
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
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Handle = b''
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Value = p.unpack_raw(20)
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_raw(self.Handle)

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
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Value = ''
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Value = self.__packer.unpack_raw(6)
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				if not self.SID_AUTHORITY.get(self.Value) == None:
					self.__packer.pack_raw(self.SID_AUTHORITY[self.Value])
				

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
		def __init__(self, p):
			self.__packer = p
			if isinstance(p,ndrlib.Packer):
				self.Value = ''
				self.Revision = 1 # must be 0x01
				self.SubAuthorityCount = 0
				self.SubAuthority = []
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Revision = self.__packer.unpack_small()
				self.SubAuthorityCount = self.__packer.unpack_small()
				self.IdentifierAuthority = samr.RPC_SID_IDENTIFIER_AUTHORITY(self.__packer)
				self.SubAuthority = []
				for i in range(self.SubAuthorityCount):
					self.SubAuthority.append(p.unpack_long())
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				# Revision
				self.__packer.pack_small(self.Revision)

				# SubAuthorityCount
				self.__packer.pack_small(self.SubAuthorityCount)

				# RPC_SID_IDENTIFIER_AUTHORITY
				b = samr.RPC_SID_IDENTIFIER_AUTHORITY(self.__packer)
				b.Value = self.Value
				b.pack()

				# SubAuthority
				for i in range(self.SubAuthorityCount):
					self.__packer.pack_long(int(self.SubAuthority[i]))

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
		def __init__(self, p, c=1):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Data =[]
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Count = c #specify how many string array
				print("Count = %i" % self.Count)
				for i in range(self.Count):
					self.Length = self.__packer.unpack_short()
					self.MaximumLength = self.__packer.unpack_short()
					self.Reference = self.__packer.unpack_pointer()
				for j in range(self.Count):
					self.Buffer = self.__packer.unpack_string()
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_rpc_unicode_string(self.Data)


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
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Name = []
				self.RelativeId = 0
				self.Pointer = 0x11
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.RelativeId = self.__packer.unpack_long()
				self.Name = RPC_UNICODE_STRING(self.__packer, Name)
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				for i in range(len(self.Name)): 				
					#RelativeID
					self.__packer.pack_long(self.RelativeId)

					b = samr.RPC_UNICODE_STRING(self.__packer)
					b.Data = self.Name[i]
					b.pack()
					self.__packer.pack_pointer(self.Pointer)

				for j in range(len(self.Name)):
					self.__packer.pack_string(self.Name[j].encode('utf16')[2:])

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
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.EntriesRead = 0
				self.Buffer = []
				self.Pointer = 0x4711
			elif isinstance(self.__packer,ndrlib.Unpacker):
				raise NotImplementedError
		def pack(self):
			if isinstance(self.__packer, ndrlib.Packer):
				# EntriesRead
				self.__packer.pack_long(self.EntriesRead)
				self.__packer.pack_pointer(self.Pointer)

				# Maxcount, needed as NDR array
				self.__packer.pack_long(self.EntriesRead)
 
				b = samr.SAMPR_RID_ENUMERATION(self.__packer)
				b.Name = self.Buffer
				b.pack()

	class SAMPR_DOMAIN_DISPLAY_USER:
		# 2.2.8.2 SAMPR_DOMAIN_DISPLAY_USER
		#
		# http://msdn.microsoft.com/en-us/library/cc245632%28PROT.10%29.aspx
		#
		# typedef struct _SAMPR_DOMAIN_DISPLAY_USER {
		#  unsigned long Index;
		#  unsigned long Rid;
		#  unsigned long AccountControl;
		#  RPC_UNICODE_STRING AccountName;
		#  RPC_UNICODE_STRING AdminComment;
		#  RPC_UNICODE_STRING FullName;
		#} SAMPR_DOMAIN_DISPLAY_USER, 
		# *PSAMPR_DOMAIN_DISPLAY_USER;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Name = []
				self.Index = 0
				self.Rid = 0
				# AccountControl
				#http://msdn.microsoft.com/en-us/library/cc245514%28v=PROT.10%29.aspx
				self.AccountControl = 16 # USER_NORMAL_ACCOUNT
				self.Pointer = 0x11
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.RelativeId = self.__packer.unpack_long()
				self.Name = RPC_UNICODE_STRING(self.__packer, Name)
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				for i in range(int(len(self.Name)/3)): 
					#Index
					self.__packer.pack_long(self.Index)
					#RelativeID
					self.__packer.pack_long(self.Rid)
					#AccountCotrol
					self.__packer.pack_long(self.AccountControl)

					for k in range(3):
						b = samr.RPC_UNICODE_STRING(self.__packer)
						b.Data = self.Name[i*k]
						b.pack()
						self.__packer.pack_pointer(self.Pointer)

				for j in range(len(self.Name)):
					self.__packer.pack_string(self.Name[j].encode('utf16')[2:])

	class SAMPR_DOMAIN_DISPLAY_USER_BUFFER:
		# 2.2.8.7 SAMPR_DOMAIN_DISPLAY_USER_BUFFER
		#
		# http://msdn.microsoft.com/en-us/library/cc245637%28PROT.13%29.aspx
		#
		#typedef struct _SAMPR_DOMAIN_DISPLAY_USER_BUFFER {
		#  unsigned long EntriesRead;
		#  [size_is(EntriesRead)] PSAMPR_DOMAIN_DISPLAY_USER Buffer;
		#} SAMPR_DOMAIN_DISPLAY_USER_BUFFER, 
		# *PSAMPR_DOMAIN_DISPLAY_USER_BUFFER;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.EntriesRead = 0
				self.Buffer = []
				self.Pointer = 0x4711
			elif isinstance(self.__packer,ndrlib.Unpacker):
				raise NotImplementedError
		def pack(self):
			if isinstance(self.__packer, ndrlib.Packer):
				# EntriesRead
				self.__packer.pack_long(self.EntriesRead)
				self.__packer.pack_pointer(self.Pointer)

				# Maxcount, needed as NDR array
				self.__packer.pack_long(self.EntriesRead)
 
				b = samr.SAMPR_DOMAIN_DISPLAY_USER(self.__packer)
				b.Name = self.Buffer
				b.pack()

	ops = {
		1: "Close",
		5: "LookupDomain",
		6: "EnumDomains",
		7: "OpenDomain",
		13: "EnumDomainUsers",
		15: "EnumerateAliasesInDomain",
		40: "QueryDisplayInformation",
		46: "QueryInformationDomain2",
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
		ServerHandle = samr.SAMPR_HANDLE(r)
		ServerHandle.Handle = b'01234567890123456789'
		ServerHandle.pack()

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
		ServerHandle = samr.SAMPR_HANDLE(r)
		ServerHandle.Handle = b'01234567890123456789'
		ServerHandle.pack()

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
		# unsigned long* EnumerationContext,
		r.pack_pointer(EnumerationContext)

		# Pointer to SAMPR_ENUMERATION_BUFFER* Buffer
		r.pack_pointer(0x0da260)

		# SAMPR_ENUMERATION_BUFFER Buffer
		s = samr.SAMPR_ENUMERATION_BUFFER(r)
		s.Buffer = ['HOMEUSER-3AF6FE','Builtin']
		s.EntriesRead = len(s.Buffer)
		s.pack()

		# long* CountReturned
		r.pack_long(s.EntriesRead)
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

		# http://technet.microsoft.com/en-us/library/cc778824%28WS.10%29.aspx
		# example the SID for the built-in Administrators group : S-1-5-32-544
		DomainId = samr.RPC_SID(r)
		DomainId.Value = 'NT_AUTHORITY'
		DomainId.SubAuthority = ['32','544']
		DomainId.SubAuthorityCount = len(DomainId.SubAuthority)
		
		# Maxcount, needed as the element of NDR array
		r.pack_long(DomainId.SubAuthorityCount)
		
		DomainId.pack()
	
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

		DomainHandle = samr.SAMPR_HANDLE(r)
		DomainHandle.Handle = b'11223344556677889900'
		DomainHandle.pack()

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

		# SAMPR_ENUMERATION_BUFFER Buffer
		s = samr.SAMPR_ENUMERATION_BUFFER(r)
		s.Buffer = ['Administrator','Guest','HelpAssistant','SUPPORT_388945a0']
		s.EntriesRead = len(s.Buffer)
		s.pack()

		# long* CountReturned
		r.pack_long(s.EntriesRead)
		r.pack_long(0)

		return r.get_buffer()

	@classmethod
	def handle_QueryDisplayInformation(cls,p):
		#3.1.5.3.3 SamrQueryDisplayInformation (Opnum 40)
		#
		#http://msdn.microsoft.com/en-us/library/cc245763%28PROT.10%29.aspx
		#
		#long SamrQueryDisplayInformation(
		#  [in] SAMPR_HANDLE DomainHandle,
		#  [in] DOMAIN_DISPLAY_INFORMATION DisplayInformationClass,
		#  [in] unsigned long Index,
		#  [in] unsigned long EntryCount,
		#  [in] unsigned long PreferredMaximumLength,
		#  [out] unsigned long* TotalAvailable,
		#  [out] unsigned long* TotalReturned,
		#  [out, switch_is(DisplayInformationClass)] 
		#    PSAMPR_DISPLAY_INFO_BUFFER Buffer
		#);
		x = ndrlib.Unpacker(p.StubData)
		DomainHandle = samr.SAMPR_HANDLE(x)
		print("DomainHandle %s" % DomainHandle)
	
		DisplayInformationClass = x.unpack_long()
		print("DisplayInformationClass %i" % DisplayInformationClass)
		
		Index = x.unpack_long()
		print("Index %i" % Index)

		EntryCount = x.unpack_long()
		print("EntryCount %i" % EntryCount)

		PreferredMaximumLength = x.unpack_long()
		print("PreferredMaximumLength %i" % PreferredMaximumLength)

		r = ndrlib.Packer()
		# unsigned long* TotalAvailable
		r.pack_long(30)
		# unsigned long* TotalReturned
		r.pack_long(30)

		if DisplayInformationClass == 1 :
			r.pack_long(DisplayInformationClass)
			# SAMPR_DOMAIN_DISPLAY_USER_BUFFER
			s = samr.SAMPR_DOMAIN_DISPLAY_USER_BUFFER(r)
			s.Buffer = ['Administrator','Builtin','Full Name','Guest','Builtin','Full Name','HelpAssistant','Builtin','Full Name','SUPPORT_388945a0','Builtin','Full Name']
			s.EntriesRead = int(len(s.Buffer)/3)
			s.pack()

		r.pack_long(0)

		return r.get_buffer()

	@classmethod
	def handle_QueryInformationDomain2(cls,p):
		#3.1.5.5.1 SamrQueryInformationDomain2 (Opnum 46)
		#
		#http://msdn.microsoft.com/en-us/library/cc245773%28PROT.13%29.aspx
		#
		#long SamrQueryInformationDomain2(
		#  [in] SAMPR_HANDLE DomainHandle,
		#  [in] DOMAIN_INFORMATION_CLASS DomainInformationClass,
		#  [out, switch_is(DomainInformationClass)] 
		#    PSAMPR_DOMAIN_INFO_BUFFER* Buffer
		#)
		x = ndrlib.Unpacker(p.StubData)
		DomainHandle = samr.SAMPR_HANDLE(x)
		print("DomainHandle %s" % DomainHandle)
	
		DisplayInformationClass = x.unpack_long()
		print("DisplayInformationClass %i" % DisplayInformationClass)
		
		r = ndrlib.Packer()
		#typedef 
		#[switch_type(DOMAIN_INFORMATION_CLASS)] 
		#  union _SAMPR_DOMAIN_INFO_BUFFER {
		#  [case(DomainPasswordInformation)] 
		#    DOMAIN_PASSWORD_INFORMATION Password;
		#  [case(DomainGeneralInformation)] 
		#    SAMPR_DOMAIN_GENERAL_INFORMATION General;
		#  [case(DomainLogoffInformation)] 
		#    DOMAIN_LOGOFF_INFORMATION Logoff;
		#  [case(DomainOemInformation)] 
		#    SAMPR_DOMAIN_OEM_INFORMATION Oem;
		#  [case(DomainNameInformation)] 
		#    SAMPR_DOMAIN_NAME_INFORMATION Name;
		#  [case(DomainServerRoleInformation)] 
		#    DOMAIN_SERVER_ROLE_INFORMATION Role;
		#  [case(DomainReplicationInformation)] 
		#    SAMPR_DOMAIN_REPLICATION_INFORMATION Replication;
		#  [case(DomainModifiedInformation)] 
		#    DOMAIN_MODIFIED_INFORMATION Modified;
		#  [case(DomainStateInformation)] 
		#    DOMAIN_STATE_INFORMATION State;
		#  [case(DomainGeneralInformation2)] 
		#    SAMPR_DOMAIN_GENERAL_INFORMATION2 General2;
		#  [case(DomainLockoutInformation)] 
		#    SAMPR_DOMAIN_LOCKOUT_INFORMATION Lockout;
		#  [case(DomainModifiedInformation2)] 
		#    DOMAIN_MODIFIED_INFORMATION2 Modified2;
		#} SAMPR_DOMAIN_INFO_BUFFER, 
		# *PSAMPR_DOMAIN_INFO_BUFFER;
		
		# Pointer to the SAMPR_DOMAIN_INFO_BUFFER
		r.pack_pointer(0x23456)
		
		if DisplayInformationClass == 1: 
			# 2.2.4.5 DOMAIN_PASSWORD_INFORMATION
			# http://msdn.microsoft.com/en-us/library/cc245575%28PROT.13%29.aspx
			#typedef struct _DOMAIN_PASSWORD_INFORMATION {
			#  unsigned short MinPasswordLength;
			#  unsigned short PasswordHistoryLength;
			#  unsigned long PasswordProperties;
			#  OLD_LARGE_INTEGER MaxPasswordAge;
			#  OLD_LARGE_INTEGER MinPasswordAge;
			#} DOMAIN_PASSWORD_INFORMATION, 
			# *PDOMAIN_PASSWORD_INFORMATION;

			r.pack_long(DisplayInformationClass)
			r.pack_short(0)
			r.pack_short(0)
			r.pack_hyper(999999999999)
			r.pack_hyper(0)

		elif DisplayInformationClass == 8:
			# 2.2.4.8 DOMAIN_MODIFIED_INFORMATION
			# http://msdn.microsoft.com/en-us/library/cc245578%28PROT.10%29.aspx
			#typedef struct _DOMAIN_MODIFIED_INFORMATION {
			#  OLD_LARGE_INTEGER DomainModifiedCount;
			#  OLD_LARGE_INTEGER CreationTime;
			#} DOMAIN_MODIFIED_INFORMATION, 
			# *PDOMAIN_MODIFIED_INFORMATION;
			
			r.pack_long(DisplayInformationClass)
			r.pack_hyper(10)
			r.pack_raw(b'\xc2\x1e\xdc\x23\xd5\x13\xcb\x01') # Jun 25,2010 03:40:46.078125000

		elif DisplayInformationClass == 12:
			# 2.2.4.15 SAMPR_DOMAIN_LOCKOUT_INFORMATION
			# http://msdn.microsoft.com/en-us/library/cc245569%28PROT.13%29.aspx
			#typedef struct _SAMPR_DOMAIN_LOCKOUT_INFORMATION {
			#  LARGE_INTEGER LockoutDuration;
			#  LARGE_INTEGER LockoutObservationWindow;
			#  unsigned short LockoutThreshold;
			#} SAMPR_DOMAIN_LOCKOUT_INFORMATION, 
			# *PSAMPR_DOMAIN_LOCKOUT_INFORMATION;
			r.pack_long(DisplayInformationClass)
			r.pack_hyper(18446744055709551616) #windows XP give this value
			r.pack_hyper(18446744055709551616)
			r.pack_short(0)

		r.pack_long(0)

		return r.get_buffer()

	@classmethod
	def handle_EnumerateAliasesInDomain(cls, p):
		#3.1.5.2.4 SamrEnumerateAliasesInDomain (Opnum 15)
		#
		#http://msdn.microsoft.com/en-us/library/cc245758%28PROT.10%29.aspx
		#
		#long SamrEnumerateAliasesInDomain(
		#  [in] SAMPR_HANDLE DomainHandle,
		#  [in, out] unsigned long* EnumerationContext,
		#  [out] PSAMPR_ENUMERATION_BUFFER* Buffer,
		#  [in] unsigned long PreferedMaximumLength,
		#  [out] unsigned long* CountReturned
		#)
		x = ndrlib.Unpacker(p.StubData)
		DomainHandle = samr.SAMPR_HANDLE(x)
		print("DomainHandle %s" % DomainHandle)
	
		EnumerationContext = x.unpack_long()
		print("EnumerationContext %i" % EnumerationContext)
		
		PreferedMaximumLength = x.unpack_long()
		print("PreferedMaximumLength %i" % PreferedMaximumLength)

		r = ndrlib.Packer()
		r.pack_long(EnumerationContext)

		# PSAMPR_ENUMERATION_BUFFER* Buffer
		r.pack_pointer(0x0da260)

		# SAMPR_ENUMERATION_BUFFER Buffer
		s = samr.SAMPR_ENUMERATION_BUFFER(r)
		s.Buffer = ['Administrator','Guest']
		s.EntriesRead = len(s.Buffer)
		s.pack()

		# long* CountReturned
		r.pack_long(s.EntriesRead)
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
		s = samr.SAMPR_HANDLE(r)
		s.Handle =  b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
		s.pack()
		r.pack_long(0)

		return r.get_buffer()

class SceSvc(RPCService):
	uuid = UUID('93149ca2-973b-11d1-8c39-00c04fb984f9').hex


class sfcapi(RPCService):
	uuid = UUID('83da7c00-e84f-11d2-9807-00c04f8ec850').hex


class spoolss(RPCService):
	uuid = UUID('12345678-1234-abcd-ef00-0123456789ab').hex

	ops = {
		0x00: "EnumPrinters"

	}

	class PRINTER_INFO_1 :
		# PRINTER_INFO_1 Structure
		# 
		# http://msdn.microsoft.com/en-us/library/dd162844%28v=VS.85%29.aspx
		# 
		#typedef struct _PRINTER_INFO_1 {
		#  DWORD  Flags;
		#  LPTSTR pDescription;
		#  LPTSTR pName;
		#  LPTSTR pComment;
		#} PRINTER_INFO_1, *PPRINTER_INFO_1;

		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Flags = 0x00018000
				self.Buffer = ''
				self.Buffersize = 0
				self.Offset = 0
			elif isinstance(self.__packer,ndrlib.Unpacker):
				pass
		def pack(self):
			if isinstance(self.__packer, ndrlib.Packer):
				self.__packer.pack_pointer(self.Flags)
				
				# self.Offset is the distance of the string count from the end of PRINTER_INFO_1 buffer. To count the distance of the string from the start of PRINTER_INFO_1 buffer, self.Buffersize - self offset needed
				for j in range(len(self.Buffer)):
					count = 0
					count = len(self.Buffer) - j - 1
					self.Offset = self.Offset + 2*len(self.Buffer[count])
					self.__packer.pack_long(self.Buffersize-self.Offset)					
				
				for i in range(len(self.Buffer)):
					
					self.__packer.pack_raw(self.Buffer[i].encode('utf16')[2:])
		def size(self):
			size = 4 + 4*len(self.Buffer) + 2*(sum([len(x) for x in self.Buffer]))
			print ("PRINTER_INFO_1 size %i" % size)
			return size

	@classmethod
	def handle_EnumPrinters (cls, p):
		#EnumPrinters Function
		#
		#http://msdn.microsoft.com/en-us/library/dd162692%28VS.85%29.aspx
		#
		#BOOL EnumPrinters(
		#  __in   DWORD Flags,
		#  __in   LPTSTR Name,
		#  __in   DWORD Level,
		#  __out  LPBYTE pPrinterEnum,
		#  __in   DWORD cbBuf,
		#  __out  LPDWORD pcbNeeded,
		#  __out  LPDWORD pcReturned
		#);
		
		p = ndrlib.Unpacker(p.StubData)
		Flags = p.unpack_long()
		Name = p.unpack_pointer()
		Level = p.unpack_long()
		Pointer = p.unpack_pointer()
		cbBuf = p.unpack_long()
		
		print("Flags %s Name %s Level %i cbBuf %i " % (Flags, Name, Level, cbBuf))

		r = ndrlib.Packer()
		# Pointer to PRINTER_INFO_X buffer
		r.pack_pointer(0x6b254)
		
		# PRINTER_INFO_1 Buffer
		a = spoolss.PRINTER_INFO_1(r)
			
		# these string are the default response of windows xp
		# 'Windows NT Remote Printers' need for msf fingerprinting OS language as 'English version'
		#https://www.metasploit.com/redmine/projects/framework/repository/revisions/8941/entry/lib/msf/core/exploit/smb.rb#L396
			
		a.Buffer = ['Internet URL Printers\0','Windows NT Internet Provider\0','Windows NT Internet Printing\0','Remote Printers\0','Windows NT Remote Printers\0','Microsoft Windows Network\0','Locally Connected Printers\0','Windows NT Local Print Providor\0','Windows NT Local Printers\0']
		a.Buffersize = a.size()
		
		if Level == 1 and cbBuf != 0:
			r.pack_long(a.Buffersize)
			a.pack()
		
			r.pack_long(a.Buffersize)
			r.pack_long(3) #pcReturned, default in windows xp is 3
			r.pack_long(0)
		else:
			# this need to trick metasploit ms08-067 exploit
			# dionaea need send a malformed response if the cbBuf == 0
			r.pack_long(0)
			r.pack_long(a.Buffersize)
			r.pack_long(0)
			
		return r.get_buffer()


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
		0x10: "NetrShareGetInfo",
		0x1c: "NetrRemoteTOD",
		0x1f: "NetPathCanonicalize",
		0x20: "NetPathCompare",
		0x22: "NetNameCanonicalize"
	}
	vulns  = { 
		0x1f: "MS08-67",
		0x20: "MS08-67",
	}

	class SRVSVC_HANDLE:
		# 2.2.1.1 SRVSVC_HANDLE
		# 
		# http://msdn.microsoft.com/en-us/library/cc247105%28PROT.10%29.aspx
		# 
		# 	typedef [handle, string] WCHAR* SRVSVC_HANDLE; 
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Handle = b''
				self.Pointer = 0x3a20f2
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Ref = self.__packer.unpack_pointer()
				self.Handle = self.__packer.unpack_string()
		def pack(self):
			if isinstance(self.__packer, ndrlib.Packer):
				self.__packer.pack_pointer(self.Pointer)
				self.__packer.pack_string(handle)

	class SHARE_INFO_0_CONTAINER:
		# 2.2.4.32 SHARE_INFO_0_CONTAINER
 		# 
		# http://msdn.microsoft.com/en-us/library/cc247156%28PROT.13%29.aspx
 		# 
		#typedef struct _SHARE_INFO_0_CONTAINER {
		#  DWORD EntriesRead;
		#  [size_is(EntriesRead)] LPSHARE_INFO_0 Buffer;
		#} SHARE_INFO_0_CONTAINER;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.EntriesRead = 0
				self.Data = []
				self.Pointer = 0x23456
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Ptr = self.__packer.unpack_pointer()
				self.EntriesRead = self.__packer.unpack_long()
				self.Buffer = self.__packer.unpack_pointer()
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				# EntriesRead
				self.__packer.pack_long(self.EntriesRead)
				# LPSHARE_INFO_0 Buffer
				b = SRVSVC.SHARE_INFO_0(self.__packer)
				b.Data = self.Data
				b.MaxCount = self.EntriesRead
				b.pack()
				

	class SHARE_INFO_1_CONTAINER:
		# 2.2.4.33 SHARE_INFO_1_CONTAINER
 		# 
		# http://msdn.microsoft.com/en-us/library/cc247157%28PROT.10%29.aspx
 		# 
		# typedef struct _SHARE_INFO_1_CONTAINER {
		#   DWORD EntriesRead;
		#   [size_is(EntriesRead)] LPSHARE_INFO_1 Buffer;
		# } SHARE_INFO_1_CONTAINER;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.EntriesRead = 0
				self.Data = []
				self.Pointer = 0x23456
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Ptr = self.__packer.unpack_pointer()
				self.EntriesRead = self.__packer.unpack_long()
				self.Buffer = self.__packer.unpack_pointer()
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				# EntriesRead
				self.__packer.pack_long(self.EntriesRead)
				# LPSHARE_INFO_1 Buffer
				b = SRVSVC.SHARE_INFO_1(self.__packer)
				b.Data = self.Data
				b.MaxCount = self.EntriesRead
				b.pack()


	class SHARE_INFO_2_CONTAINER:
		# 2.2.4.34 SHARE_INFO_2_CONTAINER
 		# 
		# http://msdn.microsoft.com/en-us/library/cc247158%28PROT.13%29.aspx
 		# 
		#typedef struct _SHARE_INFO_2_CONTAINER {
		#  DWORD EntriesRead;
		#  [size_is(EntriesRead)] LPSHARE_INFO_2 Buffer;
		#} SHARE_INFO_2_CONTAINER, 
		# *PSHARE_INFO_2_CONTAINER, 
		# *LPSHARE_INFO_2_CONTAINER;
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.EntriesRead = 0
				self.Data = []
				self.Pointer = 0x23456
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Ptr = self.__packer.unpack_pointer()
				self.EntriesRead = self.__packer.unpack_long()
				self.Buffer = self.__packer.unpack_pointer()
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				# EntriesRead
				#self.__packer.pack_long(self.EntriesRead)
				# LPSHARE_INFO_2 Buffer
				b = SRVSVC.SHARE_INFO_2(self.__packer)
				b.Data = self.Data
				b.MaxCount = self.EntriesRead
				b.pack()

	class SHARE_INFO_502_CONTAINER:
		# 2.2.4.36 SHARE_INFO_502_CONTAINER
		#
		# http://msdn.microsoft.com/en-us/library/cc247160%28PROT.13%29.aspx
		#
		# typedef struct _SHARE_INFO_502_CONTAINER {
		#   DWORD EntriesRead;
		#   [size_is(EntriesRead)] LPSHARE_INFO_502_I Buffer;
		# } SHARE_INFO_502_CONTAINER,
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.EntriesRead = 0
				self.Data = []
				self.Pointer = 0x23456
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.Ctr = self.__packer.unpack_pointer()
				self.Ptr = self.__packer.unpack_pointer()
				self.EntriesRead = self.__packer.unpack_long()
				self.Buffer = self.__packer.unpack_pointer()
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				# EntriesRead
				self.__packer.pack_long(self.EntriesRead)
				# SHARE_INFO_502_I Buffer
				b = SRVSVC.SHARE_INFO_502(self.__packer)
				b.Data = self.Data
				b.MaxCount = self.EntriesRead
				b.pack()

	class SHARE_INFO_0:
		# 2.2.4.22 SHARE_INFO_0
		# 
		# http://msdn.microsoft.com/en-us/library/cc247146%28v=PROT.13%29.aspx
		# 
		#typedef struct _SHARE_INFO_0 {
		#  [string] wchar_t* shi0_netname;
		#} SHARE_INFO_0, 
		# *PSHARE_INFO_0, 
		# *LPSHARE_INFO_0
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Data = []
				self.Pointer = 0x99999
				self.MaxCount = 0
				self.Netname_pointer = 0x34567
			elif isinstance(self.__packer,ndrlib.Unpacker):
				pass
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_pointer(self.Pointer)
				# MaxCount, needed as the NDR array
				self.__packer.pack_long(self.MaxCount)

				for i in range(self.MaxCount): 				
					self.__packer.pack_pointer(self.Netname_pointer) # netname
				for j in range(len(self.Data)):
					self.__packer.pack_string_fix(self.Data[j].encode('utf16')[2:])

	class SHARE_INFO_1:
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

		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Data = []
				self.Pointer = 0x99999
				self.MaxCount = 0
				self.Netname_pointer = 0x34567
				self.Type = 0x00000000 # STYPE_DISKTREE
				self.Remark_pointer = 0x45678
			elif isinstance(self.__packer,ndrlib.Unpacker):
				pass
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_pointer(self.Pointer)
				# MaxCount, needed as the NDR array
				self.__packer.pack_long(self.MaxCount)

				for i in range(self.MaxCount): 				
					self.__packer.pack_pointer(self.Netname_pointer) # netname
					self.__packer.pack_long(self.Type) # type
					self.__packer.pack_pointer(self.Remark_pointer) # remark

				for j in range(len(self.Data)):
					self.__packer.pack_string(self.Data[j].encode('utf16')[2:])

	class SHARE_INFO_502:
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
		def __init__(self, p, data=None):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Data = []
				self.Pointer = 0x99999
				self.MaxCount = 0
				self.Netname_pointer = 0x34567
				self.Type = 0x00000000
				self.Remark_pointer = 0x45678
				self.Permissions = 0
				self.Max_uses = 0xffffffff
				self.Current_uses = 1
				self.Path_pointer = 0x87654
				self.Passwd_pointer = 0
				self.Reserved = 0
				self.Security_descriptor = 0				
			elif isinstance(self.__packer,ndrlib.Unpacker):
				pass
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_pointer(self.Pointer)
				self.__packer.pack_long(self.MaxCount)

				for i in range(self.MaxCount): 				
					self.__packer.pack_pointer(self.Netname_pointer) # netname
					self.__packer.pack_long(self.Type) # STYPE_DISKTREE
					self.__packer.pack_pointer(self.Remark_pointer) # remark
					self.__packer.pack_long(self.Permissions)		# permissions
					self.__packer.pack_long(self.Max_uses) # max_uses
					self.__packer.pack_long(self.Current_uses)		# current_uses
					self.__packer.pack_pointer(self.Path_pointer) # path
					self.__packer.pack_pointer(self.Passwd_pointer) 	# passwd
					self.__packer.pack_long(self.Reserved) # reserved
					self.__packer.pack_pointer(self.Security_descriptor)	# security descriptor

				for j in range(len(self.Data)):
					self.__packer.pack_string_fix(self.Data[j].encode('utf16')[2:])
				

	class SHARE_INFO_2:
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
		def __init__(self, p):
			self.__packer = p
			if isinstance(self.__packer,ndrlib.Packer):
				self.Data = []
				self.Pointer = 0x99999
				self.MaxCount = 0
				self.Netname_pointer = 0x34567
				self.Type = 0x00000000
				self.Remark_pointer = 0x45678
				self.Permissions = 0
				self.Max_uses = 0xffffffff
				self.Current_uses = 1
				self.Path_pointer = 0x87654
				self.Passwd_pointer = 0		
			elif isinstance(self.__packer,ndrlib.Unpacker):
				self.ref = self.__packer.unpack_pointer()
				self.netname = self.__packer.unpack_pointer()
				self.sharetype = self.__packer.unpack_long()
				self.remark = self.__packer.unpack_long()
				self.permission = self.__packer.unpack_long()
				self.max_use = self.__packer.unpack_long()
				self.current_use = self.__packer.unpack_long()
				self.path = self.__packer.unpack_pointer()
				self.passwd = self.__packer.unpack_pointer()
				self.share_name = self.__packer.unpack_string()
				self.share_comment = self.__packer.unpack_string()
				self.share_path = self.__packer.unpack_string()
		def pack(self):
			if isinstance(self.__packer,ndrlib.Packer):
				self.__packer.pack_pointer(self.Netname_pointer) # netname
				self.__packer.pack_long(self.Type) # STYPE_DISKTREE
				self.__packer.pack_pointer(self.Remark_pointer) # remark
				self.__packer.pack_long(self.Permissions) # permissions
				self.__packer.pack_long(self.Max_uses) # max_uses
				self.__packer.pack_long(self.Current_uses) # current_uses
				self.__packer.pack_pointer(self.Path_pointer) # path
				self.__packer.pack_pointer(self.Passwd_pointer) # passwd

				for j in range(len(self.Data)):
					self.__packer.pack_string_fix(self.Data[j].encode('utf16')[2:])

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

		ServerName = SRVSVC.SRVSVC_HANDLE(x)
		
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
		if infostruct_share == 0:
			buffer = SRVSVC.SHARE_INFO_0_CONTAINER(x)
		elif infostruct_share == 1:
			buffer = SRVSVC.SHARE_INFO_1_CONTAINER(x)

		elif infostruct_share == 502:
			buffer = SRVSVC.SHARE_INFO_502_CONTAINER(x)
		
		preferdmaxlen = x.unpack_long()
		
		# ResumeHandle
		resumehandleptr = x.unpack_pointer()
		resumehandle = 0
		if resumehandleptr != 0:
			resumehandle = x.unpack_long()
		
		print("infostruct_share %i preferdmaxlen %i  resumehandleptr %x resumehandle %i" % (infostruct_share,preferdmaxlen,resumehandleptr,resumehandle) )

		# compile reply
		r = ndrlib.Packer()
		r.pack_long(infostruct_level)
		r.pack_long(infostruct_share)

		# pointer to the SHARE_INFO_X_CONTAINER
		r.pack_pointer(0x23456)
		
		if infostruct_share == 0:
			s = SRVSVC.SHARE_INFO_0_CONTAINER(r)
			s.Data = ['test\0','test2\0']
			s.EntriesRead = int(len(s.Data))
			s.pack()

		elif infostruct_share == 1:
			s = SRVSVC.SHARE_INFO_1_CONTAINER(r)
			s.Data = ['test\0','es geht test\0','test2\0','es geht test\0']
			s.EntriesRead = int(len(s.Data)/2)
			s.pack()
		
		elif infostruct_share == 502:
			s = SRVSVC.SHARE_INFO_502_CONTAINER(r)
			s.Data = ['test\0','es geht test\0','C:\0','test2\0','es geht test\0','C:\WINDOWS\0']
			s.EntriesRead = int(len(s.Data)/3)
			s.pack()

		# total entries
		r.pack_long(s.EntriesRead)

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

		# conficker is stubborn
		# dionaea replies to the exploit, conficker retries to exploit
		# I'd prefer a real check for a bad path, but the path provided by conficker is not utf16, 
		# therefore it is not possible to canonicalize the path and check if it path canonicalizes beyond /
		# the workaround ... is checking for a 'long' path ...
		if len(path) > 128:
			raise DCERPCValueError("path","too long", path)

		r = ndrlib.Packer()
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
		print("ref 0x%x server_unc %s path1 %s path2 %s pathtype %i pathflags %i" % (ref, server_unc, path1, path2, pathtype, pathflags))
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
		ServerName = SRVSVC.SRVSVC_HANDLE(p)
		infostruct_level = p.unpack_long()
		infostruct_share = p.unpack_long()

		if infostruct_share == 2:
			buffer = SRVSVC.SHARE_INFO_2(p)
		
		ptr_parm = p.unpack_pointer()
		error = p.unpack_long()

		print("infostruct_share %i ptr_parm %x ParmErr %i" % (infostruct_share,ptr_parm,error) )

		r = ndrlib.Packer()
		r.pack_pointer(0x324567)
		r.pack_long(0)
		r.pack_long(0)
		return r.get_buffer()
		
	@classmethod
	def handle_NetrShareGetInfo(cls, p):
		#3.1.4.10 NetrShareGetInfo (Opnum 16)
		#
		#http://msdn.microsoft.com/en-us/library/cc247236%28PROT.13%29.aspx
		#
		#NET_API_STATUS NetrShareGetInfo(
		#  [in, string, unique] SRVSVC_HANDLE ServerName,
		#  [in, string] WCHAR* NetName,
		#  [in] DWORD Level,
		#  [out, switch_is(Level)] LPSHARE_INFO InfoStruct
		#);
		p = ndrlib.Unpacker(p.StubData)
		ServerName = SRVSVC.SRVSVC_HANDLE(p)
		NetName = p.unpack_string()
		Level = p.unpack_long()
		print("NetName %s Level %i" % (NetName,Level))

		r = ndrlib.Packer()
		r.pack_long(Level)

		# pointer to the SHARE_INFO_X_CONTAINER
		r.pack_pointer(0x23456)
		
		if Level == 2:
			s = SRVSVC.SHARE_INFO_2_CONTAINER(r)
			s.Data = [NetName.decode('utf16'),'es geht test\0','C:\0']
			s.EntriesRead = int(len(s.Data)/3)
			s.pack()

		r.pack_long(0)
		return r.get_buffer()

	@classmethod
	def handle_NetNameCanonicalize (cls, p):
		#3.1.4.33 NetprNameCanonicalize (Opnum 34)
		#
		#http://msdn.microsoft.com/en-us/library/cc247261%28PROT.13%29.aspx
		#
		#NET_API_STATUS NetprNameCanonicalize(
		#  [in, string, unique] SRVSVC_HANDLE ServerName,
		#  [in, string] WCHAR* Name,
		#  [out, size_is(OutbufLen)] WCHAR* Outbuf,
		#  [in, range(0,64000)] DWORD OutbufLen,
		#  [in] DWORD NameType,
		#  [in] DWORD Flags
		#);
		
		# Combination of metasploit ms08-067 exploit + wireshark cant parse this request correct, so this function have not fully tested
		p = ndrlib.Unpacker(p.StubData)
		ServerName = SRVSVC.SRVSVC_HANDLE(p)
		Name = p.unpack_string()
		Outbuflen = p.unpack_long()
		NameType = p.unpack_long()
		Flags = p.unpack_long()
		print("ServerName %s Name %s Outbuflen %i Nametype %i Flags %i" % (ServerName, Name, Outbuflen , NameType, Flags))

		r = ndrlib.Packer()
		r.pack_pointer(0)
		r.pack_string(Name)
	
		r.pack_long(0)
		return r.get_buffer()

	@classmethod
	def handle_NetrRemoteTOD(cls, p):
		#3.1.4.21 NetrRemoteTOD (Opnum 28)
		#
		#http://msdn.microsoft.com/en-us/library/cc247248%28v=PROT.13%29.aspx
		#
		#NET_API_STATUS NetrRemoteTOD(
		#  [in, string, unique] SRVSVC_HANDLE ServerName,
		#  [out] LPTIME_OF_DAY_INFO* BufferPtr
		#);
		p = ndrlib.Unpacker(p.StubData)
		ServerName = SRVSVC.SRVSVC_HANDLE(p)

		r = ndrlib.Packer()

		# pointer to the LPTIME_OF_DAY_INFO* BufferPtr
		r.pack_pointer(0x23456)
		
		#typedef struct TIME_OF_DAY_INFO {
		#  DWORD tod_elapsedt;
		#  DWORD tod_msecs;
		#  DWORD tod_hours;
		#  DWORD tod_mins;
		#  DWORD tod_secs;
		#  DWORD tod_hunds;
		#  long tod_timezone;
		#  DWORD tod_tinterval;
		#  DWORD tod_day;
		#  DWORD tod_month;
		#  DWORD tod_year;
		#  DWORD tod_weekday;
		#} TIME_OF_DAY_INFO, 
		# *PTIME_OF_DAY_INFO, 
		# *LPTIME_OF_DAY_INFO;

		ctime = localtime()
		#Eg, time.struct_time(tm_year=2010, tm_mon=7, tm_mday=13, tm_hour=2, tm_min=12, tm_sec=27, tm_wday=1, tm_yday=194, tm_isdst=0)

		r.pack_long(int(time()))#elapsedt
		r.pack_long(515893)	#msecs
		r.pack_long(ctime[3])	#hours
		r.pack_long(ctime[4])   #mins
		r.pack_long(ctime[5])   #secs
		r.pack_long(59) 	#hunds
		r.pack_long_signed(int(altzone/60),) #timezone
		r.pack_long(310) 	#tinterval
		r.pack_long(ctime[2])   #day
		r.pack_long(ctime[1])   #month
		r.pack_long(ctime[0])   #year
		r.pack_long(ctime[6])   #weekday

		r.pack_long(0)
		return r.get_buffer()
		
		
class ssdpsrv(RPCService):
	uuid = UUID('4b112204-0e19-11d3-b42b-0000f81feb9f').hex


class SVCCTL(RPCService):
	"""[MS-SCMR]: Service Control Manager Remote Protocol Specification

	http://msdn.microsoft.com/en-us/library/cc245832%28v=PROT.10%29.aspx
	"""
	uuid = UUID('367abb81-9844-35f1-ad32-98f038001003').hex
	version_major = 0
	version_minor = 0

	ops = {
		0 : "CloseServiceHandle",
		24: "CreateServiceA",
		27: "OpenSCManagerA",
	}

	@classmethod
	def handle_CloseServiceHandle(cls, p):
		# DWORD RCloseServiceHandle(
		# 	[in, out] LPSC_RPC_HANDLE hSCObject
		# );
		pass

	@classmethod
	def handle_CreateServiceA(cls, p):
		# DWORD RCreateServiceA(
		# 	[in] SC_RPC_HANDLE hSCManager,
		# 	[in, string, range(0, SC_MAX_NAME_LENGTH)] LPSTR lpServiceName,
		# 	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)] LPSTR lpDisplayName,
		# 	[in] DWORD dwDesiredAccess,
		# 	[in] DWORD dwServiceType,
		# 	[in] DWORD dwStartType,
		# 	[in] DWORD dwErrorControl,
		# 	[in, string, range(0, SC_MAX_PATH_LENGTH)] LPSTR lpBinaryPathName,
		# 	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)] LPSTR lpLoadOrderGroup,
		# 	[in, out, unique] LPDWORD lpdwTagId,
		# 	[in, unique, size_is(dwDependSize)] LPBYTE lpDependencies,
		# 	[in, range(0, SC_MAX_DEPEND_SIZE)] DWORD dwDependSize,
		# 	[in, string, unique, range(0, SC_MAX_ACCOUNT_NAME_LENGTH)] LPSTR lpServiceStartName,
		# 	[in, unique, size_is(dwPwSize)] LPBYTE lpPassword,
		# 	[in, range(0, SC_MAX_PWD_SIZE)] DWORD dwPwSize,
		# 	[out] LPSC_RPC_HANDLE lpServiceHandle
		# );
		pass


	@classmethod
	def handle_OpenSCManagerA(cls, p):
		# DWORD ROpenSCManagerA(
		# 	[in, string, unique, range(0, SC_MAX_COMPUTER_NAME_LENGTH)] SVCCTL_HANDLEA lpMachineName,
		# 	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)] LPSTR lpDatabaseName,
		# 	[in] DWORD dwDesiredAccess,
		# 	[out] LPSC_RPC_HANDLE lpScHandle
		# );
		pass

class tapsrv(RPCService):
	uuid = UUID('2f5f6520-ca46-1067-b319-00dd010662da').hex


class TerminalServerLicensing(RPCService):
	uuid = UUID('3d267954-eeb7-11d1-b94e-00c04fa3080d').hex


class trkwks(RPCService):
	uuid = UUID('300f3532-38cc-11d0-a3f0-0020af6b0add').hex


class w32time(RPCService):
	uuid = UUID('8fb6d884-2388-11d0-8c35-00c04fda2795').hex


#class winipsec(RPCService):
#	uuid = UUID('12345678-1234-abcd-ef00-0123456789ab').hex


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




