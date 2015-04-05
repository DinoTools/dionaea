#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2011  Markus Koetter
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


from dionaea.smb.include.fieldtypes import IntField, Field, StrField
import struct

class Int24Field(IntField):
	def __init__(self, name, default):
		IntField.__init__(self,name,default)
	def i2len(self, pkt, i):
		return 3
	def i2m(self, pkt, y):
		return struct.pack("<BBB", y&0xff, (y&0xff00) >> 8, (y&0xff0000) >> 16)
	def m2i(self, pkt, x):
		(l,m,h) = struct.unpack("<BBB", x[:3])
		return h * 2**16 + m * 2**8 + l
	def addfield(self, pkt, s, val):
		m = self.i2m(pkt, val)
		return s+m
	def getfield(self, pkt, d):
		return d[3:],self.m2i(pkt, d)
	def size(self, pkt, val):
		return 3

class LengthCodedIntField(IntField):
	def __init__(self, name, default):
		Field.__init__(self,name,default,fmt="H")
	def i2len(self, pkt, i):
		return len(self.i2m(pkt,i))
	def i2m(self, pkt, y):
		if y is None:
			y = 0
		l = b''
		if y < 250:
			l = struct.pack("<B", y)
		elif y < 2**16:
			l = struct.pack("<BH", 252, y)
		elif y < 2**32:
			l = struct.pack("<BI", 253, y)
		else:
			l = struct.pack("<BQ", 254, y)
		return l
	def m2i(self, pkt, x):
		(l,o,s) = self._los(x)
		return l
	def addfield(self, pkt, s, val):
		m = self.i2m(pkt, val)
		return s+m
	def getfield(self, pkt, d):
		(l,o,s) = self._los(d)
		return d[s+o:],self.m2i(pkt, d)
	def size(self, pkt, val):
		return len(self.i2m(pkt, val))
	def _los(self, d):
		l = d[0]
		o = 1
		s = 1
		if l<=250 or l == 251:
			o = 0
		elif l == 252:
			s = 2
			(l,) = struct.unpack("<H", d[o:o+s])
		elif l == 253:
			s = 4
			(l,) = struct.unpack("<I", d[o:o+s])
		elif l == 254:
			s = 8
			(l,) = struct.unpack("<Q", d[o:o+s])
		return (l,o,s)

class LengthCodedBinaryField(StrField):
	def __init__(self, name, default):
		Field.__init__(self,name,default,fmt="H")
	def i2len(self, pkt, i):
		return len(self.i2m(pkt,i))
	def i2m(self, pkt, x):
		if x is None:
			y = None
		else:
			if type(x) is str:
				x = x.encode('ascii')
			elif type(x) is not bytes:
				x = str(x).encode('ascii')
			y=len(x)
		
		l = b''
		if y is None:
			l = struct.pack("<B", 251)
			x = b''
		elif y == 0:
			l = struct.pack("<B", y)
			x = b''
		elif y > 0 and y < 250:
			l = struct.pack("<B", y)
		elif y < 2**16:
			l = struct.pack("<BH", 252, y)
		elif y < 2**32:
			l = struct.pack("<BI", 253, y)
		else:
			l = struct.pack("<BQ", 254, y)
		return l+x
	def m2i(self, pkt, x):
		(l,o,s) = self._los(x)
		return x[o+s:o+s+l]
	def addfield(self, pkt, s, val):
		m = self.i2m(pkt, val)
		return s+m
	def getfield(self, pkt, d):
		(l,o,s) = self._los(d)
		return d[s+o+l:],self.m2i(pkt, d)
	def size(self, pkt, val):
		return len(self.i2m(pkt, val))
	def _los(self, d):
		l = d[0]
		o = 1
		s = 1
		if l<=250 or l == 251:
			o = 0
		elif l == 252:
			s = 2
			(l,) = struct.unpack("<H", d[o:o+s])
		elif l == 253:
			s = 4
			(l,) = struct.unpack("<I", d[o:o+s])
		elif l == 254:
			s = 8
			(l,) = struct.unpack("<Q", d[o:o+s])
		return (l,o,s)
