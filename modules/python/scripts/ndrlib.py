"""Implements (a subset of) NDR -- Network Data Representation.

	http://www.opengroup.org/onlinepubs/9629399/chap14.htm

"""


import struct
from io import BytesIO

__all__ = ["Error", "Packer", "Unpacker"]

# exceptions
class Error(Exception):
	"""Exception class for this module. Use:

	except ndrlib.Error, var:
		# var has the Error instance for the exception

	Public ivars:
		msg -- contains the message

	"""
	def __init__(self, msg):
		self.msg = msg
	def __repr__(self):
		return repr(self.msg)
	def __str__(self):
		return str(self.msg)


class Unpacker:
	"""Unpacks basic data representations from the given buffer."""

	def __init__(self, data, integer='le', char='ascii', floating='IEEE'):
		self.reset(data)

	def reset(self, data):
		self.__buf = data
		self.__pos = 0

	def get_position(self):
		return self.__pos

	def set_position(self, position):
		self.__pos = position

	def get_buffer(self):
		return self.__buf

	def done(self):
		if self.__pos < len(self.__buf):
			raise Error('unextracted data remains')

	def unpack_small(self):
		i = self.__pos
		self.__pos = j = i+1
		data = self.__buf[i:j]
		if len(data) < 1:
			raise EOFError
		x = struct.unpack('<B', data)[0]
		try:
			return int(x)
		except OverflowError:
			return x

	def unpack_short(self):
		self.__pos += self.__pos % 2
		i = self.__pos
		self.__pos = j = i+2
		data = self.__buf[i:j]
		if len(data) < 2:
			raise EOFError
		return struct.unpack('<H', data)[0]

	def unpack_long(self):
		self.__pos += self.__pos % 4
		i = self.__pos
		self.__pos = j = i+4
		data = self.__buf[i:j]
		if len(data) < 4:
			raise EOFError
		return struct.unpack('<L', data)[0]

	def unpack_bool(self):
		return bool(self.unpack_long())

	def unpack_pointer(self):
		return self.unpack_long()

	def unpack_string(self, width=16):
		mc = self.unpack_long()
		off = self.unpack_long()
		ac = self.unpack_long() 
		print("mc %i ac %i off %i" % ( mc, ac, off))
		i = self.__pos
		self.__pos = j = i+(ac*int((width/8)))
		data = self.__buf[i:j]
		if len(data) < ac:
			raise EOFError
		return data

	def unpack_raw(self, l):
		data = self.__buf[self.__pos:self.__pos+l]
		self.__pos = self.__pos + l
		return data


class Packer:
	"""Pack various data representations into a buffer."""

	def __init__(self, integer='le', char='ascii', floating='IEEE'):
		self.reset()
		self.integer = integer

	def reset(self):
		self.__buf = BytesIO()

	def get_buffer(self):
		return self.__buf.getvalue()

	
	def pack_small(self, x):
		"""8-bit integer"""
		self.__buf.write(struct.pack('<B', x))

	def pack_short(self, x):
		"""16-bit integer"""
		if self.__buf.tell() % 2 > 0:
			self.__buf.write('\0')
		if self.integer == 'le':
			self.__buf.write(struct.pack('<H', x))
		else:
			self.__buf.write(struct.pack('>H', x))

	def pack_long(self, x):
		"""32-bit integer"""
		align = self.__buf.tell() % 4
		if align > 0:
			self.__buf.write(b'\0'*align)
		if self.integer == 'le':
			self.__buf.write(struct.pack('<L', x))
		else:
			self.__buf.write(struct.pack('>L', x))

	def pack_hyper(self, x):
		"""64-bit integer"""
		align = self.__buf.tell() % 8
		if align > 0:
			self.__buf.write(b'\0'*align)
		if self.integer == 'le':
			self.__buf.write(struct.pack('<Q', x))
		else:
			self.__buf.write(struct.pack('>Q', x))

	def pack_pointer(self, x):
		self.pack_long(x)

	def pack_bool(self, x):
		if x: 
			self.__buf.write(b'\0\0\0\1')
		else: 
			self.__buf.write(b'\0\0\0\0')

	"""to obtain different maxcount and actualcount of the string"""
	def pack_string(self, s, offset=0, width=16):
		x = int(len(s)/(width/8))
		if (x % 8 == 0):
			maxcount = x
		else :
			maxcount = (int(x/8) + 1)*8
		self.pack_long(maxcount)
		self.pack_long(offset)
		self.pack_long(x)
		self.__buf.write(s)

	"""to obtain the same maxcount and actualcount of the string"""
	def pack_string_fix(self, s, offset=0, width=16):
		x = int(len(s)/(width/8))
		self.pack_long(x)
		self.pack_long(offset)
		self.pack_long(x)
		self.__buf.write(s)

	def pack_raw(self, s):
		self.__buf.write(s)




