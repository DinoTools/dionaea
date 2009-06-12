#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter
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

import weakref

cdef extern from "../../include/connection.h":

	ctypedef struct c_connection_ "struct connection":
		pass

	int c_ntohs "ntohs" (int)

	ctypedef void *(*protocol_handler_ctx_new)(c_connection_ *con)
	ctypedef void (*protocol_handler_ctx_free)(void *data)
	ctypedef void (*protocol_handler_established)(c_connection_ *con)
	ctypedef void (*protocol_handler_error)(c_connection_ *con, int error)
	ctypedef int (*protocol_handler_timeout)(c_connection_ *con, void *context)
	ctypedef unsigned int (*protocol_handler_io_in)(c_connection_ *con, void *context, char *data, int size)
	ctypedef void (*protocol_handler_io_out)(c_connection_ *con, void *context)
	ctypedef int (*protocol_handler_disconnect)(c_connection_ *con, void *context)
	ctypedef struct c_protocol "struct protocol":
		protocol_handler_ctx_new  			ctx_new
		protocol_handler_ctx_free 			ctx_free
		protocol_handler_established 		established
		protocol_handler_error 		error
		protocol_handler_timeout 			timeout
		protocol_handler_disconnect 		disconnect
		protocol_handler_io_in 				io_in
		protocol_handler_io_out 			io_out
		void *ctx

	ctypedef struct c_node_info "struct node_info":
		char *ip_string
		char *port_string
		int port

	char *c_node_info_get_ip_string "node_info_get_ip_string" (c_node_info *node)
	char *c_node_info_get_port_string "node_info_get_port_string" (c_node_info *node)

	ctypedef enum c_connection_transport "enum connection_transport":
		pass

	ctypedef enum c_connection_state "enum connection_state":
		pass

	ctypedef struct c_connection_throttle_info "struct connection_throttle_info":
		pass

	double c_connection_throttle_info_speed_get "connection_throttle_info_speed_get"(c_connection_throttle_info *)
	double c_connection_throttle_info_limit_get "connection_throttle_info_limit_get"(c_connection_throttle_info *throttle)
	void c_connection_throttle_info_limit_set "connection_throttle_info_limit_set"(c_connection_throttle_info *, double)


	ctypedef struct c_connection_stats "struct connection_stats":
		c_connection_throttle_info io_in
		c_connection_throttle_info io_out

	ctypedef struct c_connection "struct connection":
		c_connection_transport trans
		c_protocol protocol
		c_connection_state state
		c_node_info remote
		c_node_info local
		c_connection_stats stats


	bint c_connection_transport_from_string "connection_transport_from_string" (char *, c_connection_transport *)
	char *c_connection_transport_to_string "connection_transport_to_string"(c_connection_transport)
	char *c_connection_state_to_string "connection_state_to_string"(c_connection_state)
	c_connection *c_connection_new "connection_new" (c_connection_transport)
	void c_connection_free "connection_free"(c_connection *)
	int c_connection_bind "connection_bind" (c_connection *, char *, int, char *)
	int c_connection_listen "connection_listen" (c_connection *, int)
	void c_connection_connect "connection_connect" (c_connection *, char *, int port, char *)
	void c_connection_send "connection_send" (c_connection *, char *, int)
	void c_connection_close "connection_close" 	(c_connection *)
	
	void *c_cython_protocol_ctx_new "cython_protocol_ctx_new" (c_connection *)
	void c_cython_protocol_ctx_free "cython_protocol_ctx_free" (void *)

	void *c_connection_protocol_ctx_get "connection_protocol_ctx_get" (c_connection *)
	void c_connection_protocol_ctx_set "connection_protocol_ctx_set" (c_connection *, void *)

	void c_connection_listen_timeout_set "connection_listen_timeout_set"(c_connection *, double)
	double c_connection_listen_timeout_get "connection_listen_timeout_get"(c_connection *)
	void c_connection_connect_timeout_set "connection_connect_timeout_set"(c_connection *, double)
	double c_connection_connect_timeout_get "connection_connect_timeout_get"(c_connection *)
	void c_connection_handshake_timeout_set "connection_handshake_timeout_set"(c_connection *, double)
	double c_connection_handshake_timeout_get "connection_handshake_timeout_get"(c_connection *)
	void c_connection_connecting_timeout_set "connection_connecting_timeout_set"(c_connection *, double)
	double c_connection_connecting_timeout_get "connection_connecting_timeout_get"(c_connection *)
	void c_connection_reconnect_timeout_set "connection_reconnect_timeout_set"(c_connection *, double)
	double c_connection_reconnect_timeout_get "connection_reconnect_timeout_get"(c_connection *)
	
	void c_node_info_set_port "node_info_set_port" (c_node_info *, int )

	void c_PyErr_Print "PyErr_Print"()
	

cdef class node_info:
	"""node_info stores information about a node"""
	cdef c_node_info *thisptr
	def __cinit__(self):
		self.thisptr = NULL

	def __init__(self):
		pass
	
	property host:
		def __get__(self): 
			return bytes.decode(self.thisptr.ip_string)

	property port:
		def __get__(self): 
			return c_ntohs(self.thisptr.port)
		def __set__(self, port):
			c_node_info_set_port(self.thisptr, port)

cdef class connection_throttle_info:
	"""throttle information"""
	cdef c_connection_throttle_info *thisptr
	def __cinit__(self):
		self.thisptr = NULL
	def __init__(self):
		pass
	property throttle:
		def __get__(self):
			return c_connection_throttle_info_limit_get(self.thisptr)
		def __set__(self, limit):
			c_connection_throttle_info_limit_set(self.thisptr, limit)
	property speed:
		def __get__(self):
			return c_connection_throttle_info_speed_get(self.thisptr)
			
cdef connection_throttle_info connection_throttle_info_from(c_connection_throttle_info *info):
	cdef connection_throttle_info instance
	instance = NEW_C_NODE_INFO_CLASS(connection_throttle_info)
	instance.thisptr = info
	return instance
		
#cdef class connection_stats:
#	"""stats about in/out traffic"""
#	cdef c_connection_stats *thisptr
#	def __cinit__(self):
#		self.thisptr = NULL
#	def __init__(self):
#		pass
#	property _in:
#		def __get__(self):
#			return connection_throttle_info_from(&self.thisptr.io_in)
#		
#	property _out:
#		def __get__(self):
#			return connection_throttle_info_from(&self.thisptr.io_out)
#
#
#cdef connection_stats connection_stats_from(c_connection_stats *stats):
#	cdef connection_stats instance
#	instance = NEW_C_NODE_INFO_CLASS(connection_stats)
#	instance.thisptr = stats
#	return instance
	

	


cdef extern from "./module.h":
	cdef node_info NEW_C_NODE_INFO_CLASS "PY_NEW"(object T)
	cdef void INCREF "Py_INCREF"(object)
	cdef void DECREF "Py_DECREF"(object)
	void c_log_wrap "log_wrap" (char *, int, char *, int, char *)

cdef node_info node_info_from(c_node_info *node):
	cdef node_info instance
	instance = NEW_C_NODE_INFO_CLASS(node_info)
	instance.thisptr = node
	return instance

cdef class connection:
	"""the connection"""

	cdef c_connection *thisptr
	cdef bint factory
	cdef object __weakref__

	def __cinit__(self):
#		print "hello cinit"
		self.thisptr = NULL
		self.factory = False

	def __init__(self, con_type):
		"""constructor do not use on cli, use connection.create instead"""
		cdef c_connection_transport enum_type 
		if self.thisptr == NULL:
			if isinstance(con_type, unicode):
				con_type_utf8 = con_type.encode(u'UTF-8')
			else:
				raise ValueError("requires text input, got %s" % type(con_type))

			if not c_connection_transport_from_string(con_type_utf8, &enum_type):
				raise ValueError(str(con_type) + 'is not a valid protocol')
			self.thisptr = c_connection_new(enum_type)
			self.thisptr.protocol.ctx_new = <protocol_handler_ctx_new>_factory
			self.thisptr.protocol.ctx_free = <protocol_handler_ctx_free>_garbage
			self.thisptr.protocol.established = <protocol_handler_established>established_cb
			self.thisptr.protocol.error = <protocol_handler_error>connect_error_cb
			self.thisptr.protocol.timeout = <protocol_handler_timeout>timeout_cb
			self.thisptr.protocol.io_in = <protocol_handler_io_in> io_in_cb
			self.thisptr.protocol.io_out = <protocol_handler_io_out> io_out_cb
			self.thisptr.protocol.disconnect = <protocol_handler_disconnect> disconnect_cb
			self.thisptr.protocol.ctx = <void *>self;
#		else:
#			print "connection is already assigned!"

		if self.factory == False:
			INCREF(self)

#	def __dealloc__(self):
#		print "goodbye connection"
	
	def established(self):
		"""callback once the connection is established"""
		pass
	
	def disconnect(self):
		"""callback once the connection is disconnected
		for outbound connections, returning 1 will try to restablish the connection
		"""
		return 0

	def learn(self, p):
		pass

	def timeout(self):
		"""callback for established connection timeouts, return 1 to reestablish the connection"""
		return True

	def error(self, err):
		"""callback for connection errors"""
		pass
	

	def io_in(self,data):
		"""callback for incoming data"""
#		print(data)
		return len(data)

	def io_out(self):
		"""callback for flushed out buffer"""
		pass
		
	def bind(self, addr, port, iface=u''):
		"""bind the connection to a given addr and  port, iface is optional (for ipv6 local scope)"""
		if self.thisptr == NULL:
			raise ReferenceError('the object requested does not exist')

		if isinstance(addr, unicode):
			addr_utf8 = addr.encode(u'UTF-8')
		else:
			raise ValueError(u"requires text input, got %s" % type(addr))
		
		if isinstance(iface, unicode):
			iface_utf8 = iface.encode(u'UTF-8')
		else:
			raise ValueError(u"requires text input, got %s" % type(iface))
		return c_connection_bind(self.thisptr, addr_utf8, port, iface_utf8)
	
	def listen(self, size=20):
		"""listen on the bound connection, queuesize is optional (default is 20)"""
		if self.thisptr == NULL:
			raise ReferenceError('the object requested does not exist')
		return c_connection_listen(self.thisptr, size)

	def connect(self, addr, port, iface=u''):
		"""connect a remote host by ipv4/6 or domain on a given port using a specified iface (for ipv6 local scope)"""
		if self.thisptr == NULL:
			raise ReferenceError('the object requested does not exist')

		if isinstance(addr, unicode):
			addr_utf8 = addr.encode(u'UTF-8')
		else:
			raise ValueError(u"requires text input, got %s" % type(addr))

		if isinstance(iface, unicode):
			iface_utf8 = iface.encode(u'UTF-8')
		else:
			raise ValueError(u"requires text input, got %s" % type(iface))

		c_connection_connect(self.thisptr,addr_utf8,port,iface_utf8)

	def send(self, data):
		"""send something to the remote"""
		if self.thisptr == NULL:
			raise ReferenceError('the object requested does not exist')
		if isinstance(data, unicode):
			data_bytes = data.encode()
		elif isinstance(data, bytes):
			data_bytes = data
		else:
			raise ValueError(u"requires text/bytes input, got %s" % type(data))

		c_connection_send(self.thisptr, data_bytes, len(data_bytes))

	def close(self):
		"""close this connection"""
		if self.thisptr == NULL:
			raise ReferenceError('the object requested does not exist')
		c_connection_close(self.thisptr)


	property remote:
		def __get__(self): 
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return node_info_from(&self.thisptr.remote)

	property local:
		def __get__(self): 
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return node_info_from(&self.thisptr.local)


	property connect_timeout:
		"""repeating timeout for established connections, io action on the connection will restart the timeout"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return c_connection_connect_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			c_connection_connect_timeout_set(self.thisptr, to)
			
	property connecting_timeout:
		"""timeout for connections in progress"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return c_connection_connecting_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			c_connection_connecting_timeout_set(self.thisptr, to)
			
	property listen_timeout:
		"""timeout for listeners"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return c_connection_listen_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			c_connection_listen_timeout_set(self.thisptr, to)

	property reconnect_timeout:
		"""timeout before reconnecting the connection"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return c_connection_reconnect_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			c_connection_reconnect_timeout_set(self.thisptr, to)

	property handshake_timeout:
		"""timeout for the ssl handshake"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return c_connection_handshake_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			c_connection_handshake_timeout_set(self.thisptr, to)

	property transport:
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return c_connection_transport_to_string(self.thisptr.trans).decode()

	property status:
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return c_connection_state_to_string(self.thisptr.state).decode()

	property _in:
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return connection_throttle_info_from(&self.thisptr.stats.io_in)	

	property _out:
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError('the object requested does not exist')
			return connection_throttle_info_from(&self.thisptr.stats.io_out)


	create = staticmethod(connection_new)

def connection_new(type):
	""" create a new connection - for cli useage
	returns weakref to the connection"""
	return weakref.proxy(connection(type))



cdef extern from "./module.h":
	cdef connection CLONE_C_CONNECTION_CLASS "PY_CLONE"(object T)
	cdef void INIT_C_CONNECTION_CLASS "PY_INIT" (object P, object O)
#	cdef int PRINT_REFCOUNT "REFCOUNT"(object T)
	cdef object stringfrom "PyBytes_FromStringAndSize"(char *v, int len)
	

cdef connection _factory(c_connection *con):
	cdef connection instance
	cdef connection parent = <object>c_connection_protocol_ctx_get(con)
	instance = CLONE_C_CONNECTION_CLASS(parent)
	instance.factory = True
	instance.thisptr = con
	INIT_C_CONNECTION_CLASS(parent,instance)
	c_connection_protocol_ctx_set(con, <void *>instance)
	instance.learn(parent)
	return instance

cdef void _garbage(void *context):
#	print "get out the garbage !"
	cdef connection instance
	instance = <connection>context;
	instance.thisptr = NULL
	DECREF(instance)


cdef void established_cb(c_connection *con) except *:
#	print "established_cb"
	cdef connection instance
	instance = <connection>c_connection_protocol_ctx_get(con)
	instance.established()

cdef int io_in_cb(c_connection *con, void *context, void *data, int size) except *:
#	print "io_in_cb"
	cdef connection instance
	instance = <connection>context
	return instance.io_in(stringfrom(<char *>data, size))
	
cdef int io_out_cb(c_connection *con, void *context) except *:
#	print "io_out_cb"
	cdef connection instance
	instance = <connection>context
	instance.io_out()
	
cdef int disconnect_cb(c_connection *con, void *context) except *:
#	print "disconnect_cb"
	cdef connection instance
	instance = <connection>context
	r = instance.disconnect()
	if r == 0:
		instance.thisptr = NULL
	return r

cdef void connect_error_cb(c_connection *con, int err) except *:
#	print "connect_error_cb"
	cdef connection instance
	instance = <connection>c_connection_protocol_ctx_get(con)
	instance.error(err)

cdef bint timeout_cb(c_connection *con, void *ctx) except *:
#	print "timeout_cb"
	cdef connection instance
	instance = <connection>ctx
	return instance.timeout()

def dlhfn(name, number, path, line, msg):
	if isinstance(name, unicode):
		name = name.encode()
	if isinstance(path, unicode):
		path = path.encode()
	if isinstance(msg, unicode):
		msg = msg.encode()
	c_log_wrap(name, number, path, line, msg)
	
