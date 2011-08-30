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

cdef extern from *:
	ctypedef char* const_char_ptr "const char*"


cdef extern from "module.h":
	cdef object bytesfrom "PyBytes_FromStringAndSize"(char *v, int len)
	cdef object stringfrom "PyUnicode_FromStringAndSize"(char *v, int len)
	int c_strlen "strlen" (char *)
	ctypedef int c_uintptr_t "uintptr_t"
	char * c_g_strdup "g_strdup" (char *)
	cdef object c_pygetifaddrs "pygetifaddrs"(object self, object args)
	cdef object c_pylcfg "pylcfg"(object self, object args)
	cdef object c_version "pyversion"(object self, object args)
	

#cdef extern from "../../include/dionaea.h":
	ctypedef struct c_dionaea "struct dionaea":
		pass
#
#	cdef extern c_dionaea *g_dionaea
#
cdef class dionaea:
	cdef c_dionaea *thisptr
	def config(self):
		return c_pylcfg(<object> None, <object> None)
	def getifaddrs(self):
		return c_pygetifaddrs(<object> None, <object> None)
	def version(self):
		return c_version(<object> None, <object> None)
	

g_dionaea = dionaea() 




cdef extern from "../../include/connection.h":

	ctypedef struct c_connection_ "struct connection":
		pass

	int c_ntohs "ntohs" (int)

#	ctypedef char* const_char_ptr "const char*"
	ctypedef bint c_bool "bool"
	ctypedef int c_connection_error "enum connection_error"
	ctypedef char c_unsigned_char "unsigned char "
	ctypedef  int c_uint32_t "uint32_t"

	ctypedef void *(*protocol_handler_ctx_new)(c_connection_ *con)
	ctypedef void (*protocol_handler_ctx_free)(void *data)
	ctypedef void (*protocol_handler_origin)(c_connection_ *origin, c_connection_ *con)
	ctypedef void (*protocol_handler_established)(c_connection_ *con)
	ctypedef c_bool (*protocol_handler_error)(c_connection_ *con, c_connection_error error)
	ctypedef c_bool (*protocol_handler_timeout)(c_connection_ *con, void *context)
	ctypedef unsigned int (*protocol_handler_io_in)(c_connection_ *con, void *context, c_unsigned_char *data, c_uint32_t size)
	ctypedef void (*protocol_handler_io_out)(c_connection_ *con, void *context)
	ctypedef c_bool (*protocol_handler_disconnect)(c_connection_ *con, void *context)
	ctypedef struct c_protocol "struct protocol":
		char 								*name
		protocol_handler_ctx_new  			ctx_new
		protocol_handler_ctx_free 			ctx_free
		protocol_handler_origin				origin
		protocol_handler_established 		established
		protocol_handler_error 				error
		protocol_handler_timeout 			idle_timeout
		protocol_handler_timeout 			sustain_timeout
		protocol_handler_timeout 			listen_timeout
		protocol_handler_disconnect 		disconnect
		protocol_handler_io_in 				io_in
		protocol_handler_io_out 			io_out
		void *ctx

	ctypedef struct c_node_info "struct node_info":
		char *ip_string
		char *port_string
		int port
		char *hostname





	char *c_node_info_get_ip_string "node_info_get_ip_string" (c_node_info *node)
	char *c_node_info_get_port_string "node_info_get_port_string" (c_node_info *node)
	void c_node_info_set_port "node_info_set_port" (c_node_info *, int )
	void c_node_info_set_addr "node_info_set_addr" (c_node_info *, char *)

	ctypedef enum c_connection_transport "enum connection_transport":
		pass

	ctypedef enum c_connection_state "enum connection_state":
		pass

	ctypedef struct c_connection_stats "struct connection_stats":
		pass

	double c_connection_stats_speed_get "connection_stats_speed_get"(c_connection_stats *)
	double c_connection_stats_speed_limit_get "connection_stats_speed_limit_get"(c_connection_stats *throttle)
	void c_connection_stats_speed_limit_set "connection_stats_speed_limit_set"(c_connection_stats *, double)
	double c_connection_stats_accounting_get "connection_stats_accounting_get"(c_connection_stats *)
	double c_connection_stats_accounting_limit_get "connection_stats_accounting_limit_get"(c_connection_stats *throttle)
	void c_connection_stats_accounting_limit_set "connection_stats_accounting_limit_set"(c_connection_stats *, double)


	ctypedef struct c_processor_data "struct processor_data":
		pass

	ctypedef struct c_connection_stats_info "struct connection_stats_info":
		c_connection_stats io_in
		c_connection_stats io_out

	ctypedef struct c_connection "struct connection":
		c_connection_transport trans
		c_protocol protocol
		c_connection_state state
		c_node_info remote
		c_node_info local
		c_connection_stats_info stats
		c_processor_data *processor_data

	bint c_connection_transport_from_string "connection_transport_from_string" (char *, c_connection_transport *)
	const_char_ptr c_connection_transport_to_string "connection_transport_to_string"(c_connection_transport)
	const_char_ptr c_connection_state_to_string "connection_state_to_string"(c_connection_state)
	c_connection *c_connection_new "connection_new" (c_connection_transport)
	void c_connection_free "connection_free"(c_connection *)
	int c_connection_bind "connection_bind" (c_connection *, char *, int, char *)
	int c_connection_listen "connection_listen" (c_connection *, int)
	void c_connection_connect "connection_connect" (c_connection *, char *, int port, char *)
	void c_connection_send "connection_send" (c_connection *, char *, int)
	void c_connection_close "connection_close" 	(c_connection *)
	void c_connection_process "connection_process" 	(c_connection *)
	
	void *c_cython_protocol_ctx_new "cython_protocol_ctx_new" (c_connection *)
	void c_cython_protocol_ctx_free "cython_protocol_ctx_free" (void *)

	void *c_connection_protocol_ctx_get "connection_protocol_ctx_get" (c_connection *)
	void c_connection_protocol_ctx_set "connection_protocol_ctx_set" (c_connection *, void *)

	void c_connection_listen_timeout_set "connection_listen_timeout_set"(c_connection *, double)
	double c_connection_listen_timeout_get "connection_listen_timeout_get"(c_connection *)
	void c_connection_sustain_timeout_set "connection_sustain_timeout_set"(c_connection *, double)
	double c_connection_sustain_timeout_get "connection_sustain_timeout_get"(c_connection *)
	void c_connection_idle_timeout_set "connection_idle_timeout_set"(c_connection *, double)
	double c_connection_idle_timeout_get "connection_idle_timeout_get"(c_connection *)
	void c_connection_handshake_timeout_set "connection_handshake_timeout_set"(c_connection *, double)
	double c_connection_handshake_timeout_get "connection_handshake_timeout_get"(c_connection *)
	void c_connection_connecting_timeout_set "connection_connecting_timeout_set"(c_connection *, double)
	double c_connection_connecting_timeout_get "connection_connecting_timeout_get"(c_connection *)
	void c_connection_reconnect_timeout_set "connection_reconnect_timeout_set"(c_connection *, double)
	double c_connection_reconnect_timeout_get "connection_reconnect_timeout_get"(c_connection *)

	int c_connection_ref "connection_ref"(c_connection *)
	int c_connection_unref "connection_unref"(c_connection *)
	
	void c_PyErr_Print "PyErr_Print"()
	

cdef class node_info:
	"""node_info stores information about a node"""
	cdef c_node_info *thisptr
	def __cinit__(self):
		self.thisptr = NULL

	def __init__(self):
		pass
	
	property host:
		"""the nodes address as string"""
		def __get__(self): 
			return bytes.decode(self.thisptr.ip_string, u'UTF-8')
		def __set__(self, addr):
			if isinstance(addr, unicode):
				addr = addr.encode(u'UTF-8')
			c_node_info_set_addr(self.thisptr, addr)

	property hostname:
		"""the nodes hostname as string"""
		def __get__(self):
			if self.thisptr.hostname != NULL:
				return bytes.decode(self.thisptr.hostname, u'UTF-8')
			else:
				return u''



	property port:
		"""the nodes port as integer in host byte order"""
		def __get__(self): 
			return c_ntohs(self.thisptr.port)
		def __set__(self, port):
			c_node_info_set_port(self.thisptr, port)

cdef class connection_speed:
	"""throttle information"""
	cdef c_connection_stats *thisptr

	def __cinit__(self):
		self.thisptr = NULL

	def __init__(self):
		pass

	property limit:
		"""the speed limit"""
		def __get__(self):
			return c_connection_stats_speed_limit_get(self.thisptr)
		def __set__(self, limit):
			c_connection_stats_speed_limit_set(self.thisptr, limit)

	property bps:
		"""the current speed in bytes per second"""
		def __get__(self):
			return c_connection_stats_speed_get(self.thisptr)
               
cdef connection_speed connection_speed_from(c_connection_stats *info):
	cdef connection_speed instance
	instance = NEW_C_NODE_INFO_CLASS(connection_speed)
	instance.thisptr = info
	return instance


cdef class connection_accounting:
	"""accounting information"""
	cdef c_connection_stats *thisptr

	def __cinit__(self):
		self.thisptr = NULL

	def __init__(self):
		pass

	property limit:
		"""the maximum amount of bytes we want to transfer here"""
		def __get__(self):
			return c_connection_stats_accounting_limit_get(self.thisptr)
		def __set__(self, limit):
			c_connection_stats_accounting_limit_set(self.thisptr, limit)

	property bytes:
		"""the amount of bytes we already transferred"""
		def __get__(self):
			return c_connection_stats_accounting_get(self.thisptr)
               
cdef connection_accounting connection_accounting_from(c_connection_stats *info):
	cdef connection_accounting instance
	instance = NEW_C_NODE_INFO_CLASS(connection_accounting)
	instance.thisptr = info
	return instance


cdef class connection_stats:
	"""connection information"""
	cdef c_connection_stats *thisptr

	def __cinit__(self):
		self.thisptr = NULL

	def __init__(self):
		pass

	property speed:
		"""access the connection_throttle informations for this connection"""
		def __get__(self):
			return connection_speed_from(self.thisptr)

	property accounting:
		"""access the connection_accounting informations for this connection"""
		def __get__(self):
			return connection_accounting_from(self.thisptr)
			
cdef connection_stats connection_stats_from(c_connection_stats *info):
	cdef connection_stats instance
	instance = NEW_C_NODE_INFO_CLASS(connection_stats)
	instance.thisptr = info
	return instance
		
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


cdef class connection_timeouts:
	cdef c_connection *thisptr

	def __cinit__(self):
		self.thisptr = NULL

	def __init__(self):
		pass

	property idle:
		"""repeating timeout for established connections, io action on the connection will restart the timeout"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return c_connection_idle_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			c_connection_idle_timeout_set(self.thisptr, to)
			
	property connecting:
		"""timeout for connections in progress"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return c_connection_connecting_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			c_connection_connecting_timeout_set(self.thisptr, to)
			
	property listen:
		"""timeout for listeners"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return c_connection_listen_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			c_connection_listen_timeout_set(self.thisptr, to)

	property reconnect:
		"""timeout before reconnecting the connection"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return c_connection_reconnect_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			c_connection_reconnect_timeout_set(self.thisptr, to)

	property handshake:
		"""timeout for the ssl handshake"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return c_connection_handshake_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			c_connection_handshake_timeout_set(self.thisptr, to)

	property sustain:
		"""timeout for the session"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return c_connection_sustain_timeout_get(self.thisptr)
		def __set__(self, to): 
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			c_connection_sustain_timeout_set(self.thisptr, to)


cdef extern from "./module.h":
	cdef connection_timeouts NEW_C_CONNECTION_TIMEOUTS_CLASS "PY_NEW"(object T)

cdef connection_timeouts connection_timeouts_from(c_connection *con):
	cdef connection_timeouts instance
	instance = NEW_C_CONNECTION_TIMEOUTS_CLASS(connection_timeouts)
	instance.thisptr = con
	return instance


cdef extern from "modules.h":
	void * c_traceable_ctx_new_cb "traceable_ctx_new_cb" (c_connection *con)
	void * c_traceable_ctx_free_cb "traceable_ctx_free_cb" (void *ctx)
	void c_traceable_origin_cb "traceable_origin_cb" (c_connection *origin, c_connection *con)
	void c_traceable_established_cb "traceable_established_cb" (c_connection *con)
	unsigned int c_traceable_io_in_cb "traceable_io_in_cb" (c_connection_ *con, void *context, c_unsigned_char *data, c_uint32_t size)
	void c_traceable_io_out_cb "traceable_io_out_cb"(c_connection *con, void *context)
	c_bool c_traceable_error_cb "traceable_error_cb" (c_connection *con, c_connection_error error)
	c_bool c_traceable_disconnect_cb "traceable_disconnect_cb" (c_connection *con, void *context)
	c_bool c_traceable_idle_timeout_cb "traceable_idle_timeout_cb"(c_connection *con, void *context)
	c_bool c_traceable_listen_timeout_cb "traceable_listen_timeout_cb" (c_connection *con, void *context)
	c_bool c_traceable_sustain_timeout_cb "traceable_sustain_timeout_cb" (c_connection *con, void *context)

cdef extern from "processor.h":
	ctypedef void (*processor_io)(c_connection *con, c_processor_data *pd, void *data, int size)
	ctypedef c_bool (*processor_process)(c_connection *con, void *config)
	ctypedef struct c_processor "struct processor":
		processor_io io_in
		processor_io io_out
		processor_process process
	void c_python_processor_bistream_create "python_processor_bistream_create"(c_connection *con)




cdef class connection:
	"""the connection"""

	cdef c_connection *thisptr
	cdef bint factory
	cdef object __weakref__


	def __cinit__(self):
#		print "hello cinit"
		self.thisptr = NULL
		self.factory = False
		

	def __init__(self, con_type=None):
		cdef c_connection_transport enum_type 
		
		if self.thisptr == NULL:
			if isinstance(con_type, unicode):
				con_type_utf8 = con_type.encode(u'UTF-8')
			else:
				raise ValueError(u"requires text input, got %s" % type(con_type))

			if not c_connection_transport_from_string(con_type_utf8, &enum_type):
				raise ValueError(str(con_type) + u'is not a valid protocol')
			self.thisptr = c_connection_new(enum_type)
#			print(u"XXXXXXXXXXXXX" + self.__class__.__name__)
			protoname = self.__class__.__name__
			protoname = protoname.encode(u'ascii')
			self.thisptr.protocol.name = c_g_strdup(protoname)
			self.thisptr.protocol.ctx_new = <protocol_handler_ctx_new>c_traceable_ctx_new_cb
			self.thisptr.protocol.ctx_free = <protocol_handler_ctx_free>c_traceable_ctx_free_cb
			self.thisptr.protocol.origin = <protocol_handler_origin>c_traceable_origin_cb
			self.thisptr.protocol.established = <protocol_handler_established>c_traceable_established_cb
			self.thisptr.protocol.error = <protocol_handler_error>c_traceable_error_cb
			self.thisptr.protocol.idle_timeout = <protocol_handler_timeout>c_traceable_idle_timeout_cb
			self.thisptr.protocol.sustain_timeout = <protocol_handler_timeout>c_traceable_sustain_timeout_cb
			self.thisptr.protocol.listen_timeout = <protocol_handler_timeout>c_traceable_listen_timeout_cb
			self.thisptr.protocol.io_in = <protocol_handler_io_in> c_traceable_io_in_cb
			self.thisptr.protocol.io_out = <protocol_handler_io_out> c_traceable_io_out_cb
			self.thisptr.protocol.disconnect = <protocol_handler_disconnect> c_traceable_disconnect_cb
			self.thisptr.protocol.ctx = <void *>self;
#		else:
#			print "connection is already assigned!"

		if self.factory == False and self.thisptr.protocol.ctx == <void *>self:
			INCREF(self)

#	def __dealloc__(self):
#		print "goodbye connection"
	
	# we want to be able to store connections in a dict
	# therefore we need __richcmp__ and __hash__
	# connection from the same c connection are equal
	# if you store connections in a dict, 
	# be aware to delete once the c-core free's them
	# as you'd access invalid memory else
	# could be addressed by making c_connection observeable
	# so it notices all observing python instances if it gets free'd
	# and sets their .thisptr to NULL
	# ... maybe later
	def __richcmp__(a, b, t):
		if not isinstance(a, connection) or not isinstance(b, connection):
			if t == 2: # ==
				return False
			if t == 3: # != 
				return True
			return NotImplemented

		if t == 0: # <
			return (<connection>a).thisptr < (<connection>b).thisptr

		if t == 1: # <=
			return (<connection>a).thisptr <= (<connection>b).thisptr

		if t == 2: # == 
			return (<connection>a).thisptr == (<connection>b).thisptr

		if t == 3: # != 
			return (<connection>a).thisptr != (<connection>b).thisptr

		if t == 4: # >
			return (<connection>a).thisptr > (<connection>b).thisptr

		if t == 5: # >=
			return (<connection>a).thisptr >= (<connection>b).thisptr

	def __hash__(self):
		return <long>self.thisptr


	def handle_established(self):
		"""callback once the connection is established"""
		pass
	
	def handle_disconnect(self):
		"""callback once the connection is disconnected
		for outbound connections, returning 1 will try to restablish the connection
		"""
		return 0

	def ref(self):
		return c_connection_ref(self.thisptr)

	def unref(self):
		return c_connection_unref(self.thisptr)

	def handle_origin(self, p):
		"""connection meets is parent"""
		pass

	def handle_timeout_sustain(self):
		"""callback for established connection session timeouts, return True to keep the connection"""
		return False

	def handle_timeout_idle(self):
		"""callback for established connection idle timeouts, return True to keep the connection"""
		return True

	def handle_timeout_listen(self):
		"""callback for listening timeouts, return True to keep the listener alive for a new period"""
		return False

	def handle_error(self, err):
		"""callback for connection errors"""
		pass
	

	def handle_io_in(self,data):
		"""callback for incoming data"""
#		print(data)
		return len(data)

	def handle_io_out(self):
		"""callback for flushed out buffer"""
		pass
		
	def bind(self, addr, port, iface=u''):
		"""bind the connection to a given addr and  port, iface is optional (for ipv6 local scope)"""
		if self.thisptr == NULL:
			raise ReferenceError(u'the object requested does not exist')

		if isinstance(addr, unicode):
			addr_utf8 = addr.encode(u'UTF-8')
		else:
			raise ValueError(u"addr requires text input, got %s" % type(addr))
		
		if isinstance(iface, unicode):
			iface_utf8 = iface.encode(u'UTF-8')
		elif not iface:
			iface_utf8 = u''.encode(u'UTF-8')
		else:
			raise ValueError(u"iface requires text input, got %s" % type(iface))

		return c_connection_bind(self.thisptr, addr_utf8, port, iface_utf8)
	
	def listen(self, size=20):
		"""listen on the bound connection, queuesize is optional (default is 20)"""
		if self.thisptr == NULL:
			raise ReferenceError(u'the object requested does not exist')
		return c_connection_listen(self.thisptr, size)

	def connect(self, addr, port, iface=u''):
		"""connect a remote host by ipv4/6 or domain on a given port using a specified iface (for ipv6 local scope)"""
		if self.thisptr == NULL:
			raise ReferenceError(u'the object requested does not exist')

		if isinstance(addr, unicode):
			addr_utf8 = addr.encode(u'UTF-8')
		else:
			raise ValueError(u"addr requires text input, got %s" % type(addr))

		if isinstance(iface, unicode):
			iface_utf8 = iface.encode(u'UTF-8')
		else:
			raise ValueError(u"iface requires text input, got %s" % type(iface))

		c_connection_connect(self.thisptr,addr_utf8,port,iface_utf8)

	def send(self, data, local=None, remote=None):
		"""send something to the remote"""
		if self.thisptr == NULL:
			raise ReferenceError(u'the object requested does not exist')
		if remote is not None and local is not None and self.transport == u'udp':
			if type(remote) is tuple:
				(host,port) = remote
				host = host.encode(u'UTF-8')
				c_node_info_set_addr(&self.thisptr.remote, host)
				c_node_info_set_port(&self.thisptr.remote, port)
			else:
				raise ValueError(u"requires tuple input, got %s" % type(remote))
			if type(local) is tuple:
				(host,port) = local
				host = host.encode(u'UTF-8')
				c_node_info_set_addr(&self.thisptr.local, host)
				c_node_info_set_port(&self.thisptr.local, port)
			else:
				raise ValueError(u"requires tuple input, got %s" % type(local))
		if isinstance(data, unicode):
			data_bytes = data.encode(u'UTF-8')
		elif isinstance(data, bytes):
			data_bytes = data
		else:
			raise ValueError(u"requires text/bytes input, got %s" % type(data))
		c_connection_send(self.thisptr, data_bytes, len(data_bytes))



	def close(self):
		"""close this connection"""
		if self.thisptr == NULL:
			raise ReferenceError(u'the object requested does not exist')
		c_connection_close(self.thisptr)

	def processors(self):
		"""process the data on this connection using the defined processors"""
		if self.thisptr == NULL:
			raise ReferenceError(u'the object requested does not exist')
		c_connection_process(self.thisptr)
#		c_python_processor_bistream_create(self.thisptr)
#		self.bistream = []



	property remote:
		"""access the node_info for the remote part of this connection"""
		def __get__(self): 
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return node_info_from(&self.thisptr.remote)

	property local:
		"""access the node_info for the local part of this connection"""
		def __get__(self): 
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return node_info_from(&self.thisptr.local)

	property timeouts:
		"""access the connection_timeouts for the connection"""
		def __get__(self): 
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return connection_timeouts_from(self.thisptr)
		
	property transport:
		"""connection transport as string, (tcp|udp|tls)"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return c_connection_transport_to_string(self.thisptr.trans).decode(u'UTF-8')

	property protocol:
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return self.thisptr.protocol.name.decode(u'UTF-8')

	property status:
		"""the connection status, resolving, connecting ...."""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return c_connection_state_to_string(self.thisptr.state).decode(u'UTF-8')

	property _in:
		"""access the connection_stats for the ingress part of the connection"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return connection_stats_from(&self.thisptr.stats.io_in)	

	property _out:
		"""access the connection_stats for the egress part of the connection"""
		def __get__(self):
			if self.thisptr == NULL:
				raise ReferenceError(u'the object requested does not exist')
			return connection_stats_from(&self.thisptr.stats.io_out)

# the static create method causes problems with cython 0.14
# not used anyway, so comment for now (tm)
#	create = staticmethod(connection_new)

def connection_new(type):
	""" create a new connection - for cli useage
	returns weakref to the connection"""
	return weakref.proxy(connection(type))



cdef extern from "./module.h":
	cdef connection CLONE_C_CONNECTION_CLASS "PY_CLONE"(object T)
	cdef connection NEW_C_CONNECTION_CLASS "PY_NEW"(object T)
	cdef void INIT_C_CONNECTION_CLASS "PY_INIT" (object P, object O)
#	cdef int PRINT_REFCOUNT "REFCOUNT"(object T)
	

cdef connection _factory(c_connection *con):
	cdef connection instance
	cdef connection parent = <object>c_connection_protocol_ctx_get(con)
	instance = CLONE_C_CONNECTION_CLASS(parent)
	instance.factory = True
	instance.thisptr = con
	INIT_C_CONNECTION_CLASS(parent,instance)
	c_connection_protocol_ctx_set(con, <void *>instance)
	return instance

cdef void _garbage(void *context):
#	print "get out the garbage !"
	cdef connection instance
	instance = <connection>context;
	instance.thisptr = NULL
	DECREF(instance)

cdef void handle_origin_cb(c_connection *con, c_connection *origin) except *:
#	print "origin_cb"
	cdef connection instance
	instance = <connection>c_connection_protocol_ctx_get(con)
	parent = <connection>c_connection_protocol_ctx_get(origin)
	instance.handle_origin(parent)

cdef void handle_established_cb(c_connection *con) except *:
#	print "established_cb"
	cdef connection instance
	instance = <connection>c_connection_protocol_ctx_get(con)
	instance.handle_established()

cdef int handle_io_in_cb(c_connection *con, void *context, void *data, int size) except *:
#	print "io_in_cb"
	cdef connection instance
	instance = <connection>context
	bdata = bytesfrom(<char *>data, size)
	l = instance.handle_io_in(bdata)
	return l
	
cdef void handle_io_out_cb(c_connection *con, void *context) except *:
#	print "io_out_cb"
	cdef connection instance
	instance = <connection>context
	instance.handle_io_out()
	
cdef c_bool handle_disconnect_cb(c_connection *con, void *context) except *:
#	print "disconnect_cb"
	cdef connection instance
	instance = <connection>context
	r = instance.handle_disconnect()
	if r == 0:
		instance.thisptr = NULL
	return <bint>r

cdef c_bool handle_error_cb(c_connection *con, c_connection_error err) except *:
#	print "connect_error_cb"
	cdef connection instance
	instance = <connection>c_connection_protocol_ctx_get(con)
	r = instance.handle_error(err)
	return <bint>r

cdef c_bool handle_timeout_sustain_cb(c_connection *con, void *ctx) except *:
#	print "timeout_sustain_cb"
	cdef connection instance
	instance = <connection>ctx
	return <bint> instance.handle_timeout_sustain()

cdef c_bool handle_timeout_listen_cb(c_connection *con, void *ctx) except *:
#	print "timeout_listen_cb"
	cdef connection instance
	instance = <connection>ctx
	return <bint> instance.handle_timeout_listen()


cdef c_bool handle_timeout_idle_cb(c_connection *con, void *ctx) except *:
#	print "timeout_idle_cb"
	cdef connection instance
	instance = <connection>ctx
	return <bint> instance.handle_timeout_idle()


cdef void process_io_in(c_connection *con, c_processor_data *pd, void *data, int size) except *:
	bdata = bytesfrom(<char *>data, size)
	cdef connection instance
	instance = <connection>c_connection_protocol_ctx_get(con)

	if instance.thisptr.processor_data != NULL:
		if len(instance.bistream) > 0 and instance.bistream[-1][0] == u'in':
			instance.bistream[-1] = (u'in', instance.bistream[-1][1] + bdata)
		else:
			instance.bistream.append((u'in',bdata))
	return

cdef void process_io_out(c_connection *con, c_processor_data *pd, void *data, int size) except *:
	cdef connection instance
	instance = <connection>c_connection_protocol_ctx_get(con)
	if instance.thisptr.processor_data != NULL:
		bdata = bytesfrom(<char *>data, size)
		if len(instance.bistream) > 0 and instance.bistream[-1][0] == u'out':
			instance.bistream[-1] = (u'out', instance.bistream[-1][1] + bdata)
		else:
			instance.bistream.append((u'out',bdata))
	return

cdef c_bool process_process(c_connection *con, void *config) except *:
	cdef connection instance
	instance = <connection>c_connection_protocol_ctx_get(con)
	instance.bistream = []

def dlhfn(name, number, path, line, msg):
	if isinstance(name, unicode):
		name = name.encode(u'UTF-8')
	if isinstance(path, unicode):
		path = path.encode(u'UTF-8')
	if isinstance(msg, unicode):
		msg = msg.encode(u'UTF-8')
	c_log_wrap(name, number, path, line, msg)
	

cdef extern from "glib.h": 
	ctypedef struct c_GString "GString":
		char *str
		int len
	c_GString *c_g_string_new "g_string_new" (char *)

	ctypedef struct c_GList "GList":
		void *data

	ctypedef void *gpointer
	ctypedef void *gconstpointer
	ctypedef int gint
	ctypedef unsigned int guint
	ctypedef unsigned long gulong
	ctypedef signed long long gint64
	ctypedef unsigned long long guint64
	ctypedef gint gboolean
	ctypedef gboolean (*GSourceFunc) (gpointer data)
	ctypedef unsigned int gsize
	ctypedef signed int gssize
	ctypedef char gchar
	ctypedef unsigned char guchar

	ctypedef void (*GCallback) ()
	ctypedef void (*GDestroyNotify) (gpointer)

	ctypedef guint GHashFunc (gconstpointer)
	ctypedef gboolean GEqualFunc (gconstpointer, gconstpointer)

	ctypedef struct GHashTable:
		pass
	ctypedef struct GHashTableIter:
		pass
	void g_hash_table_iter_init(GHashTableIter *iter, GHashTable *hash_table)
	gboolean g_hash_table_iter_next(GHashTableIter *iter, gpointer *key, gpointer *value)
	gboolean g_str_equal (gconstpointer, gconstpointer)
	guint g_str_hash (gconstpointer)

	GHashTable *g_hash_table_new (GHashFunc *, GEqualFunc *)
	void g_hash_table_destroy (GHashTable*)
	void g_hash_table_insert (GHashTable*, gpointer, gpointer)
	gpointer g_hash_table_lookup (GHashTable*, gconstpointer)


	c_GList *c_g_list_append "g_list_append" (c_GList *l, void *data)
	c_GList *c_g_list_first "g_list_first" (c_GList *l)
	c_GList *c_g_list_next "g_list_next" (c_GList *l)

cdef extern from "../../include/incident.h":
	ctypedef enum c_opaque_data_type "opaque_data_type":
		opaque_type_none
		opaque_type_string
		opaque_type_int
		opaque_type_ptr
		opaque_type_list
		opaque_type_dict

	ctypedef struct c_opaque_data "struct opaque_data":
		c_opaque_data_type type
		char *name

	c_opaque_data *c_opaque_data_new "opaque_data_new"()
	void c_opaque_data_free "opaque_data_free"(c_opaque_data *d)
	void c_opaque_data_string_set "opaque_data_string_set" (c_opaque_data *d, c_GString *val)
	void c_opaque_data_int_set    "opaque_data_int_set"    (c_opaque_data *d, long int val)
	void c_opaque_data_con_set    "opaque_data_con_set"    (c_opaque_data *d, c_connection *val)
	void c_opaque_data_list_set   "opaque_data_list_set"   (c_opaque_data *d, c_GList *val)
	void c_opaque_data_dict_set   "opaque_data_dict_set"   (c_opaque_data *d, GHashTable *val)
	void c_opaque_data_none_set   "opaque_data_none_get"   (c_opaque_data *d)

	void c_opaque_data_string_get "opaque_data_string_get" (c_opaque_data *d, c_GString **val)
	void c_opaque_data_int_get    "opaque_data_int_get"    (c_opaque_data *d, long int *val)
	void c_opaque_data_con_get    "opaque_data_con_get"    (c_opaque_data *d, c_connection **val)
	void c_opaque_data_list_get   "opaque_data_list_get"   (c_opaque_data *d, c_GList **val)
	void c_opaque_data_dict_get   "opaque_data_dict_get"   (c_opaque_data *d, GHashTable **val)
	void c_opaque_data_none_get   "opaque_data_none_get"   (c_opaque_data *d)

	ctypedef struct c_incident "struct incident":
		char *origin

	c_incident *c_incident_new "incident_new"(char *origin)
	void c_incident_report "incident_report" (c_incident *i)

	void c_incident_free "incident_free"(c_incident *)

	c_bool c_incident_value_int_set "incident_value_int_set" (c_incident *,  char *, long int)
	c_bool c_incident_value_int_get "incident_value_int_get" (c_incident *e, char *name, long int *val)
	c_bool c_incident_value_con_set "incident_value_con_set" (c_incident *e, char *name, c_connection *val)
	c_bool c_incident_value_con_get "incident_value_con_get" (c_incident *e, char *name, c_connection **val)
	c_bool c_incident_value_string_set "incident_value_string_set" (c_incident *e, char *name, c_GString *str)
	c_bool c_incident_value_string_get "incident_value_string_get" (c_incident *e, char *name, c_GString **str)
	c_bool c_incident_value_list_set "incident_value_list_set" (c_incident *e, char *name, c_GList *val)
	c_bool c_incident_value_list_get "incident_value_list_get" (c_incident *e, char *name, c_GList **val)
	c_bool c_incident_value_dict_set "incident_value_dict_set" (c_incident *e, char *name, GHashTable *val)
	c_bool c_incident_value_dict_get "incident_value_dict_get" (c_incident *e, char *name, GHashTable **val)
	c_bool c_incident_value_none_set "incident_value_none_set"(c_incident *e, char *name)
	c_bool c_incident_value_none_get "incident_value_none_get"(c_incident *e, char *name)

	c_bool c_incident_keys_get "incident_keys_get" (c_incident *e, char ***keys)
	void c_incident_dump "incident_dump" (c_incident *)



cdef c_GList *py_to_glist(l):
	cdef c_GList *gl
	gl = NULL
	for i in l:
		print(i)
		gl = c_g_list_append(gl, py_to_opaque(i))
	return gl

cdef py_from_glist(c_GList *l):
	cdef c_GList *it
	it = c_g_list_first(l)
	pl = []
	while it != NULL:
		pl.append(py_from_opaque(<c_opaque_data *>it.data))
		it = c_g_list_next(it)
	return pl

cdef GHashTable *py_to_ghashtable(d):
	cdef GHashTable *gd
	cdef char *kn
	cdef c_opaque_data *op
	gd = g_hash_table_new(g_str_hash, g_str_equal)
	for k,v in d.items():
		x = repr(k)
		x = x.encode('ascii')
		op = py_to_opaque(v)
		op.name = c_g_strdup(x)
		g_hash_table_insert(gd, op.name, op)
	return gd

cdef py_from_ghashtable(GHashTable *h):
	cdef GHashTableIter iter
	cdef gpointer key
	cdef gpointer value
	a = {}
	g_hash_table_iter_init (&iter, h)
	while g_hash_table_iter_next(&iter, &key, &value):
		skey = <char *>key
		skey = skey.decode('ascii')
		a[skey] = py_from_opaque(<c_opaque_data *>value)
	return a

cdef c_opaque_data *py_to_opaque(value):
	cdef c_opaque_data *o
	o = c_opaque_data_new()
	if isinstance(value, connection) :
		con = <connection>value
		c_opaque_data_con_set(o,con.thisptr)
	elif isinstance(value, int) :
		c_opaque_data_int_set(o, value)
	elif isinstance(value, unicode):
		value = value.encode(u'UTF-8')
		c_opaque_data_string_set(o, c_g_string_new(value))
	elif isinstance(value, bytes):
		c_opaque_data_string_set(o, c_g_string_new(value))
	elif isinstance(value, list):
		c_opaque_data_list_set(o, py_to_glist(value))
	elif isinstance(value, dict):
		c_opaque_data_dict_set(o, py_to_ghashtable(value))
	elif value is None:
		c_opaque_data_none_set(o)
	else:
		c_opaque_data_free(o)
		return NULL
	return o

cdef py_from_opaque(c_opaque_data *value):
	cdef c_uintptr_t x
	cdef connection c
	cdef c_connection *cc
	cdef c_GString *s
	cdef long int i
	cdef c_GList *l
	cdef GHashTable *d
	if value.type == opaque_type_string:
		c_opaque_data_string_get(value, &s)
		return stringfrom(s.str, s.len)
	elif value.type == opaque_type_int:
		c_opaque_data_int_get(value, &i)
		return i
	elif value.type == opaque_type_ptr:
		c_opaque_data_con_get(value,&cc)
		c = NEW_C_CONNECTION_CLASS(connection)
		c.thisptr = <c_connection *>cc
		INIT_C_CONNECTION_CLASS(c, c)
		return c
	elif value.type == opaque_type_list:
		c_opaque_data_list_get(value,&l)
		return py_from_glist(l)
	elif value.type == opaque_type_dict:
		c_opaque_data_dict_get(value,&d)
		return py_from_ghashtable(d)
	elif value.type == opaque_type_none:
		return None

cdef class incident:
	cdef c_incident *thisptr
	cdef bint free_on_dealloc

	def __init__(self, origin=None):
		if origin != None and self.thisptr == NULL:
			origin = origin.encode(u'UTF-8')
			self.thisptr = c_incident_new(origin)
			self.free_on_dealloc = 1
		else:
			self.free_on_dealloc = 0

	def __dealloc__(self):
		if self.free_on_dealloc == 1:
			c_incident_free(self.thisptr)


	def dump(self):
		c_incident_dump(self.thisptr)

	def keys(self):
		cdef char **x
		cdef int i = 0
		c_incident_keys_get(self.thisptr, &x)
		r = []
		while x[i] is not NULL:
			r.append(x[i])
			i = i+1
		return r


	def set(self, key, value):
		self.__setattr__(key, value)

	def get(self, key):
		return self.__getattr__(key)

	def __setattr__(self, key, value):
		cdef connection con
		if isinstance(key, unicode):
			key = key.encode(u'UTF-8')
		
		if isinstance(value, connection) :
			con = <connection>value
			c_incident_value_con_set(self.thisptr, key, con.thisptr)
		elif isinstance(value, int) :
			c_incident_value_int_set(self.thisptr, key, value)
		elif isinstance(value, unicode):
			value = value.encode(u'UTF-8')
			c_incident_value_string_set(self.thisptr, key, c_g_string_new(value))
		elif isinstance(value, bytes):
			c_incident_value_string_set(self.thisptr, key, c_g_string_new(value))
		elif isinstance(value, list):
			c_incident_value_list_set(self.thisptr, key, py_to_glist(value))
		elif isinstance(value, dict):
			c_incident_value_dict_set(self.thisptr, key, py_to_ghashtable(value))

	def __getattr__(self, key):
		cdef c_uintptr_t x
		cdef connection c
		cdef c_connection *cc
		cdef c_GString *s
		cdef long int i
		cdef c_GList *l
		cdef GHashTable *d
		if isinstance(key, unicode):
			key = key.encode(u'UTF-8')
		if c_incident_value_con_get(self.thisptr, key, &cc) == True:
			c = NEW_C_CONNECTION_CLASS(connection)
			c.thisptr = <c_connection *>cc
			INIT_C_CONNECTION_CLASS(c, c)
			return c
		elif c_incident_value_string_get(self.thisptr, key, &s) == True:
			return stringfrom(s.str, s.len)
		elif c_incident_value_int_get(self.thisptr, key, &i) == True:
			return i
		elif c_incident_value_list_get(self.thisptr,key,&l) == True:
			return py_from_glist(l)
		elif c_incident_value_dict_get(self.thisptr,key,&d) == True:
			return py_from_ghashtable(d)
		else:
			raise AttributeError(u"%s does not exist" % key.decode(u'UTF-8'))

	def report(self):
		c_incident_report(self.thisptr)


	property origin:
		def __get__(self):
			return stringfrom(self.thisptr.origin, c_strlen(self.thisptr.origin));

cdef extern from "module.h":
	cdef incident NEW_C_INCIDENT_CLASS "PY_NEW"(object T)
	cdef void INIT_C_INCIDENT_CLASS "PY_INIT" (object P, object O)

######
cdef extern from "../../include/incident.h":

	ctypedef void (*ihandler_cb) (c_incident *, void *ctx)
	ctypedef struct c_ihandler "struct ihandler":
		ihandler_cb cb


	c_ihandler *c_ihandler_new "ihandler_new" (char *, ihandler_cb cb, void *ctx)
	void c_ihandler_free "ihandler_free" (c_ihandler *)

cdef extern from "module.h":
	void c_traceable_ihandler_cb "traceable_ihandler_cb" (c_incident *, void *)

cdef void c_python_ihandler_cb (c_incident *i, void *ctx) except *:
	cdef ihandler handler
	cdef incident pi
	handler = <ihandler>ctx
	pi = NEW_C_INCIDENT_CLASS(incident)
	pi.thisptr = i
	INIT_C_INCIDENT_CLASS(pi,pi)
	origin = pi.origin
	if isinstance(origin, bytes):
		origin = origin.decode(u'ascii')
	elif not isinstance(origin, unicode):
		raise ValueError(u"requires text/bytes input, got %s" % type(origin))
	origin = origin.replace(u".",u"_")
	try:
		method = getattr(handler, u"handle_incident_" + origin)
	except:
		handler.handle_incident(pi)
		return

	method(pi)
	

cdef class ihandler:
	cdef c_ihandler *thisptr
	def __init__(self, pattern):
		pattern = pattern.encode(u'UTF-8')
		self.thisptr = c_ihandler_new(pattern, <ihandler_cb> c_traceable_ihandler_cb, <void *>self)

	def __dealloc__(self):
		c_ihandler_free(self.thisptr)

	def start(self):
		pass

	def stop(self):
		pass

	def register(self):
		pass

	def unregister(self):
		pass

	def handle_incident(self, i):
		pass

cdef extern from "modules.h":
	void c_set_protocol "set_protocol" (c_protocol *)
	void c_set_ihandler "set_ihandler" (c_ihandler *)
	void c_set_processor "set_processor" (c_processor *)

def init_traceables():
	cdef c_protocol proto
	proto.ctx_new = <protocol_handler_ctx_new>_factory
	proto.ctx_free = <protocol_handler_ctx_free>_garbage
	proto.origin = <protocol_handler_origin> handle_origin_cb
	proto.established = <protocol_handler_established>handle_established_cb
	proto.error = <protocol_handler_error>handle_error_cb
	proto.idle_timeout = <protocol_handler_timeout>handle_timeout_idle_cb
	proto.sustain_timeout = <protocol_handler_timeout>handle_timeout_sustain_cb
	proto.listen_timeout = <protocol_handler_timeout>handle_timeout_listen_cb
	proto.io_in = <protocol_handler_io_in> handle_io_in_cb
	proto.io_out = <protocol_handler_io_out> handle_io_out_cb
	proto.disconnect = <protocol_handler_disconnect> handle_disconnect_cb
	c_set_protocol(&proto)


	cdef c_ihandler ih
	ih.cb = <ihandler_cb>c_python_ihandler_cb
	c_set_ihandler(&ih);

	cdef c_processor p
	p.io_in = <processor_io>process_io_in
	p.io_out = <processor_io>process_io_out
	p.process = <processor_process>process_process
	c_set_processor(&p)
	
###
	
