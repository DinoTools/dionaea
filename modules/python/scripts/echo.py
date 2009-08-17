from dionaea import connection
class echo(connection):
	def __init__ (self, proto=None):
		print("echo init")
		connection.__init__(self,proto)
	def handle_established(self):
		print("new connection to serve!")
		self.send('welcome to reverse world!\n')
	def handle_io_in(self,data):
		print('py_io_in\n')
		self.send(data[::-1][1:] + b'\n')
		return len(data)

#
#e = echo(proto='tcp')
#e.bind('0.0.0.0',4713,'')
#e.listen()

