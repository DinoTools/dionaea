from . import PrinterConnection

class TestPCLCommands:
    def test_print_hello_world(self):
        connection = PrinterConnection()
        connection.send(b"\x1bEHello World")
        connection.disconnect()
