from . import PrinterConnection

class TestPCLCommands:
    def test_print_hello_world(self):
        connection = PrinterConnection()
        connection.send(b"\x1bEHello World")
        connection.disconnect()

    def test_print_many_pages(self):
        connection = PrinterConnection()
        connection.send(b"\x1bEHello World" * 10000)
        connection.disconnect()
