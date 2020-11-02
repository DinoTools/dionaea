from . import PrinterConnection


class TestPJLCommands:
    def test_basic_commands(self):
        connection = PrinterConnection()
        connection.send_pjl_commands(
            "@PJL INFO MEMORY",
        )
        assert connection.read_to_end() == b"TOTAL=1494416\r\nLARGEST=1494176\r\n"
        connection.disconnect()

    def test_echo(self):
        connection = PrinterConnection()
        connection.send_pjl_commands(
            "@PJL ECHO FOOBAR",
        )
        assert connection.read_to_end() == b"@PJL ECHO FOOBAR\r\n"
        connection.disconnect()

    def test_ls(self):
        connection = PrinterConnection()
        connection.send_pjl_commands(
            "@PJL FSDIRLIST NAME=\"0:\\\""
        )
        assert connection.read_to_end() == b". TYPE=DIR\r\n"
        connection.disconnect()

    def test_relative_paths(self):
        connection = PrinterConnection()
        connection.send_pjl_commands(
            "@PJL FSQUERY NAME=\"0:\\..\\..\\\""
        )
        relative_up_response = connection.read_to_end()

        connection.send_pjl_commands(
            "@PJL FSQUERY NAME=\"0:\\\""
        )
        base_volume_response = connection.read_to_end()

        assert relative_up_response == base_volume_response
        connection.disconnect()
