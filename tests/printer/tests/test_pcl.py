# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2019 Michael Neu
#
# SPDX-License-Identifier: GPL-2.0-or-later

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
