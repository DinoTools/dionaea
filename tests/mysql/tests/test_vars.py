# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from . import SQLConnection


class TestVars(object):
    def test_show_database(self):
        con = SQLConnection()

        con.cursor.execute("SET @v1 = 2")

        con.disconnect()
