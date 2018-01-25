from . import SQLConnection


class TestVars(object):
    def test_show_database(self):
        con = SQLConnection()

        con.cursor.execute("SET @v1 = 2")

        con.disconnect()
