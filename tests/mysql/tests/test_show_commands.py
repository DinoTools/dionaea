from . import SQLConnection


class TestSQLShow(object):
    def test_select_database(self):
        con = SQLConnection()

        con.cursor.execute("select database()")

        con.disconnect()

    def test_show_database(self):
        con = SQLConnection()

        con.cursor.execute("show databases")

        con.disconnect()

    def test_show_tables(self):
        con = SQLConnection()

        # Database: information_schema is in memory by default
        con.cnx.select_db("information_schema")
        con.cursor.execute("show tables")

        con.disconnect()
