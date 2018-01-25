import pymysql


class SQLConnection(object):
    def __init__(self):
        self.cnx = None
        self.cursor = None
        self.connect()

    def __del__(self):
        self.disconnect()

    def connect(self):
        self.cnx = pymysql.connect(user="root", host="127.0.0.1")
        self.cursor = self.cnx.cursor()
        return self.cursor

    def disconnect(self):
        self.cursor.close()
        self.cnx.close()
