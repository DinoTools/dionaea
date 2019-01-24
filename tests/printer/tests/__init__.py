import socket


class PrinterConnection(object):
    def __init__(self):
        self.connection = None
        self.connect()

    def __del__(self):
        self.disconnect()

    def connect(self):
        if self.connection is not None:
            return

        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect(("localhost", 9100))
        self.connection.settimeout(1)

    def send(self, message):
        return self.connection.send(message)

    def receive(self, bytes_count):
        return self.connection.recv(bytes_count)

    def read_to_end(self):
        buffer = b""

        while True:
            try:
                data = self.receive(1024)
            except socket.timeout:
                break

            if not data:
                break

            buffer += data

        return buffer

    def send_pjl_commands(self, *pjl):
        uel = "\x1b%-12345X"
        message = uel + "\r\n".join(pjl) + "\r\n" + uel
        message_bytes = bytes(message, "utf-8")
        return self.send(message_bytes)

    def disconnect(self):
        self.connection.close()
