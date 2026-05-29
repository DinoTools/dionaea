# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2016-2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

class DionaeaError(Exception):
    def __init__(self, msg, *args):
        self.msg = msg
        self.args = args

    def __str__(self):
        return self.msg % self.args


class LoaderError(DionaeaError):
    pass


class ServiceConfigError(DionaeaError):
    pass


class ConnectionError(DionaeaError):
    def __init__(self, connection=None, error_id=None):
        self.connection = connection
        self.error_id = error_id


class ConnectionDNSTimeout(ConnectionError):
    def __str__(self):
        return "Timeout resolving the hostname/domain: %s" % (
            self.connection.remote.hostname
        )


class ConnectionUnreachable(ConnectionError):
    def __str__(self):
        hostname = self.connection.remote.hostname
        if hostname is None or hostname == "":
            hostname = self.connection.remote.host

        return "Could not connect to host(s): %s:%d" % (
            hostname,
            self.connection.remote.port
        )


class ConnectionNoSuchDomain(ConnectionError):
    def __str__(self):
        return "Could not resolve the domain: %s" % (
            self.connection.remote.hostname
        )


class ConnectionTooMany(ConnectionError):
    def __str__(self):
        return "Too many connections"


class ConnectionUnknownError(ConnectionError):
    def __str__(self):
        return "Unknown error occured: error_id=%d" % (
            self.error_id
        )
