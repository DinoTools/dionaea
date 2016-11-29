#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2010  Mark Schloesser
#* Copyright (C) 2009  Paul Baecher & Markus Koetter
#*
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#*
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#*
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#*
#*
#*             contact nepenthesdev@gmail.com
#*
#*******************************************************************************/

import hashlib
import logging
import re


logger = logging.getLogger("util")
logger.setLevel(logging.DEBUG)


def md5file(filename):
    """
    Compute md5 checksum of file.

    :param str filename: File to read
    :return: MD5 checksum as hex string
    :rtype: str
    """
    return hashfile(filename, hashlib.md5())


def sha512file(filename):
    """
    Compute sha512 checksum of file.

    :param str filename: File to read
    :return: SHA512 checksum as hex string
    :rtype: str
    """
    return hashfile(filename, hashlib.sha512())


def hashfile(filename, digest):
    """
    Computer checksum of file.

    :param str filename: File to read
    :param _hashlib.Hash digest: Hash object
    :return: Checksum as hex string
    :rtype: str
    """
    fh = open(filename, mode="rb")
    while 1:
        buf = fh.read(4096)
        if len(buf) == 0:
            break
        digest.update(buf)
    fh.close()
    return digest.hexdigest()


def detect_shellshock(connection, data, report_incidents=True):
    """
    Try to find Shellshock attacks, included download commands and URLs.

    :param connection: The connection object
    :param data: Data to analyse
    :param report_incidents:
    :return: List of urls or None
    """
    from dionaea.core import incident
    regex = re.compile(b"\(\)\s*\t*\{.*;\s*\}\s*;")
    if not regex.search(data):
        return None
    logger.debug("Shellshock attack found")

    urls = []
    regex = re.compile(
        b"(wget|curl).+(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
    )
    for m in regex.finditer(data):
        logger.debug("Found download command with url %s", m.group("url"))
        urls.append(m.group("url"))
        if report_incidents:
            i = incident("dionaea.download.offer")
            i.con = connection
            i.url = m.group("url")
            i.report()

    return urls


def find_shell_download(connection, data, report_incidents=True):
    """
    Try to analyse the data and find download commands

    :param connection: The connection object
    :param data: Data to analyse
    :param report_incidents:
    :return: List of urls or None
    """
    from dionaea.core import incident
    urls = []
    regex = re.compile(
        b"(wget|curl).+(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
    )
    for m in regex.finditer(data):
        logger.debug("Found download command with url %s", m.group("url"))
        urls.append(m.group("url"))
        if report_incidents:
            i = incident("dionaea.download.offer")
            i.con = connection
            i.url = m.group("url")
            i.report()

    return urls
