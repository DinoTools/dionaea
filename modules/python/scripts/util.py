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

def md5file(filename):
    return hashfile(filename, hashlib.md5())

def sha512file(filename):
    return hashfile(filename, hashlib.sha512())

def hashfile(filename, digest):
    fh = open(filename, mode="rb")
    while 1:
        buf = fh.read(4096)
        if len(buf) == 0:
            break
        digest.update(buf)
    fh.close()
    return digest.hexdigest()

