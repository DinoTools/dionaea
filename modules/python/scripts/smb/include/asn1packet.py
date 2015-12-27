#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2010  Markus Koetter
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
#*  This file was part of Scapy
#*  See http://www.secdev.org/projects/scapy for more informations
#*  Copyright (C) Philippe Biondi <phil@secdev.org>
#*  This program is published under a GPLv2 license
#*************************************************************************


from .packet import *

class ASN1_Packet(Packet):
    ASN1_root = None
    ASN1_codec = None
    def init_fields(self):
        flist = self.ASN1_root.get_fields_list()
        self.do_init_fields(flist)
        self.fields_desc = flist
    def do_build(self):
        return self.ASN1_root.build(self)
    def do_dissect(self, x):
        return self.ASN1_root.dissect(self, x)
