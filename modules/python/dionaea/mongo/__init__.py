#                               Dionaea
#                           - catches bugs -
#
# Copyright (C) 2017 PhiBo (DinoTools)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from dionaea import ServiceLoader
from .mongo import mongod


class MongoService(ServiceLoader):
    name = "mongo"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        daemon = mongod()
        daemon.apply_config(config)
        daemon.bind(addr, 27017, iface=iface)
        daemon.listen()
        return daemon