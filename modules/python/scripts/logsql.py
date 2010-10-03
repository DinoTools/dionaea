#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
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


from dionaea.core import ihandler, incident, g_dionaea

import os
import logging
import random
import json
import sqlite3
import time

logger = logging.getLogger('logsql')
logger.setLevel(logging.DEBUG)

class logsqlhandler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)

		# mapping socket -> attackid
		self.attacks = {}

		self.pending = {}

#		self.dbh = sqlite3.connect(user = g_dionaea.config()['modules']['python']['logsql']['file'])
		file = g_dionaea.config()['modules']['python']['logsql']['sqlite']['file']
		self.dbh = sqlite3.connect(file)
		self.cursor = self.dbh.cursor()
		update = False

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			connections	(
				connection INTEGER PRIMARY KEY,
				connection_type TEXT, 
				connection_transport TEXT, 
				connection_protocol TEXT, 
				connection_timestamp INTEGER,
				connection_root INTEGER,
				connection_parent INTEGER,
				local_host TEXT, 
				local_port INTEGER, 
				remote_host TEXT,
				remote_hostname TEXT,
				remote_port INTEGER
			)""")

		self.cursor.execute("""CREATE TRIGGER IF NOT EXISTS	connections_INSERT_update_connection_root_trg
			AFTER INSERT ON connections 
			FOR EACH ROW 
			WHEN 
				new.connection_root IS NULL 
			BEGIN
				UPDATE connections SET connection_root = connection WHERE connection = new.connection AND new.connection_root IS NULL;
			END""")

		for idx in ["type","timestamp","root","parent"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS connections_%s_idx
			ON connections (connection_%s)""" % (idx, idx))

		for idx in ["local_host","local_port","remote_host"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS connections_%s_idx
			ON connections (%s)""" % (idx, idx))


# 		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
#			bistreams (
#				bistream INTEGER PRIMARY KEY,
#				connection INTEGER,
#				bistream_data TEXT
#			)""")
#
#		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
#			smbs (
#				smb INTEGER PRIMARY KEY,
#				connection INTEGER,
#				smb_direction TEXT,
#				smb_action TEXT,
#				CONSTRAINT smb_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
#			)""")

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			dcerpcbinds (
				dcerpcbind INTEGER PRIMARY KEY,
				connection INTEGER,
				dcerpcbind_uuid TEXT,
				dcerpcbind_transfersyntax TEXT
				-- CONSTRAINT dcerpcs_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
			)""")

		for idx in ["uuid","transfersyntax"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS dcerpcbinds_%s_idx 
			ON dcerpcbinds (dcerpcbind_%s)""" % (idx, idx))

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			dcerpcrequests (
				dcerpcrequest INTEGER PRIMARY KEY,
				connection INTEGER,
				dcerpcrequest_uuid TEXT,
				dcerpcrequest_opnum INTEGER
				-- CONSTRAINT dcerpcs_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
			)""")

		for idx in ["uuid","opnum"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS dcerpcrequests_%s_idx 
			ON dcerpcrequests (dcerpcrequest_%s)""" % (idx, idx))


		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			dcerpcservices (
				dcerpcservice INTEGER PRIMARY KEY,
				dcerpcservice_uuid TEXT,
				dcerpcservice_name TEXT,
				CONSTRAINT dcerpcservice_uuid_uniq UNIQUE (dcerpcservice_uuid)
			)""")

		from uuid import UUID
		from dionaea.smb import rpcservices
		import inspect
		services = inspect.getmembers(rpcservices, inspect.isclass)
		for name, servicecls in services:
			if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
				try:
					self.cursor.execute("INSERT INTO dcerpcservices (dcerpcservice_name, dcerpcservice_uuid) VALUES (?,?)",
						(name, str(UUID(hex=servicecls.uuid))) )
				except Exception as e:
#					print("dcerpcservice %s existed %s " % (servicecls.uuid, e) )
					pass


		logger.info("Getting RPC Services")
		r = self.cursor.execute("SELECT * FROM dcerpcservices")
#		print(r)
		names = [r.description[x][0] for x in range(len(r.description))]
		r = [ dict(zip(names, i)) for i in r]
#		print(r)
		r = dict([(UUID(i['dcerpcservice_uuid']).hex,i['dcerpcservice']) for i in r])
#		print(r)


		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			dcerpcserviceops (
				dcerpcserviceop INTEGER PRIMARY KEY,
				dcerpcservice INTEGER,
				dcerpcserviceop_opnum INTEGER,
				dcerpcserviceop_name TEXT,
				dcerpcserviceop_vuln TEXT,
				CONSTRAINT dcerpcop_service_opnum_uniq UNIQUE (dcerpcservice, dcerpcserviceop_opnum)
			)""")

		logger.info("Setting RPC ServiceOps")
		for name, servicecls in services:
			if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
				for opnum in servicecls.ops:
					op = servicecls.ops[opnum]
					uuid = servicecls.uuid
					vuln = ''
					dcerpcservice = r[uuid]
					if opnum in servicecls.vulns:
						vuln = servicecls.vulns[opnum]
					try:
						self.cursor.execute("INSERT INTO dcerpcserviceops (dcerpcservice, dcerpcserviceop_opnum, dcerpcserviceop_name, dcerpcserviceop_vuln) VALUES (?,?,?,?)", 
							(dcerpcservice, opnum, op, vuln))
					except:
#						print("%s %s %s %s %s existed" % (dcerpcservice, uuid, name, op, vuln))
						pass

		# NetPathCompare was called NetCompare in dcerpcserviceops
		try:
			logger.debug("Trying to update table: dcerpcserviceops")
			x = self.cursor.execute("""SELECT * FROM dcerpcserviceops WHERE dcerpcserviceop_name = 'NetCompare'""").fetchall()
			if len(x) > 0:
				self.cursor.execute("""UPDATE dcerpcserviceops SET dcerpcserviceop_name = 'NetPathCompare' WHERE dcerpcserviceop_name = 'NetCompare'""")
				logger.debug("... done")
			else:
				logger.info("... not required")
		except Exception as e:
			print(e)
			logger.info("... not required")

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			emu_profiles (
				emu_profile INTEGER PRIMARY KEY,
				connection INTEGER,
				emu_profile_json TEXT
				-- CONSTRAINT emu_profiles_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
			)""")


		# fix a typo on emu_services table definition
		# emu_services.emu_serive is wrong, should be emu_services.emu_service
		# 1) rename table, create the proper table
		try:
			logger.debug("Trying to update table: emu_services")
			self.cursor.execute("""SELECT emu_serivce FROM emu_services LIMIT 1""")
			self.cursor.execute("""ALTER TABLE emu_services RENAME TO emu_services_old""")
			update = True
		except Exception as e:
			logger.debug("... not required")
			update = False

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			emu_services (
				emu_serivce INTEGER PRIMARY KEY,
				connection INTEGER,
				emu_service_url TEXT
				-- CONSTRAINT emu_services_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
			)""")

		# 2) copy all values to proper table, drop old table
		try:
			if update == True:
				self.cursor.execute("""
					INSERT INTO
						emu_services (emu_service, connection, emu_service_url)
					SELECT 
						emu_serivce, connection, emu_service_url
					FROM emu_services_old""")
				self.cursor.execute("""DROP TABLE emu_services_old""")
				logger.debug("... done")
		except Exception as e:
			logger.debug("Updating emu_services failed, copying old table failed (%s)" % e)


		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			offers (
				offer INTEGER PRIMARY KEY,
				connection INTEGER,
				offer_url TEXT
				-- CONSTRAINT offers_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
			)""")

		self.cursor.execute("""CREATE INDEX IF NOT EXISTS offers_url_idx ON offers (offer_url)""")

		# fix a type on downloads table definition
		# downloads.downloads is wrong, should be downloads.download
		# 1) rename table, create the proper table
		try:
			logger.debug("Trying to update table: downloads")
			self.cursor.execute("""SELECT downloads FROM downloads LIMIT 1""")
			self.cursor.execute("""ALTER TABLE downloads RENAME TO downloads_old""")
			update = True
		except Exception as e:
#			print(e)
			logger.debug("... not required")
			update = False

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			downloads (
				download INTEGER PRIMARY KEY,
				connection INTEGER,
				download_url TEXT,
				download_md5_hash TEXT
				-- CONSTRAINT downloads_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
			)""")
		
		# 2) copy all values to proper table, drop old table
		try:
			if update == True:
				self.cursor.execute("""
					INSERT INTO
						downloads (download, connection, download_url, download_md5_hash)
					SELECT 
						downloads, connection, download_url, download_md5_hash
					FROM downloads_old""")
				self.cursor.execute("""DROP TABLE downloads_old""")
				logger.debug("... done")
		except Exeption as e:
			logger.debug("Updating downloads failed, copying old table failed (%s)" % e)

		for idx in ["url", "md5_hash"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS downloads_%s_idx 
			ON downloads (download_%s)""" % (idx, idx))


		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			resolves (
				resolve INTEGER PRIMARY KEY,
				connection INTEGER,
				resolve_hostname TEXT,
				resolve_type TEXT,
				resolve_result TEXT
			)""")

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
			p0fs (
				p0f INTEGER PRIMARY KEY,
				connection INTEGER,
				p0f_genre TEXT,
				p0f_link TEXT,
				p0f_detail TEXT,
				p0f_uptime INTEGER,
				p0f_tos TEXT,
				p0f_dist INTEGER,
				p0f_nat INTEGER,
				p0f_fw INTEGER
				-- CONSTRAINT p0fs_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
			)""")

		for idx in ["genre","detail","uptime"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS p0fs_%s_idx 
			ON p0fs (p0f_%s)""" % (idx, idx))

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS
			logins (
				login INTEGER PRIMARY KEY,
				connection INTEGER,
				login_username TEXT,
				login_password TEXT
				-- CONSTRAINT logins_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
			)""")

		for idx in ["username","password"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS logins_%s_idx 
			ON logins (login_%s)""" % (idx, idx))

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS
			mssql_fingerprints (
				mssql_fingerprint INTEGER PRIMARY KEY,
				connection INTEGER,
				mssql_fingerprint_hostname TEXT,
				mssql_fingerprint_appname TEXT,
				mssql_fingerprint_cltintname TEXT
				-- CONSTRAINT mssql_fingerprints_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
			)""")

		for idx in ["hostname","appname","cltintname"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS mssql_fingerprints_%s_idx 
			ON mssql_fingerprints (mssql_fingerprint_%s)""" % (idx, idx))

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS
			mssql_commands (
				mssql_command INTEGER PRIMARY KEY,
				connection INTEGER,
				mssql_command_status TEXT,
				mssql_command_cmd TEXT
				-- CONSTRAINT mssql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
			)""")

		for idx in ["status"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS mssql_commands_%s_idx 
			ON mssql_commands (mssql_command_%s)""" % (idx, idx))



		self.cursor.execute("""CREATE TABLE IF NOT EXISTS virustotals (
				virustotal INTEGER PRIMARY KEY,
				virustotal_md5_hash TEXT NOT NULL,
				virustotal_timestamp INTEGER NOT NULL,
				virustotal_permalink TEXT NOT NULL
			)""")

		for idx in ["md5_hash"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS virustotals_%s_idx 
			ON virustotals (virustotal_%s)""" % (idx, idx))

		self.cursor.execute("""CREATE TABLE IF NOT EXISTS virustotalscans (
			virustotalscan INTEGER PRIMARY KEY,
			virustotal INTEGER NOT NULL,
			virustotalscan_scanner TEXT NOT NULL,
			virustotalscan_result TEXT
		)""")


		for idx in ["scanner","result"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS virustotalscans_%s_idx 
			ON virustotalscans (virustotalscan_%s)""" % (idx, idx))

		self.cursor.execute("""CREATE INDEX IF NOT EXISTS virustotalscans_virustotal_idx 
			ON virustotalscans (virustotal)""")

#		self.cursor.execute("""CREATE TABLE IF NOT EXISTS 
#			httpheaders (
#				httpheader INTEGER PRIMARY KEY,
#				connection INTEGER,
#				http_headerkey TEXT,
#				http_headervalue TEXT,
#				-- CONSTRAINT httpheaders_connection_fkey FOREIGN KEY (connection) REFERENCES connections (connection)
#			)""")
#
#		for idx in ["headerkey","headervalue"]:
#			self.cursor.execute("""CREATE INDEX IF NOT EXISTS httpheaders_%s_idx 
#			ON httpheaders (httpheader_%s)""" % (idx, idx))


		# connection index for all 
		for idx in ["dcerpcbinds", "dcerpcrequests", "emu_profiles", "emu_services", "offers", "downloads", "p0fs", "logins", "mssql_fingerprints", "mssql_commands"]:
			self.cursor.execute("""CREATE INDEX IF NOT EXISTS %s_connection_idx	ON %s (connection)""" % (idx, idx))


		self.dbh.commit()


		# updates, database schema corrections for old versions

		# svn rev 2143 removed the table dcerpcs 
		# and created the table dcerpcrequests
		# 
		# copy the data to the new table dcerpcrequests
		# drop the old table
		try:
			logger.debug("Updating Table dcerpcs")
			self.cursor.execute("""INSERT INTO 
									dcerpcrequests (connection, dcerpcrequest_uuid, dcerpcrequest_opnum) 
								SELECT 
									connection, dcerpc_uuid, dcerpc_opnum 
								FROM 
									dcerpcs""")
			self.cursor.execute("""DROP TABLE dcerpcs""")
			logger.debug("... done")
		except Exception as e:
#			print(e)
			logger.debug("... not required")
			

	def __del__(self):
		logger.info("Closing sqlite handle")
		self.cursor.close()
		self.dbh.close()

	def handle_incident(self, icd):
#		print("unknown")
		pass

	def connection_insert(self, icd, connection_type):
		con=icd.con
		r = self.cursor.execute("INSERT INTO connections (connection_timestamp, connection_type, connection_transport, connection_protocol, local_host, local_port, remote_host, remote_hostname, remote_port) VALUES (?,?,?,?,?,?,?,?,?)",
			(time.time(), connection_type, con.transport, con.protocol, con.local.host, con.local.port, con.remote.host, con.remote.hostname, con.remote.port) )
		attackid = self.cursor.lastrowid
		self.attacks[con] = (attackid, attackid)
		self.dbh.commit()

		# maybe this was a early connection?
		if con in self.pending:
			# the connection was linked before we knew it
			# that means we have to 
			# - update the connection_root and connection_parent for all connections which had the pending
			# - update the connection_root for all connections which had the 'childid' as connection_root
			for i in self.pending[con]:
				print("%s %s %s" % (attackid, attackid, i))
				self.cursor.execute("UPDATE connections SET connection_root = ?, connection_parent = ? WHERE connection = ?",
					(attackid, attackid, i ) )
				self.cursor.execute("UPDATE connections SET connection_root = ? WHERE connection_root = ?",
					(attackid, i ) )
			self.dbh.commit()

		return attackid


	def handle_incident_dionaea_connection_tcp_listen(self, icd):
		attackid = self.connection_insert( icd, 'listen')
		con=icd.con
		logger.info("listen connection on %s:%i (id=%i)" % 
			(con.remote.host, con.remote.port, attackid))

	def handle_incident_dionaea_connection_tls_listen(self, icd):
		attackid = self.connection_insert( icd, 'listen')
		con=icd.con
		logger.info("listen connection on %s:%i (id=%i)" % 
			(con.remote.host, con.remote.port, attackid))

	def handle_incident_dionaea_connection_tcp_connect(self, icd):
		attackid = self.connection_insert( icd, 'connect')
		con=icd.con
		logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" % 
			(con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

	def handle_incident_dionaea_connection_tls_connect(self, icd):
		attackid = self.connection_insert( icd, 'connect')
		con=icd.con
		logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" % 
			(con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

	def handle_incident_dionaea_connection_udp_connect(self, icd):
		attackid = self.connection_insert( icd, 'connect')
		con=icd.con
		logger.info("connect connection to %s/%s:%i from %s:%i (id=%i)" % 
			(con.remote.host, con.remote.hostname, con.remote.port, con.local.host, con.local.port, attackid))

	def handle_incident_dionaea_connection_tcp_accept(self, icd):
		attackid = self.connection_insert( icd, 'accept')
		con=icd.con
		logger.info("accepted connection from %s:%i to %s:%i (id=%i)" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

	def handle_incident_dionaea_connection_tls_accept(self, icd):
		attackid = self.connection_insert( icd, 'accept')
		con=icd.con
		logger.info("accepted connection from %s:%i to %s:%i (id=%i)" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))


	def handle_incident_dionaea_connection_tcp_reject(self, icd):
		attackid = self.connection_insert(icd, 'reject')
		con=icd.con
		logger.info("reject connection from %s:%i to %s:%i (id=%i)" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

	def handle_incident_dionaea_connection_tcp_pending(self, icd):
		attackid = self.connection_insert(icd, 'pending')
		con=icd.con
		logger.info("pending connection from %s:%i to %s:%i (id=%i)" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))

	def handle_incident_dionaea_connection_link_early(self, icd):
		# if we have to link a connection with a connection we do not know yet,
		# we store the unknown connection in self.pending and associate the childs id with it
		if icd.parent not in self.attacks:
			if icd.parent not in self.pending:
				self.pending[icd.parent] = {self.attacks[icd.child][1]: True}
			else:
				if icd.child not in self.pending[icd.parent]:
					self.pending[icd.parent][self.attacks[icd.child][1]] = True

	def handle_incident_dionaea_connection_link(self, icd):
		if icd.parent in self.attacks:
			logger.info("parent ids %s" % str(self.attacks[icd.parent]))
			parentroot, parentid = self.attacks[icd.parent]
			if icd.child in self.attacks:
				logger.info("child had ids %s" % str(self.attacks[icd.child]))
				childroot, childid = self.attacks[icd.child]
			else:
				childid = parentid
			self.attacks[icd.child] = (parentroot, childid)
			logger.info("child has ids %s" % str(self.attacks[icd.child]))
			logger.info("child %i parent %i root %i" % (childid, parentid, parentroot) )
			r = self.cursor.execute("UPDATE connections SET connection_root = ?, connection_parent = ? WHERE connection = ?",
				(parentroot, parentid, childid) )
			self.dbh.commit()

		if icd.child in self.pending:
			# if the new accepted connection was pending
			# assign the connection_root to all connections which have been waiting for this connection
			parentroot, parentid = self.attacks[icd.parent]
			if icd.child in self.attacks:
				childroot, childid = self.attacks[icd.child]
			else:
				childid = parentid

			self.cursor.execute("UPDATE connections SET connection_root = ? WHERE connection_root = ?",
				(parentroot, childid) )
			self.dbh.commit()

	def handle_incident_dionaea_connection_free(self, icd):
		con=icd.con
		if con in self.attacks:
			attackid = self.attacks[con][1]
			del self.attacks[con]
			logger.info("attackid %i is done" % attackid)
		else:
			logger.warn("no attackid for %s:%s" % (con.local.host, con.local.port) )
		if con in self.pending:
			del self.pending[con]


	def handle_incident_dionaea_module_emu_profile(self, icd):
		con = icd.con
		attackid = self.attacks[con][1]
		logger.info("emu profile for attackid %i" % attackid)
		self.cursor.execute("INSERT INTO emu_profiles (connection, emu_profile_json) VALUES (?,?)",
			(attackid, icd.profile) )
		self.dbh.commit()


	def handle_incident_dionaea_download_offer(self, icd):
		con=icd.con
		attackid = self.attacks[con][1]
		logger.info("offer for attackid %i" % attackid)
		self.cursor.execute("INSERT INTO offers (connection, offer_url) VALUES (?,?)",
			(attackid, icd.url) )
		self.dbh.commit()

	def handle_incident_dionaea_download_complete_hash(self, icd):
		con=icd.con
		attackid = self.attacks[con][1]
		logger.info("complete for attackid %i" % attackid)
		self.cursor.execute("INSERT INTO downloads (connection, download_url, download_md5_hash) VALUES (?,?,?)",
			(attackid, icd.url, icd.md5hash) )
		self.dbh.commit()


	def handle_incident_dionaea_service_shell_listen(self, icd):
		con=icd.con
		attackid = self.attacks[con][1]
		logger.info("listen shell for attackid %i" % attackid)
		self.cursor.execute("INSERT INTO emu_services (connection, emu_service_url) VALUES (?,?)",
			(attackid, "bindshell://"+str(icd.port)) )
		self.dbh.commit()

	def handle_incident_dionaea_service_shell_connect(self, icd):
		con=icd.con
		attackid = self.attacks[con][1]
		logger.info("connect shell for attackid %i" % attackid)
		self.cursor.execute("INSERT INTO emu_services (connection, emu_service_url) VALUES (?,?)",
			(attackid, "connectbackshell://"+str(icd.host)+":"+str(icd.port)) )
		self.dbh.commit()

	def handle_incident_dionaea_detect_attack(self, icd):
		con=icd.con
		attackid = self.attacks[con]


	def handle_incident_dionaea_modules_python_p0f(self, icd):
		con=icd.con
		if con in self.attacks:
			attackid = self.attacks[con][1]
			self.cursor.execute("INSERT INTO p0fs (connection, p0f_genre, p0f_link, p0f_detail, p0f_uptime, p0f_tos, p0f_dist, p0f_nat, p0f_fw) VALUES (?,?,?,?,?,?,?,?,?)",
				( attackid, icd.genre, icd.link, icd.detail, icd.uptime, icd.tos, icd.dist, icd.nat, icd.fw))
			self.dbh.commit()

	def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, icd):
		con=icd.con
		if con in self.attacks:
			attackid = self.attacks[con][1]
			self.cursor.execute("INSERT INTO dcerpcrequests (connection, dcerpcrequest_uuid, dcerpcrequest_opnum) VALUES (?,?,?)",
				(attackid, icd.uuid, icd.opnum))
			self.dbh.commit()

	def handle_incident_dionaea_modules_python_smb_dcerpc_bind(self, icd):
		con=icd.con
		if con in self.attacks:
			attackid = self.attacks[con][1]
			self.cursor.execute("INSERT INTO dcerpcbinds (connection, dcerpcbind_uuid, dcerpcbind_transfersyntax) VALUES (?,?,?)",
				(attackid, icd.uuid, icd.transfersyntax))
			self.dbh.commit()

	def handle_incident_dionaea_modules_python_mssql_login(self, icd):
		con = icd.con
		if con in self.attacks:
			attackid = self.attacks[con][1]
			self.cursor.execute("INSERT INTO logins (connection, login_username, login_password) VALUES (?,?,?)",
				(attackid, icd.username, icd.password))
			self.cursor.execute("INSERT INTO mssql_fingerprints (connection, mssql_fingerprint_hostname, mssql_fingerprint_appname, mssql_fingerprint_cltintname) VALUES (?,?,?,?)", 
				(attackid, icd.hostname, icd.appname, icd.cltintname))
			self.dbh.commit()

	def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
		con = icd.con
		if con in self.attacks:
			attackid = self.attacks[con][1]
			self.cursor.execute("INSERT INTO mssql_commands (connection, mssql_command_status, mssql_command_cmd) VALUES (?,?,?)", 
				(attackid, icd.status, icd.cmd))
			self.dbh.commit()

	def handle_incident_dionaea_modules_python_virustotal_report(self, icd):
		md5 = icd.md5hash
		f = open(icd.path, mode='r')
		j = json.load(f)

		if j['result'] == 1: # file was known to virustotal
			permalink = j['permalink']
			date = j['report'][0]
			self.cursor.execute("INSERT INTO virustotals (virustotal_md5_hash, virustotal_permalink, virustotal_timestamp) VALUES (?,?,strftime('%s',?))", 
				(md5, permalink, date))
			self.dbh.commit()

			virustotal = self.cursor.lastrowid

			scans = j['report'][1]
			for av in scans:
				res = scans[av]
				# not detected = '' -> NULL
				if res == '':
					res = None

				self.cursor.execute("""INSERT INTO virustotalscans (virustotal, virustotalscan_scanner, virustotalscan_result) VALUES (?,?,?)""",
					(virustotal, av, res))
#				logger.debug("scanner {} result {}".format(av,scans[av]))
			self.dbh.commit()







