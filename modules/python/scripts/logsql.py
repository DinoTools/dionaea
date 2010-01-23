from dionaea import ihandler, incident, g_dionaea

import os
import logging
import random

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
		from smb import rpcservices
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

		# connection index for all 
		for idx in ["dcerpcbinds", "dcerpcrequests", "emu_profiles", "emu_services", "offers", "downloads", "p0fs"]:
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


	def handle_incident_dionaea_connection_link(self, icd):
		if icd.parent in self.attacks:
			logger.warn("parent ids %s" % str(self.attacks[icd.parent]))
			parentroot, parentid = self.attacks[icd.parent]
			if icd.child in self.attacks:
				logger.warn("child had ids %s" % str(self.attacks[icd.child]))
				childroot, childid = self.attacks[icd.child]
			else:
				childid = parentid
			self.attacks[icd.child] = (parentroot, childid)
			logger.warn("child has ids %s" % str(self.attacks[icd.child]))
			logger.warn("child %i parent %i root %i" % (childid, parentid, parentroot) )
			r = self.cursor.execute("UPDATE connections SET connection_root = ?, connection_parent = ? WHERE connection = ?",
				(parentroot, parentid, childid) )
#			print(r.fetchall())
#			r = self.cursor.execute("INSERT INTO connection_links (connection_parent, connection_child) VALUES(?,?)",
#				(parentid, childid) )
			self.dbh.commit()
			
						
	def handle_incident_dionaea_connection_free(self, icd):
		con=icd.con
		if con in self.attacks:
			attackid = self.attacks[con][1]
			del self.attacks[con]
			logger.info("attackid %i is done" % attackid)
		else:
			logger.warn("no attackid for %s:%s" % (con.local.host, con.local.port) )


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


