from dionaea import ihandler, incident, g_dionaea

import os
import logging
import random

import postgresql
import postgresql.driver as pg_driver
import ipaddr
logger = logging.getLogger('surfids')
logger.setLevel(logging.DEBUG)

AS_POSSIBLE_MALICIOUS_CONNECTION   = 0x00000
AS_DEFINITLY_MALICIOUS_CONNECTION  = 0x00001

AS_DOWNLOAD_OFFER                  = 0x00010
AS_DOWNLOAD_SUCCESS                = 0x00020


DT_DIALOGUE_NAME                   = 0x00001
DT_SHELLCODEHANDLER_NAME           = 0x00002
DT_DOWNLOAD_URL                    = 0x00004
DT_DOWNLOAD_HASH                   = 0x00008

class surfnetidshandler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)

		# mapping socket -> attackid
		self.attacks = {}
		print("foo")
#		print(g_dionaea.config()['modules']['python']['surfids'])
		self.dbh = pg_driver.connect(user = g_dionaea.config()['modules']['python']['surfids']['user'],
			password = g_dionaea.config()['modules']['python']['surfids']['password'],
			database = g_dionaea.config()['modules']['python']['surfids']['database'],
			host = g_dionaea.config()['modules']['python']['surfids']['host'],
			port = g_dionaea.config()['modules']['python']['surfids']['port'])


		self.stmt_sensor_type = self.dbh.prepare("SELECT surfids3_type_from_name('dionaea')")
		self.sensor_type = self.stmt_sensor_type()[0][0]
		logger.debug("surfids sensor type %i" % self.sensor_type)
		self.stmt_attack_add = self.dbh.prepare("SELECT surfids3_attack_add($1, $2::text::inet, $3, $4::text::inet, $5, $6, $7)")
		self.stmt_detail_add = self.dbh.prepare("SELECT surfids3_detail_add($1, $2::text::inet, $3, $4)")
		self.stmt_detail_add_offer = self.dbh.prepare("SELECT surfids3_detail_add_offer($1::text::inet, $2::text::inet, $3, $4)")
		self.stmt_detail_add_download = self.dbh.prepare("SELECT surfids3_detail_add_download($1::text::inet, $2::text::inet, $3, $4, $5)")
		self.stmt_attack_update_severity = self.dbh.prepare("SELECT surfids3_attack_update_severity($1, $2)")
	def handle_incident(self, icd):
#		print("unknown")
		pass

	def handle_incident_dionaea_connection_tcp_accept(self, icd):
		con=icd.con
		attackid = random.randint(0,1000)
		self.attacks[con] = attackid
		
		r = self.stmt_attack_add(0, con.remote.host, con.remote.port, con.local.host, con.local.port, None, self.sensor_type)
		attackid = r[0][0]
		self.attacks[con] = attackid
		logger.info("accepted connection from %s:%i to %s:%i (id=%i)" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))
		self.stmt_detail_add(attackid, con.local.host, DT_DIALOGUE_NAME, con.protocol)

	def handle_incident_dionaea_connection_free(self, icd):
		con=icd.con
		if con in self.attacks:
			attackid = self.attacks[con]
			del self.attacks[con]
			logger.info("attackid %i is done" % attackid)
		else:
			logger.warn("no attackid for %s:%s" % (con.local.host, con.local.port) )


	def handle_incident_dionaea_module_emu_profile(self, icd):
		con = icd.con
		attackid = self.attacks[con]
#		self.stmt_detail_add(attackid, con.local.host, 
		logger.info("emu profile for attackid %i" % attackid)
		self.stmt_attack_update_severity(attackid, AS_DEFINITLY_MALICIOUS_CONNECTION)
		self.stmt_detail_add(attackid, con.local.host, DT_SHELLCODEHANDLER_NAME, icd.profile)

	def handle_incident_dionaea_download_offer(self, icd):
		con=icd.con
		attackid = self.attacks[con]
		logger.info("offer for attackid %i" % attackid)
		self.stmt_detail_add_offer(con.remote.host, con.local.host, icd.url, self.sensor_type)

	def handle_incident_dionaea_download_complete_hash(self, icd):
		con=icd.con
		attackid = self.attacks[con]
		logger.info("complete for attackid %i" % attackid)
		self.stmt_detail_add_download(con.remote.host, con.local.host, icd.url, icd.md5hash, self.sensor_type)

	def handle_incident_dionaea_service_shell_listen(self, icd):
		con=icd.con
		attackid = self.attacks[con]
		logger.info("listen shell for attackid %i" % attackid)

	def handle_incident_dionaea_service_shell_connect(self, icd):
		con=icd.con
		attackid = self.attacks[con]
		logger.info("connect shell for attackid %i" % attackid)

	def handle_incident_dionaea_detect_attack(self, icd):
		con=icd.con
		attackid = self.attacks[con]






