from dionaea.core import ihandler, incident, g_dionaea

import os
import logging
import random

import postgresql
import postgresql.driver as pg_driver
from postgresql.exceptions import ConnectionError

from time import sleep

logger = logging.getLogger('surfids')
logger.setLevel(logging.DEBUG)

AS_POSSIBLE_MALICIOUS_CONNECTION   = 0x00000
AS_DEFINITLY_MALICIOUS_CONNECTION  = 0x00001

AS_DOWNLOAD_OFFER                  = 0x00010
AS_DOWNLOAD_SUCCESS                = 0x00020


DT_PROTOCOL_NAME                   = 80
DT_EMULATION_PROFILE               = 81
DT_SHELLCODE_ACTION                = 82
DT_DCERPC_REQUEST                  = 83

class surfidshandler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)

		# mapping socket -> attackid
		self.attacks = {}

		self.dbh = None
		self.connect()


	def connect(self):
#		print(g_dionaea.config()['modules']['python']['surfids'])
		self.dbh = pg_driver.connect(user = g_dionaea.config()['modules']['python']['surfids']['username'],
			password = g_dionaea.config()['modules']['python']['surfids']['password'],
			database = g_dionaea.config()['modules']['python']['surfids']['dbname'],
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
		origin = icd.origin
		origin = origin.replace(".","_")
		try:
			method = getattr(self, "_handle_incident_" + origin)
		except:
			return

		while True:
			try:
				method(icd)
				return
			except ConnectionError as e:
				logger.warn("ConnectionError %s" % e)
				time.sleep(1)
				self.connect()
		



	def _handle_incident_dionaea_connection_tcp_accept(self, icd):
		con=icd.con
		r = self.stmt_attack_add(0, con.remote.host, con.remote.port, con.local.host, con.local.port, None, self.sensor_type)
		attackid = r[0][0]
		self.attacks[con] = attackid
		logger.info("accepted connection from %s:%i to %s:%i (id=%i)" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))
		self.stmt_detail_add(attackid, con.local.host, DT_PROTOCOL_NAME, con.protocol)

	def handle_incident_dionaea_connection_tcp_reject(self, icd):
		con=icd.con
		r = self.stmt_attack_add(0, con.remote.host, con.remote.port, con.local.host, con.local.port, None, self.sensor_type)
		attackid = r[0][0]
		self.attacks[con] = attackid
		logger.info("reject connection from %s:%i to %s:%i (id=%i)" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port, attackid))
		self.stmt_detail_add(attackid, con.local.host, DT_PROTOCOL_NAME, con.protocol)

	def _handle_incident_dionaea_connection_free(self, icd):
		con=icd.con
		if con in self.attacks:
			attackid = self.attacks[con]
			del self.attacks[con]
			logger.info("attackid %i is done" % attackid)
		else:
			logger.warn("no attackid for %s:%s" % (con.local.host, con.local.port) )


	def _handle_incident_dionaea_module_emu_profile(self, icd):
		con = icd.con
		attackid = self.attacks[con]
#		self.stmt_detail_add(attackid, con.local.host, 
		logger.info("emu profile for attackid %i" % attackid)
		self.stmt_attack_update_severity(attackid, AS_DEFINITLY_MALICIOUS_CONNECTION)
		self.stmt_detail_add(attackid, con.local.host, DT_EMULATION_PROFILE, icd.profile)

	def _handle_incident_dionaea_download_offer(self, icd):
		con=icd.con
		attackid = self.attacks[con]
		logger.info("offer for attackid %i" % attackid)
		self.stmt_detail_add_offer(con.remote.host, con.local.host, icd.url, self.sensor_type)

	def _handle_incident_dionaea_download_complete_hash(self, icd):
		con=icd.con
		attackid = self.attacks[con]
		logger.info("complete for attackid %i" % attackid)
		self.stmt_detail_add_download(con.remote.host, con.local.host, icd.url, icd.md5hash, self.sensor_type)

	def _handle_incident_dionaea_service_shell_listen(self, icd):
		con=icd.con
		attackid = self.attacks[con]
		logger.info("listen shell for attackid %i" % attackid)
		self.stmt_detail_add(attackid, con.local.host, DT_SHELLCODE_ACTION, "bindshell://"+str(icd.port) )

	def _handle_incident_dionaea_service_shell_connect(self, icd):
		con=icd.con
		attackid = self.attacks[con]
		logger.info("connect shell for attackid %i" % attackid)
		self.stmt_detail_add(attackid, con.local.host, DT_SHELLCODE_ACTION, "connectbackshell://"+str(icd.host)+":"+str(icd.port) )
		
	def _handle_incident_dionaea_modules_python_smb_dcerpc_request(self, icd):
		con=icd.con
		attackid = self.attacks[con]
		logger.info("dcerpc request for attackid %i" % attackid)
		self.stmt_detail_add(attackid, con.local.host, DT_DCERPC_REQUEST, icd.uuid + ":" + str(icd.opnum))


