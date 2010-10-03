#********************************************************************************
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

from dionaea.core import ihandler, incident, g_dionaea

import logging
import json
import os
import uuid
import sqlite3
from dionaea import pyev

logger = logging.getLogger('virustotal')
logger.setLevel(logging.DEBUG)

class vtreport:
	def __init__(self, backlogfile, md5hash, file, status):
		self.backlogfile = backlogfile
		self.md5hash = md5hash
		self.file = file
		self.status = status

class virustotalhandler(ihandler):
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		ihandler.__init__(self, path)
		self.apikey = g_dionaea.config()['modules']['python']['virustotal']['apikey']
		self.cookies = {}
		self.loop = pyev.default_loop()

		self.backlog_timer = pyev.Timer(0, 20, self.loop, self.__handle_backlog_timeout)
		self.backlog_timer.start()

		self.dbh = sqlite3.connect('/opt/dionaea/var/dionaea/virustotal.sqlite')
		self.cursor = self.dbh.cursor()
		self.cursor.execute("""
			CREATE TABLE IF NOT EXISTS backlogfiles (
				backlogfile INTEGER PRIMARY KEY,
				status TEXT NOT NULL, -- new, submit, query, comment
				md5_hash TEXT NOT NULL,
				path TEXT NOT NULL,
				timestamp INTEGER NOT NULL,
				scan_id TEXT,
				lastcheck_time INTEGER,
				submit_time INTEGER
			);""")

	def __handle_backlog_timeout(self, watcher, event):
		logger.debug("backlog_timeout")

		# try to comment on files
		sfs = self.cursor.execute("""SELECT backlogfile, md5_hash, path FROM backlogfiles WHERE status = 'comment' LIMIT 1""")
		for sf in sfs:
			self.cursor.execute("UPDATE backlogfiles SET status = 'comment-' WHERE backlogfile = ?""", (sf[0],))
			self.dbh.commit()
			self.make_comment(sf[0], sf[1], sf[2], 'comment')
			return

		# try to receive reports for files we submitted
		sfs = self.cursor.execute("""SELECT backlogfile, md5_hash, path FROM backlogfiles WHERE status = 'query' AND submit_time < strftime("%s",'now')-15*60 AND lastcheck_time < strftime("%s",'now')-15*60 LIMIT 1""")
		for sf in sfs:
			self.cursor.execute("UPDATE backlogfiles SET status = 'query-' WHERE backlogfile = ?""", (sf[0],))
			self.dbh.commit()
			self.get_file_report(sf[0], sf[1], sf[2], 'query')
			return

		# submit files not known to virustotal
		sfs = self.cursor.execute("""SELECT backlogfile, md5_hash, path FROM backlogfiles WHERE status = 'submit' LIMIT 1""")
		for sf in sfs:
			self.cursor.execute("UPDATE backlogfiles SET status = 'submit-' WHERE backlogfile = ?""", (sf[0],))
			self.dbh.commit()
			self.scan_file(sf[0], sf[1], sf[2], 'submit')
			return

		# query new files
		sfs = self.cursor.execute("""SELECT backlogfile, md5_hash, path FROM backlogfiles WHERE status = 'new' ORDER BY timestamp DESC LIMIT 1""")
		for sf in sfs:
			self.cursor.execute("UPDATE backlogfiles SET status = 'new-' WHERE backlogfile = ?""", (sf[0],))
			self.dbh.commit()
			self.get_file_report(sf[0], sf[1], sf[2], 'new')
			return

	def stop(self):
		self.backlog_timer.stop()

	def handle_incident(self, icd):
		pass

	def handle_incident_dionaea_download_complete_unique(self, icd):
		self.cursor.execute("""INSERT INTO backlogfiles (md5_hash, path, status, timestamp) VALUES (?,?,?,strftime("%s",'now')) """, (icd.md5hash, icd.file, 'new'))

	def get_file_report(self, backlogfile, md5_hash, path, status):
		cookie = str(uuid.uuid4())
		self.cookies[cookie] = vtreport(backlogfile, md5_hash, path, status)

		i = incident("dionaea.upload.request")
		i._url = "http://www.virustotal.com/api/get_file_report.json"
		i.resource = md5_hash
		i.key = self.apikey
		i._callback = "dionaea.modules.python.virustotal.get_file_report"
		i._userdata = cookie
		i.report()

	def handle_incident_dionaea_modules_python_virustotal_get_file_report(self, icd):
		f = open(icd.path, mode='r')
		j = json.load(f)

		cookie = icd._userdata
		vtr = self.cookies[cookie]

		if j['result'] == -1:
			logger.warn("something is wrong with your virustotal api key")

		elif j['result'] == 0: # file unknown, mark for submit
			self.cursor.execute("""UPDATE backlogfiles SET status = 'submit', lastcheck_time = strftime("%s",'now') WHERE backlogfile = ?""", (vtr.backlogfile,))
			self.dbh.commit()
		elif j['result'] == 1: # file known
#			self.cursor.execute("""UPDATE backlogfiles SET status = 'comment', lastcheck_time = strftime("%s",'now') WHERE backlogfile = ?""", (vtr.backlogfile,))
			if vtr.status == 'new':
				self.cursor.execute("""DELETE FROM backlogfiles WHERE backlogfile = ?""", (vtr.backlogfile,) )
			elif vtr.status == 'query':
				self.cursor.execute("""UPDATE backlogfiles SET status = 'comment' WHERE backlogfile = ?) """, (vtr.backlogfile, ))
			self.dbh.commit()

			logger.debug("report {}".format(j) )
			date = j['report'][0]
			scans = j['report'][1]
#			for av in scans:
#				logger.debug("scanner {} result {}".format(av,scans[av]))

			i = incident("dionaea.modules.python.virustotal.report")
			i.md5hash = vtr.md5hash
			i.path = icd.path
			i.report()
		del self.cookies[cookie]

	def scan_file(self, backlogfile, md5_hash, path, status):
		cookie = str(uuid.uuid4())
		self.cookies[cookie] = vtreport(backlogfile, md5_hash, path, status)

		i = incident("dionaea.upload.request")
		i._url = "http://www.virustotal.com/api/scan_file.json"
		i.key = self.apikey
		i.set('file://file', path)
		i._callback = "dionaea.modules.python.virustotal_scan_file"
		i._userdata = cookie
		i.report()


	def handle_incident_dionaea_modules_python_virustotal_scan_file(self, icd):
		f = open(icd.path, mode='r')
		j = json.load(f)
		logger.debug("scan_file {}".format(j))
		cookie = icd._userdata
		vtr = self.cookies[cookie]
		

		if j['result'] == 1:
			scan_id = j['scan_id']
			# recycle this entry for the query
			self.cursor.execute("""UPDATE backlogfiles SET scan_id = ?, status = 'query', submit_time = strftime("%s",'now') WHERE backlogfile = ?""", (scan_id, vtr.backlogfile,))
			self.dbh.commit()
		del self.cookies[cookie]

	def make_comment(self, backlogfile, md5_hash, path, status):
		cookie = str(uuid.uuid4())
		self.cookies[cookie] = vtreport(backlogfile, md5_hash, path, status)

		i = incident("dionaea.upload.request")
		i._url = "http://www.virustotal.com/api/make_comment.json"
		i.key = self.apikey
		i.file = md5_hash
		i.tags = "honeypot;malware;networkworm"
		i.comment = "This sample was captured in the wild and uploaded by the dionaea honeypot."
		i._callback = "dionaea.modules.python.virustotal_make_comment"
		i._userdata = cookie
		i.report()

	def handle_incident_dionaea_modules_python_virustotal_make_comment(self, icd):
		cookie = icd._userdata
		vtr = self.cookies[cookie]
		f = open(icd.path, mode='r')
		try:
			j = json.load(f)
			self.cursor.execute("""DELETE FROM backlogfiles WHERE backlogfile = ?""", (vtr.backlogfile,))
			self.dbh.commit()
		except Exception as e:
			pass
		del self.cookies[cookie]

