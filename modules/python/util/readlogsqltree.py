import sqlite3
import json
import sys

def resolve_result(resultcursor):
	names = [resultcursor.description[x][0] for x in range(len(resultcursor.description))]
	resolvedresult = [ dict(zip(names, i)) for i in resultcursor]
	return resolvedresult

def print_offers(cursor, connection, indent):
	r = cursor.execute("SELECT * from offers WHERE connection = ?", (connection, ))
	offers = resolve_result(r)
	for offer in offers:
		print("%*s offer: %s" % ( indent, " ", offer['offer_url']) )

def print_downloads(cursor, connection, indent):
	r = cursor.execute("SELECT * from downloads WHERE connection = ?", (connection, ))
	downloads = resolve_result(r)
	for download in downloads:
		print("%*s download: %s %s" % ( indent, " ", download['download_md5_hash'], download['download_url']) )
	
def print_profiles(cursor, connection, indent):
	r = cursor.execute("SELECT * from emu_profiles WHERE connection = ?", (connection, ))
	profiles = resolve_result(r)
	for profile in profiles:
		print("%*s profile: %s" % ( indent, " ", json.loads(profile['emu_profile_json'])) )
		
def print_services(cursor, connection, indent):
	r = cursor.execute("SELECT * from emu_services WHERE connection = ?", (connection, ))
	services = resolve_result(r)
	for service in services:
		print("%*s service: %s" % ( indent, " ", service['emu_service_url']) ) 

def print_p0fs(cursor, connection, indent):
	r = cursor.execute("SELECT * from p0fs WHERE connection = ?", (connection, ))
	p0fs = resolve_result(r)
	for p0f in p0fs:
		print("%*s p0f: genre:'%s' detail:'%s' uptime:'%i' tos:'%s' dist:'%i' nat:'%i' fw:'%i'" % ( indent, " ", p0f['p0f_genre'], p0f['p0f_detail'], p0f['p0f_uptime'], p0f['p0f_tos'], p0f['p0f_dist'], p0f['p0f_nat'], p0f['p0f_fw']) ) 

def print_dcerpcbinds(cursor, connection, indent):
	r = cursor.execute("SELECT * from dcerpcbinds WHERE connection = ?", (connection, ))
	dcerpcbinds = resolve_result(r)
	for dcerpcbind in dcerpcbinds:
		print("%*s dcerpc bind: uuid '%s' opnum %i" % ( indent, " ", dcerpcbind['dcerpcbind_uuid'], dcerpcbind['dcerpcbind_transfersyntax']) )


def print_dcerpcrequests(cursor, connection, indent):
	r = cursor.execute("SELECT * from dcerpcrequests WHERE connection = ?", (connection, ))
	dcerpcrequests = resolve_result(r)
	for dcerpcrequest in dcerpcrequests:
		print("%*s dcerpc request: uuid '%s' opnum %i" % ( indent, " ", dcerpcrequest['dcerpcrequest_uuid'], dcerpcrequest['dcerpcrequest_opnum']) )


def print_connection(c, indent):
	if c['connection_type'] == 'accept':
		print("%*s connection %i %s %s %s %s:%i <- %s:%i" % ( indent, " ", c['connection'], c['connection_protocol'], c['connection_transport'], c['connection_type'], c['local_host'], c['local_port'], c['remote_host'], c['remote_port']) )
	elif c['connection_type'] == 'connect':
		print("%*s connection %i %s %s %s %s:%i -> %s/%s:%i" % ( indent, " ", c['connection'], c['connection_protocol'], c['connection_transport'], c['connection_type'], c['local_host'], c['local_port'], c['remote_hostname'], c['remote_host'], c['remote_port']) )
	elif c['connection_type'] == 'listen':
		print("%*s connection %i %s %s %s %s:%i" % ( indent, " ", c['connection'], c['connection_protocol'], c['connection_transport'], c['connection_type'], c['local_host'], c['local_port']) )


	

def recursive_print(cursor, connection, indent):
	result = cursor.execute("SELECT * from connections WHERE connection_parent = ?", (connection, ))
	connections = resolve_result(result)
	for c in connections:
		if c['connection'] == connection:
			continue
		print_connection(c, indent)
		print_p0fs(cursor, c['connection'], indent+2)
		print_offers(cursor, c['connection'], indent+2)
		print_downloads(cursor, c['connection'], indent+2)
		recursive_print(cursor, c['connection'], indent+2)
		

def print_db(file):
	dbh = sqlite3.connect(file)
	cursor = dbh.cursor()

	result = cursor.execute("SELECT * from connections WHERE(connection_root = connection OR connection_root IS NULL) AND remote_host = ?", (sys.argv[2],))
	connections = resolve_result(result)

	for c in connections:
		connection = c['connection']
		print_connection(c, 1)
		print_dcerpcrequests(cursor, c['connection'], 2)
		print_dcerpcbinds(cursor, c['connection'], 2)
		print_p0fs(cursor, c['connection'], 2)
		print_offers(cursor, c['connection'], 2)
		print_downloads(cursor, c['connection'], 2)
		print_profiles(cursor, c['connection'], 2)
		print_services(cursor, c['connection'], 2)
		recursive_print(cursor, c['connection'], 2)

#print_db("/opt/dionaea/var/dionaea/logsql.sqlite")
print_db(sys.argv[1])
