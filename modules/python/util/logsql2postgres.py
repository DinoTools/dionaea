#!/opt/dionaea/bin/python3

# sudo su postgres
# createdb --owner=xmpp logsql
# psql -U xmpp logsql < modules/python/util/xmpp/pg_schema.sql

import sqlite3
import postgresql.driver as pg_driver
import optparse

def copy(name, lite, pg, src, dst):
    print("[+] {0}".format(name))

    pg.execute("DELETE FROM {0}".format(dst['table']))
    offset = 0
    limit = 10000
    insert = pg.prepare(dst['query'])

    while True:
        result = lite.execute(src['query'].format(limit, offset))
        r = 0
        result = result.fetchall()
        r = len(result)
        insert.load_rows(result)
#			print("{0} {1} {2}".format(offset, limit, r))
        if r != limit:
            # update the sequence if we inserted rows
            if offset + r != 0:
                pg.execute(
                    "SELECT setval('{0}',{1})".format(dst['seq'], offset + r))
            break
        offset += limit


cando = {
    'connections' : ({
        # FIXME postgres does not know connection_type pending
        # connection_type is an enum, so this may get messy
        'query' : """SELECT
		connection,
		connection_type,
		connection_transport,
		datetime(connection_timestamp, 'unixepoch') || ' UTC'  AS connection_timestamp,
		connection_parent,
		connection_root,
		ifnull(nullif(local_host,''),'0.0.0.0'),
		local_port,
		ifnull(nullif(remote_host,''),'0.0.0.0'),
		remote_port,
		connection_protocol,
		remote_hostname FROM connections WHERE connection_type != 'pending' LIMIT {:d} OFFSET {:d} \n"""
    },
        {
        'table' : 'dionaea.connections',
        'seq' : "dionaea.connections_connection_seq",
                'query' : """INSERT INTO dionaea.connections
			(connection,
			connection_type,
			connection_transport,
			connection_timestamp,
			connection_parent,
			connection_root,
			local_host,
			local_port,
			remote_host,
			remote_port,
			connection_protocol,
			remote_hostname)
			VALUES
			($1,$2,$3,$4::text::timestamp,$5,$6,$7::text::inet,$8,$9::text::inet,$10,$11,$12)""",
    }),

    'dcerpcbinds': ({
        'query' : """SELECT
		dcerpcbind,
		connection,
		dcerpcbind_uuid,
		dcerpcbind_transfersyntax FROM dcerpcbinds LIMIT {:d} OFFSET {:d} \n"""
    },
        {
        'table' : 'dionaea.dcerpcbinds',
        'seq' : "dionaea.dcerpcbinds_dcerpcbind_seq",
                'query' : """INSERT INTO dionaea.dcerpcbinds
			(dcerpcbind,
			connection,
			dcerpcbind_uuid,
			dcerpcbind_transfersyntax)
			VALUES
			($1,$2,$3,$4)""",
    }),

    'dcerpcrequests' : ({
        'query' : """SELECT
			dcerpcrequest,
			connection,
			dcerpcrequest_uuid,
			dcerpcrequest_opnum FROM dcerpcrequests LIMIT {:d} OFFSET {:d}"""
    },
        {	'table' : 'dionaea.dcerpcrequests',
          'seq' : "dionaea.dcerpcrequests_dcerpcrequest_seq",
          'query' : """INSERT INTO dionaea.dcerpcrequests
			(dcerpcrequest,
			connection,
			dcerpcrequest_uuid,
			dcerpcrequest_opnum)
			VALUES
			($1,$2,$3,$4)""",
          }),

    'dcerpcservices' : ({
        'query' : """SELECT
		dcerpcservice,
		dcerpcservice_uuid,
		dcerpcservice_name FROM dcerpcservices LIMIT {:d} OFFSET {:d}"""
    },
        {	'table' : 'dionaea.dcerpcservices',
          'seq' : "dionaea.dcerpcservices_dcerpcservice_seq",
          'query' : """INSERT INTO dionaea.dcerpcservices
			(dcerpcservice,
			dcerpcservice_uuid,
			dcerpcservice_name)
			VALUES
			($1,$2,$3)""",
          }),

    'dcerpcserviceops' : ({
        'query' : """SELECT
			dcerpcserviceop,
			dcerpcservice,
			dcerpcserviceop_name,
			dcerpcserviceop_opnum,
			dcerpcserviceop_vuln
			FROM dcerpcserviceops LIMIT {:d} OFFSET {:d}"""
    },
        {	'table' : 'dionaea.dcerpcserviceops',
          'seq' : "dionaea.dcerpcserviceops_dcerpcserviceop_seq",
          'query' : """INSERT INTO dionaea.dcerpcserviceops
			(dcerpcserviceop,
			dcerpcservice,
			dcerpcserviceop_name,
			dcerpcserviceop_opnum,
			dcerpcserviceop_vuln)
			VALUES
			($1,$2,$3,$4,$5)""",
          }),

    'downloads' : ({
        'query' : """SELECT
			download,
			connection,
			download_md5_hash,
			download_url FROM downloads LIMIT {:d} OFFSET {:d}"""
    },
        {	'table' : 'dionaea.downloads',
          'seq' : "dionaea.dcerpcrequests_dcerpcrequest_seq",
          'query' : """INSERT INTO dionaea.downloads
			(download,
			connection,
			download_md5_hash,
			download_url)
			VALUES
			($1,$2,$3,$4)""",
          }),

    'emu_profiles' : ({
        'query' : """SELECT
			emu_profile,
			connection,
			emu_profile_json FROM emu_profiles LIMIT {:d} OFFSET {:d}"""
    },
        {	'table' : 'dionaea.emu_profiles',
          'seq' : "dionaea.emu_profiles_emu_profile_seq",
          'query' : """INSERT INTO dionaea.emu_profiles
			(emu_profile,
			connection,
			emu_profile_json)
			VALUES
			($1,$2,$3)""",
          }),

    'emu_services' : ({
        'query' : """SELECT
			emu_serivce,
			connection,
			emu_service_url FROM emu_services LIMIT {:d} OFFSET {:d}"""
    },
        {	'table' : 'dionaea.emu_services',
          'seq' : "dionaea.emu_services_emu_service_seq",
          'query' : """INSERT INTO dionaea.emu_services
			(emu_service,
			connection,
			emu_service_url)
			VALUES
			($1,$2,$3)""",
          }),

    'offers' : ({
        'query' : """SELECT
			offer,
			connection,
			offer_url FROM offers LIMIT {:d} OFFSET {:d}"""
    },
        {	'table' : 'dionaea.offers',
          'seq' : "dionaea.offers_offer_seq",
          'query' : """INSERT INTO dionaea.offers
			(offer,
			connection,
			offer_url)
			VALUES
			($1,$2,$3)""",
          }),

    'p0fs' : (
        {	'query' : """SELECT
			p0f,
			connection,
			p0f_genre,
			p0f_link,
			p0f_detail,
			p0f_uptime,
			p0f_tos,
			p0f_dist,
			p0f_nat,
			p0f_fw FROM p0fs LIMIT {:d} OFFSET {:d}"""
          },
        {	'table' : 'dionaea.p0fs',
          'seq' : "dionaea.p0fs_p0f_seq",
          'query' : """INSERT INTO dionaea.p0fs
			(			p0f,
			connection,
			p0f_genre,
			p0f_link,
			p0f_detail,
			p0f_uptime,
			p0f_tos,
			p0f_dist,
			p0f_nat,
			p0f_fw)
			VALUES
			($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)""",
          }),

    'virustotals': (
        {	'query' : """SELECT
			virustotal,
			virustotal_md5_hash,
			datetime(virustotal_timestamp, 'unixepoch') || ' UTC'  AS virustotal_timestamp,
			virustotal_permalink
			FROM virustotals LIMIT {:d} OFFSET {:d}"""
          },
        {	'table' : 'dionaea.virustotals',
          'seq' : "dionaea.virustotals_virustotal_seq",
          'query' : """INSERT INTO dionaea.virustotals
			(
			virustotal,
			virustotal_md5_hash,
			virustotal_timestamp,
			virustotal_permalink
			)
			VALUES
			($1,$2,$3::text::timestamptz,$4)""",
          }),

    'virustotalscans': (
        {	'query' : """SELECT
			virustotalscan,
			virustotal,
			virustotalscan_scanner,
			nullif(virustotalscan_result,'')
			FROM virustotalscans LIMIT {:d} OFFSET {:d}"""
          },
        {	'table' : 'dionaea.virustotalscans',
          'seq' : "dionaea.virustotalscans_virustotalscan_seq",
          'query' : """INSERT INTO dionaea.virustotalscans
			(
			virustotalscan,
			virustotal,
			virustotalscan_scanner,
			virustotalscan_result
			)
			VALUES
			($1,$2,$3,$4)""",
          }),

    # x
    'mssql_fingerprints': (
        {	'query' : """SELECT
			mssql_fingerprint,
			connection,
			mssql_fingerprint_hostname,
			mssql_fingerprint_appname,
			mssql_fingerprint_cltintname FROM mssql_fingerprints LIMIT {:d} OFFSET {:d}"""
          },
        {	'table' : 'dionaea.mssql_fingerprints',
          'seq' : "dionaea.mssql_fingerprints_mssql_fingerprint_seq",
          'query' : """INSERT INTO dionaea.mssql_fingerprints
			(
			mssql_fingerprint,
			connection,
			mssql_fingerprint_hostname,
			mssql_fingerprint_appname,
			mssql_fingerprint_cltintname
			)
			VALUES
			($1,$2,$3,$4,$5)""",
          }),


    'mssql_commands': (
        {	'query' : """SELECT
			mssql_command,
			connection,
			mssql_command_status,
			mssql_command_cmd FROM mssql_commands LIMIT {:d} OFFSET {:d}"""
          },
        {	'table' : 'dionaea.mssql_commands',
          'seq' : "dionaea.mssql_commands_mssql_command_seq",
          'query' : """INSERT INTO dionaea.mssql_commands
			(
			mssql_command,
			connection,
			mssql_command_status,
			mssql_command_cmd
			)
			VALUES
			($1,$2,$3,$4)""",
          }),

    'logins': (
        {	'query' : """SELECT
			login,
			connection,
			login_username,
			login_password FROM logins LIMIT {:d} OFFSET {:d}"""
          },
        {	'table' : 'dionaea.logins',
          'seq' : "dionaea.logins_login_seq",
          'query' : """INSERT INTO dionaea.logins
			(
			login,
			connection,
			login_username,
			login_password
			)
			VALUES
			($1,$2,$3,$4)""",
          })
}

if __name__ == "__main__":
    p = optparse.OptionParser()
    p.add_option('-s', '--database-host', dest='database_host',
                 help='localhost:5432', type="string", action="store")
    p.add_option('-d', '--database', dest='database',
                 help='for example xmpp', type="string", action="store")
    p.add_option('-u', '--database-user', dest='database_user',
                 help='for example xmpp', type="string", action="store")
    p.add_option('-p', '--database-password', dest='database_password',
                 help='the database users password', type="string", action="store")
    p.add_option('-f', '--sqlite-file', dest='sqlite_file',
                 help='path to sqlite db', type="string", action="store")
    (options, args) = p.parse_args()

    if len(args) == 0:
        print("use {} as args".format( ' '.join(cando.keys()) ) )

    db = {}
    db['sqlite'] = {}
    db['sqlite']['dbh'] = sqlite3.connect(options.sqlite_file)
    db['sqlite']['cursor'] = db['sqlite']['dbh'].cursor()

    db['pg'] = {}
    db['pg']['dbh'] = pg_driver.connect(
        user = options.database_user,
        password = options.database_password,
        database = options.database,
        host = options.database_host,
        port = 5432)

    for i in args:
        if i in cando:
            copy(i,
                 db['sqlite']['cursor'],
                 db['pg']['dbh'],
                 cando[i][0],
                 cando[i][1])
#			db['pg']['dbh'].commit()
