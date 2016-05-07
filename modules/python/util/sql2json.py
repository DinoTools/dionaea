#!/opt/dionaea/bin/python2.7

from __future__ import print_function

import json
import sqlite3
from optparse import OptionParser


def resolve_result(resultcursor):
    names = [resultcursor.description[x][0]
             for x in range(len(resultcursor.description))]
    resolvedresult = [dict(zip(names, i)) for i in resultcursor]
    return resolvedresult


def get_offers(cursor, connection):
    r = cursor.execute(
        "SELECT offer, offer_url from offers WHERE connection = ?", (connection,))
    offers = resolve_result(r)
    return offers


def get_downloads(cursor, connection):
    r = cursor.execute(
        "SELECT download, download_url as url, download_md5_hash as md5_hash from downloads WHERE connection = ?", (connection,))
    downloads = resolve_result(r)
    for download in downloads:
        virustotals = get_virustotals(cursor, download['download_md5_hash'])
        download['virustotals'] = virustotals
    return downloads


def get_virustotals(cursor, md5_hash):
    r = cursor.execute("""SELECT datetime(virustotal_timestamp, 'unixepoch', 'localtime') as timestamp, virustotal_permalink, COUNT(*) AS scanners,
		(
			SELECT COUNT(virustotalscan)
			FROM virustotals
			NATURAL JOIN virustotalscans
			WHERE virustotal_md5_hash  = ?
			AND virustotalscan_result IS NOT NULL ) AS detected
			FROM virustotals NATURAL JOIN virustotalscans WHERE virustotal_md5_hash  = ?""", (md5_hash, md5_hash))
    virustotals = resolve_result(r)
    return  virustotals


def get_profiles(cursor, connection):
    r = cursor.execute(
        "SELECT emu_profile as profile, emu_profile_json as profile_detail from emu_profiles WHERE connection = ?", (connection,))
    profiles = resolve_result(r)
    return profiles


def get_services(cursor, connection):
    r = cursor.execute(
        "SELECT emu_serivce as service, emu_service_url as service_url from emu_services WHERE connection = ?", (connection,))
    services = resolve_result(r)
    return  services


def get_p0fs(cursor, connection):
    r = cursor.execute("""
        SELECT
            p0f,
            p0f_genre as genre,
            p0f_link as link,
            p0f_detail as detail,
            p0f_uptime as uptime,
            p0f_tos as tos,
            p0f_dist as dist,
            p0f_nat as nat,
            p0f_fw as fw
            FROM p0fs WHERE connection = ?""", (connection,))
    p0fs = resolve_result(r)
    return p0fs


def get_dcerpcbinds(cursor, connection):
    r = cursor.execute("""
		SELECT DISTINCT
			dcerpcbind_uuid as uuid,
			dcerpcservice_name as name,
			dcerpcbind_transfersyntax as transfersyntax
		FROM
			dcerpcbinds
			LEFT OUTER JOIN dcerpcservices ON (dcerpcbind_uuid = dcerpcservice_uuid)
		WHERE
			connection = ?""", (connection,))
    dcerpcbinds = resolve_result(r)

    return dcerpcbinds


def get_dcerpcrequests(cursor, connection):
    r = cursor.execute("""
		SELECT
			dcerpcrequest_uuid as uuid,
			dcerpcservice_name as service_name,
			dcerpcrequest_opnum as request_opnum,
			dcerpcserviceop_name as serviceop_name,
			dcerpcserviceop_vuln as serviceop_vuln
		FROM
			dcerpcrequests
			LEFT OUTER JOIN dcerpcservices ON (dcerpcrequest_uuid = dcerpcservice_uuid)
			LEFT OUTER JOIN dcerpcserviceops ON (dcerpcservices.dcerpcservice = dcerpcserviceops.dcerpcservice AND dcerpcrequest_opnum = dcerpcserviceop_opnum)
		WHERE
			connection = ?""", (connection,))
    dcerpcrequests = resolve_result(r)

    return dcerpcrequests


def get_sip_commands(cursor, connection):
    r = cursor.execute("""
		SELECT
			sip_command as command,
			sip_command_method as command_method,
			sip_command_call_id as command_call_id,
			sip_command_user_agent as command_user_agent,
			sip_command_allow as command_allow
		FROM
			sip_commands
		WHERE
			connection = ?""", (connection,))
    sipcommands = resolve_result(r)

    for cmd in sipcommands:
        cmd['addrs'] = get_sip_addrs(cursor, cmd['command'])
        cmd['vias'] = get_sip_vias(cursor, cmd['command'])
        cmd['sdp_origins'] = get_sip_sdp_origins(cursor, cmd['command'])
        cmd['sdp_connectiondata'] = get_sip_sdp_connectiondatas(cursor, cmd['command'])
        cmd['sdp_medias'] = get_sip_sdp_medias(cursor, cmd['command'])

    return sipcommands


def get_sip_addrs(cursor, sip_command):
    r = cursor.execute("""
		SELECT
			sip_addr_type,
			sip_addr_display_name,
			sip_addr_uri_scheme,
			sip_addr_uri_user,
			sip_addr_uri_host,
			sip_addr_uri_port
		FROM
			sip_addrs
		WHERE
			sip_command = ?""", (sip_command,))
    addrs = resolve_result(r)
    return addrs


def get_sip_vias(cursor, sip_command, ):
    r = cursor.execute("""
		SELECT
			sip_via_protocol,
			sip_via_address,
			sip_via_port
		FROM
			sip_vias
		WHERE
			sip_command = ?""", (sip_command,))
    vias = resolve_result(r)
    return vias


def get_sip_sdp_origins(cursor, sip_command):
    r = cursor.execute("""
		SELECT
			sip_sdp_origin_username,
			sip_sdp_origin_sess_id,
			sip_sdp_origin_sess_version,
			sip_sdp_origin_nettype,
			sip_sdp_origin_addrtype,
			sip_sdp_origin_unicast_address
		FROM
			sip_sdp_origins
		WHERE
			sip_command = ?""", (sip_command,))
    vias = resolve_result(r)
    return vias



def get_sip_sdp_connectiondatas(cursor, sip_command):
    r = cursor.execute("""
		SELECT
			sip_sdp_connectiondata_nettype,
			sip_sdp_connectiondata_addrtype,
			sip_sdp_connectiondata_connection_address,
			sip_sdp_connectiondata_ttl,
			sip_sdp_connectiondata_number_of_addresses
		FROM
			sip_sdp_connectiondatas
		WHERE
			sip_command = ?""", (sip_command,))
    vias = resolve_result(r)
    return vias


def get_sip_sdp_medias(cursor, sip_command):
    r = cursor.execute("""
		SELECT
			sip_sdp_media_media,
			sip_sdp_media_port,
			sip_sdp_media_number_of_ports,
			sip_sdp_media_proto
		FROM
			sip_sdp_medias
		WHERE
			sip_command = ?""", (sip_command,))
    vias = resolve_result(r)
    return vias


def get_logins(cursor, connection):
    r = cursor.execute("""
		SELECT
			login_username,
			login_password
		FROM
			logins
		WHERE connection = ?""", (connection,))
    logins = resolve_result(r)
    return logins


def get_mssql_fingerprints(cursor, connection):
    r = cursor.execute("""
		SELECT
			mssql_fingerprint_hostname,
			mssql_fingerprint_appname,
			mssql_fingerprint_cltintname
		FROM
			mssql_fingerprints
		WHERE connection = ?""", (connection,))
    fingerprints = resolve_result(r)
    return fingerprints


def get_mssql_commands(cursor, connection):
    r = cursor.execute("""
		SELECT
			mssql_command_status as command_status,
			mssql_command_cmd as command_cmd
		FROM
			mssql_commands
		WHERE connection = ?""", (connection,))
    commands = resolve_result(r)
    return commands


def get_mysql_commands(cursor, connection):
    r = cursor.execute("""
		SELECT
			mysql_command as command,
			mysql_command_cmd as command_cmd,
			mysql_command_op_name as command_op_name
		FROM
			mysql_commands
			LEFT OUTER JOIN mysql_command_ops USING(mysql_command_cmd)
		WHERE
			connection = ?""", (connection,))
    commands = resolve_result(r)

    for cmd in commands:

        # args
        r = cursor.execute("""
		SELECT
			mysql_command_arg_data
		FROM
			mysql_command_args
		WHERE
			mysql_command = ?
		ORDER BY
			mysql_command_arg_index ASC """, (cmd['mysql_command'],))
        args = resolve_result(r)
        cmd['args'] = args

    return commands

def deleteContent(fName):
    with open(fName, "w"):
        pass


def print_db(options, args):
    dbpath = '/opt/dionaea/var/dionaea/logsql.sqlite'
    outputpath = 'dionaea.json'
    if len(args) >= 1:
        dbpath = args[0]
    if len(args) == 2:
        outputpath = args[1]


    dbh = sqlite3.connect(dbpath)
    cursor = dbh.cursor()
    query = """
SELECT COUNT(CONNECTION) FROM CONNECTIONS
"""
    result = cursor.execute(query)
    result_json = resolve_result(result)
    connections_number = result_json[0]['COUNT(CONNECTION)']

    cursor = dbh.cursor()

    offset = 0
    limit = 1000

    query = """
SELECT
	c.connection,
	connection_root,
	connection_parent,
	connection_type,
	connection_protocol,
	connection_transport,
	connection_timestamp,
	local_host,
	local_port,
	remote_host,
	remote_hostname,
	remote_port,
	resolves.resolve,
	resolves.resolve_hostname,
	resolves.resolve_result,
	resolves.resolve_type
FROM
	connections as c
	LEFT OUTER JOIN resolves ON (c.connection = resolves.connection)
"""

    if options.remote_host:
        query = query + \
                "\tAND remote_host = '{:s}' \n".format(options.remote_host)

    if options.connection:
        query = query + \
                "\tAND c.connection = {:d} \n".format(options.connection)

    if options.in_offer_url:
        query = query + \
                "\tAND offer_url LIKE '%{:s}%' \n".format(options.in_offer_url)

    if options.in_download_url:
        query = query + \
                "\tAND download_url LIKE '%{:s}%' \n".format(
                    options.in_download_url)

    if options.time_from:
        query = query + \
                "\tAND connection_timestamp > {:s} \n".format(options.time_from)

    if options.time_to:
        query = query + \
                "\tAND connection_timestamp < {:s} \n".format(options.time_to)

    if options.uuid:
        query = query + \
                "\tAND dcerpcbind_uuid = '{:s}' \n".format(options.uuid)

    if options.opnum:
        query = query + \
                "\tAND dcerpcrequest_opnum = {:s} \n".format(options.opnum)

    if options.protocol:
        query = query + \
                "\tAND connection_protocol = '{:s}' \n".format(options.protocol)

    if options.md5sum:
        query = query + \
                "\tAND download_md5_hash = '{:s}' \n".format(options.md5sum)

    if options.type:
        query = query + \
                "\tAND connection_type = '{:s}' \n".format(options.type)

    if options.query:
        print(query)
        return

    deleteContent(outputpath)
    with open(outputpath,'a') as out:
        out.write('[\n')
    counter = 0
    while True:
        lquery = query + "\t LIMIT {:d} OFFSET {:d} \n".format(limit, offset)
        result = cursor.execute(lquery)

        connections = resolve_result(result)
        try:
            with open(outputpath,'a') as out:
                for connection in connections:
                    connection['p0fs']= get_p0fs(cursor, connection['connection'])
                    connection['dcerpcbinds'] = get_dcerpcbinds(cursor, connection['connection'])
                    connection['dcerpcrequests'] = get_dcerpcrequests(cursor, connection['connection'])
                    connection['profiles'] = get_profiles(cursor, connection['connection'])
                    connection['offers'] = get_offers(cursor, connection['connection'])
                    connection['downloads'] = get_downloads(cursor, connection['connection'])
                    connection['emu_services'] = get_services(cursor, connection['connection'])
                    connection['logins'] = get_logins(cursor, connection['connection'])
                    connection['fingerprints']= get_mssql_fingerprints(cursor, connection['connection'])
                    connection['commands_mssql']= get_mssql_commands(cursor, connection['connection'])
                    connection['commands_mysql'] = get_mysql_commands(cursor, connection['connection'])
                    connection['sip_commands'] = get_sip_commands(cursor, connection['connection'])
                    counter += 1
                    json.dump(connection, out)
                    if(counter != connections_number):
                        out.write(',\n')
        except IOError as e:
            print ('Operation failed: {0}'.format(e.strerror))

        offset += limit
        if len(connections) != limit:
            break
    with open(outputpath,'a') as out:
        out.write(']')


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option(
        "-r", "--remote-host", action="store", type="string", dest="remote_host")
    parser.add_option(
        "-o", "--in-offer-url", action="store", type="string", dest="in_offer_url")
    parser.add_option("-d", "--in-download-url",
                      action="store", type="string", dest="in_download_url")
    parser.add_option(
        "-c", "--connection", action="store", type="int", dest="connection")
    parser.add_option(
        "-q", "--query-only", action="store_true", dest="query", default=False)
    parser.add_option(
        "-t", "--time-from", action="store", type="string", dest="time_from")
    parser.add_option(
        "-T", "--time-to", action="store", type="string", dest="time_to")
    parser.add_option(
        "-u", "--dcerpcbind-uuid", action="store", type="string", dest="uuid")
    parser.add_option(
        "-p", "--dcerpcrequest-opnum", action="store", type="string", dest="opnum")
    parser.add_option(
        "-P", "--protocol", action="store", type="string", dest="protocol")
    parser.add_option(
        "-m", "--downloads-md5sum", action="store", type="string", dest="md5sum")
    parser.add_option(
        "-y", "--connection-type", action="store", type="string", dest="type")
    (options, args) = parser.parse_args()
    print_db(options, args)
