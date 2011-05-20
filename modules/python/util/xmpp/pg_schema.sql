--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;

--
-- Name: dionaea; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA dionaea;


--
-- Name: kippo; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA kippo;


--
-- Name: malware; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA malware;


SET search_path = dionaea, pg_catalog;

--
-- Name: connection_transport; Type: TYPE; Schema: dionaea; Owner: -
--

CREATE TYPE connection_transport AS ENUM (
    'udp',
    'tcp',
    'tls'
);


--
-- Name: connection_type; Type: TYPE; Schema: dionaea; Owner: -
--

CREATE TYPE connection_type AS ENUM (
    'accept',
    'connect',
    'listen',
    'reject'
);


SET search_path = public, pg_catalog;

--
-- Name: connection_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE connection_type AS ENUM (
    'accept',
    'connect',
    'listen',
    'reject'
);


SET search_path = dionaea, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: connections; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE connections (
    connection bigint NOT NULL,
    connection_type connection_type NOT NULL,
    connection_transport connection_transport NOT NULL,
    connection_timestamp timestamp with time zone NOT NULL,
    connection_parent bigint,
    connection_root bigint,
    local_host inet NOT NULL,
    local_port integer NOT NULL,
    remote_host inet NOT NULL,
    remote_port integer NOT NULL,
    connection_protocol character varying(32) NOT NULL,
    remote_hostname character varying(32)
);


--
-- Name: connections_connection_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE connections_connection_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: connections_connection_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE connections_connection_seq OWNED BY connections.connection;


--
-- Name: dcerpcbinds; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE dcerpcbinds (
    dcerpcbind bigint NOT NULL,
    connection bigint NOT NULL,
    dcerpcbind_uuid uuid NOT NULL,
    dcerpcbind_transfersyntax uuid NOT NULL
);


--
-- Name: dcerpcbinds_dcerpcbind_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcbinds_dcerpcbind_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: dcerpcbinds_dcerpcbind_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcbinds_dcerpcbind_seq OWNED BY dcerpcbinds.dcerpcbind;


--
-- Name: dcerpcrequests; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE dcerpcrequests (
    dcerpcrequest bigint NOT NULL,
    connection bigint NOT NULL,
    dcerpcrequest_uuid uuid NOT NULL,
    dcerpcrequest_opnum smallint NOT NULL
);


--
-- Name: dcerpcrequests_dcerpcrequest_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcrequests_dcerpcrequest_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: dcerpcrequests_dcerpcrequest_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcrequests_dcerpcrequest_seq OWNED BY dcerpcrequests.dcerpcrequest;


--
-- Name: dcerpcserviceops; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE dcerpcserviceops (
    dcerpcserviceop integer NOT NULL,
    dcerpcservice integer,
    dcerpcserviceop_opnum smallint NOT NULL,
    dcerpcserviceop_name character varying(64) NOT NULL,
    dcerpcserviceop_vuln character varying(32)
);


--
-- Name: dcerpcserviceops_dcerpcserviceop_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcserviceops_dcerpcserviceop_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: dcerpcserviceops_dcerpcserviceop_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcserviceops_dcerpcserviceop_seq OWNED BY dcerpcserviceops.dcerpcserviceop;


--
-- Name: dcerpcservices; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE dcerpcservices (
    dcerpcservice integer NOT NULL,
    dcerpcservice_uuid uuid NOT NULL,
    dcerpcservice_name character varying(32) NOT NULL
);


--
-- Name: dcerpcservices_dcerpcservice_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcservices_dcerpcservice_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: dcerpcservices_dcerpcservice_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcservices_dcerpcservice_seq OWNED BY dcerpcservices.dcerpcservice;


--
-- Name: downloads; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE downloads (
    download bigint NOT NULL,
    connection bigint NOT NULL,
    download_md5_hash character varying(32) NOT NULL,
    download_url character varying(256) NOT NULL
);


--
-- Name: downloads_download_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE downloads_download_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: downloads_download_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE downloads_download_seq OWNED BY downloads.download;


--
-- Name: emu_profiles; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE emu_profiles (
    emu_profile bigint NOT NULL,
    connection bigint NOT NULL,
    emu_profile_json text NOT NULL
);


--
-- Name: emu_profiles_emu_profile_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE emu_profiles_emu_profile_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: emu_profiles_emu_profile_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE emu_profiles_emu_profile_seq OWNED BY emu_profiles.emu_profile;


--
-- Name: emu_services; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE emu_services (
    emu_service bigint NOT NULL,
    connection bigint,
    emu_service_url character varying(64)
);


--
-- Name: emu_services_emu_service_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE emu_services_emu_service_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: emu_services_emu_service_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE emu_services_emu_service_seq OWNED BY emu_services.emu_service;


--
-- Name: heatpoints; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE heatpoints (
    heatpoint integer NOT NULL,
    connection integer NOT NULL,
    lat real NOT NULL,
    lng real NOT NULL
);


--
-- Name: heatpoints_heatpoint_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE heatpoints_heatpoint_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: heatpoints_heatpoint_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE heatpoints_heatpoint_seq OWNED BY heatpoints.heatpoint;


--
-- Name: logins; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE logins (
    login bigint NOT NULL,
    connection bigint,
    login_username character varying(64),
    login_password character varying(64)
);


--
-- Name: logins_login_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE logins_login_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: logins_login_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE logins_login_seq OWNED BY logins.login;


--
-- Name: mssql_commands; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE mssql_commands (
    mssql_command bigint NOT NULL,
    connection bigint NOT NULL,
    mssql_command_status character varying(8) NOT NULL,
    mssql_command_cmd text NOT NULL
);


--
-- Name: mssql_commands_mssql_command_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE mssql_commands_mssql_command_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: mssql_commands_mssql_command_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE mssql_commands_mssql_command_seq OWNED BY mssql_commands.mssql_command;


--
-- Name: mssql_fingerprints; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE mssql_fingerprints (
    mssql_fingerprint bigint NOT NULL,
    connection bigint NOT NULL,
    mssql_fingerprint_hostname character varying(64),
    mssql_fingerprint_appname character varying(32),
    mssql_fingerprint_cltintname character varying(32)
);


--
-- Name: mssql_fingerprints_mssql_fingerprint_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE mssql_fingerprints_mssql_fingerprint_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: mssql_fingerprints_mssql_fingerprint_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE mssql_fingerprints_mssql_fingerprint_seq OWNED BY mssql_fingerprints.mssql_fingerprint;


--
-- Name: mysql_command_args; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE mysql_command_args (
    mysql_command_arg bigint NOT NULL,
    mysql_command bigint NOT NULL,
    mysql_command_arg_index smallint NOT NULL,
    mysql_command_arg_data text NOT NULL
);


--
-- Name: mysql_command_args_mysql_command_arg_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE mysql_command_args_mysql_command_arg_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: mysql_command_args_mysql_command_arg_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE mysql_command_args_mysql_command_arg_seq OWNED BY mysql_command_args.mysql_command_arg;


--
-- Name: mysql_commands; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE mysql_commands (
    mysql_command bigint NOT NULL,
    connection bigint NOT NULL,
    mysql_command_cmd smallint NOT NULL
);


--
-- Name: mysql_commands_mysql_command_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE mysql_commands_mysql_command_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: mysql_commands_mysql_command_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE mysql_commands_mysql_command_seq OWNED BY mysql_commands.mysql_command;


--
-- Name: offers; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE offers (
    offer bigint NOT NULL,
    connection bigint NOT NULL,
    offer_url character varying(256) NOT NULL
);


--
-- Name: offers_offer_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE offers_offer_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: offers_offer_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE offers_offer_seq OWNED BY offers.offer;


--
-- Name: p0fs; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE p0fs (
    p0f bigint NOT NULL,
    connection bigint,
    p0f_genre character varying(64),
    p0f_link character varying(64),
    p0f_detail character varying(64),
    p0f_uptime integer,
    p0f_tos character varying(16),
    p0f_dist integer,
    p0f_nat integer,
    p0f_fw integer
);


--
-- Name: p0fs_p0f_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE p0fs_p0f_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: p0fs_p0f_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE p0fs_p0f_seq OWNED BY p0fs.p0f;


--
-- Name: virustotals; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE virustotals (
    virustotal integer NOT NULL,
    virustotal_md5_hash character(32) NOT NULL,
    virustotal_timestamp timestamp with time zone NOT NULL,
    virustotal_permalink character varying(128) NOT NULL
);


--
-- Name: virustotals_virustotal_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE virustotals_virustotal_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: virustotals_virustotal_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE virustotals_virustotal_seq OWNED BY virustotals.virustotal;


--
-- Name: virustotalscans; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE virustotalscans (
    virustotalscan integer NOT NULL,
    virustotal integer NOT NULL,
    virustotalscan_scanner character varying(32) NOT NULL,
    virustotalscan_result text
);


--
-- Name: virustotalscans_virustotalscan_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE virustotalscans_virustotalscan_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: virustotalscans_virustotalscan_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE virustotalscans_virustotalscan_seq OWNED BY virustotalscans.virustotalscan;


SET search_path = kippo, pg_catalog;

--
-- Name: asns_asn_seq; Type: SEQUENCE; Schema: kippo; Owner: -
--

CREATE SEQUENCE asns_asn_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: auths; Type: TABLE; Schema: kippo; Owner: -; Tablespace: 
--

CREATE TABLE auths (
    auth integer NOT NULL,
    session integer NOT NULL,
    auth_success boolean NOT NULL,
    auth_username character varying(64) NOT NULL,
    auth_password character varying(64) NOT NULL,
    auth_timestamp timestamp with time zone NOT NULL
);


--
-- Name: auths_auth_seq; Type: SEQUENCE; Schema: kippo; Owner: -
--

CREATE SEQUENCE auths_auth_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: auths_auth_seq; Type: SEQUENCE OWNED BY; Schema: kippo; Owner: -
--

ALTER SEQUENCE auths_auth_seq OWNED BY auths.auth;


--
-- Name: clients; Type: TABLE; Schema: kippo; Owner: -; Tablespace: 
--

CREATE TABLE clients (
    client integer NOT NULL,
    version character varying(128) NOT NULL,
    session integer NOT NULL
);


--
-- Name: clients_client_seq; Type: SEQUENCE; Schema: kippo; Owner: -
--

CREATE SEQUENCE clients_client_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: clients_client_seq; Type: SEQUENCE OWNED BY; Schema: kippo; Owner: -
--

ALTER SEQUENCE clients_client_seq OWNED BY clients.client;


--
-- Name: inputs; Type: TABLE; Schema: kippo; Owner: -; Tablespace: 
--

CREATE TABLE inputs (
    input integer NOT NULL,
    session integer NOT NULL,
    input_timestamp timestamp with time zone NOT NULL,
    input_realm character varying(128) NOT NULL,
    input_success boolean NOT NULL,
    input_data text NOT NULL
);


--
-- Name: inputs_input_seq; Type: SEQUENCE; Schema: kippo; Owner: -
--

CREATE SEQUENCE inputs_input_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: inputs_input_seq; Type: SEQUENCE OWNED BY; Schema: kippo; Owner: -
--

ALTER SEQUENCE inputs_input_seq OWNED BY inputs.input;


--
-- Name: sessions; Type: TABLE; Schema: kippo; Owner: -; Tablespace: 
--

CREATE TABLE sessions (
    session integer NOT NULL,
    session_start timestamp with time zone NOT NULL,
    session_stop timestamp with time zone NOT NULL,
    local_host inet NOT NULL,
    remote_host inet NOT NULL
);


--
-- Name: sessions_session_seq; Type: SEQUENCE; Schema: kippo; Owner: -
--

CREATE SEQUENCE sessions_session_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: sessions_session_seq; Type: SEQUENCE OWNED BY; Schema: kippo; Owner: -
--

ALTER SEQUENCE sessions_session_seq OWNED BY sessions.session;


SET search_path = malware, pg_catalog;

--
-- Name: anubi; Type: TABLE; Schema: malware; Owner: -; Tablespace: 
--

CREATE TABLE anubi (
    anubis integer NOT NULL,
    malware integer NOT NULL,
    txt text NOT NULL,
    xml xml,
    html text,
    pcap bytea,
    "timestamp" timestamp with time zone DEFAULT '2009-10-21 05:51:03+02'::timestamp with time zone NOT NULL,
    link character varying
);


--
-- Name: anubi_anubis_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE anubi_anubis_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: anubi_anubis_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE anubi_anubis_seq OWNED BY anubi.anubis;


--
-- Name: cwsandboxs; Type: TABLE; Schema: malware; Owner: -; Tablespace: 
--

CREATE TABLE cwsandboxs (
    cwsandbox integer NOT NULL,
    malware integer,
    txt text,
    xml xml,
    html text,
    "timestamp" timestamp with time zone DEFAULT '2009-10-21 05:51:03+02'::timestamp with time zone NOT NULL,
    link character varying(128) NOT NULL
);


--
-- Name: cwsandboxs_cwsandbox_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE cwsandboxs_cwsandbox_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: cwsandboxs_cwsandbox_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE cwsandboxs_cwsandbox_seq OWNED BY cwsandboxs.cwsandbox;


--
-- Name: malwares; Type: TABLE; Schema: malware; Owner: -; Tablespace: 
--

CREATE TABLE malwares (
    malware integer NOT NULL,
    malware_md5 character(32) NOT NULL,
    malware_sha1 character(40),
    malware_size integer,
    malware_timestamp timestamp with time zone NOT NULL
);


--
-- Name: malwares_malware_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE malwares_malware_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: malwares_malware_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE malwares_malware_seq OWNED BY malwares.malware;


--
-- Name: normans; Type: TABLE; Schema: malware; Owner: -; Tablespace: 
--

CREATE TABLE normans (
    norman integer NOT NULL,
    malware integer NOT NULL,
    txt text NOT NULL,
    "timestamp" timestamp with time zone DEFAULT '2009-10-21 12:14:25+02'::timestamp with time zone NOT NULL
);


--
-- Name: normans_norman_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE normans_norman_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: normans_norman_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE normans_norman_seq OWNED BY normans.norman;


--
-- Name: virustotals; Type: TABLE; Schema: malware; Owner: -; Tablespace: 
--

CREATE TABLE virustotals (
    virustotal integer NOT NULL,
    malware integer NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    link character varying(256) NOT NULL,
    status smallint DEFAULT (-1) NOT NULL
);


--
-- Name: virustotals_virustotal_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE virustotals_virustotal_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: virustotals_virustotal_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE virustotals_virustotal_seq OWNED BY virustotals.virustotal;


--
-- Name: virustotalscans; Type: TABLE; Schema: malware; Owner: -; Tablespace: 
--

CREATE TABLE virustotalscans (
    virustotalscan integer NOT NULL,
    virustotal integer NOT NULL,
    virustotalscan_scanner character varying(128) NOT NULL,
    virustotalscan_result character varying(256)
);


--
-- Name: virustotalscans_virustotalscan_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE virustotalscans_virustotalscan_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- Name: virustotalscans_virustotalscan_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE virustotalscans_virustotalscan_seq OWNED BY virustotalscans.virustotalscan;


SET search_path = dionaea, pg_catalog;

--
-- Name: connection; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE connections ALTER COLUMN connection SET DEFAULT nextval('connections_connection_seq'::regclass);


--
-- Name: dcerpcbind; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcbinds ALTER COLUMN dcerpcbind SET DEFAULT nextval('dcerpcbinds_dcerpcbind_seq'::regclass);


--
-- Name: dcerpcrequest; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcrequests ALTER COLUMN dcerpcrequest SET DEFAULT nextval('dcerpcrequests_dcerpcrequest_seq'::regclass);


--
-- Name: dcerpcserviceop; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcserviceops ALTER COLUMN dcerpcserviceop SET DEFAULT nextval('dcerpcserviceops_dcerpcserviceop_seq'::regclass);


--
-- Name: dcerpcservice; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcservices ALTER COLUMN dcerpcservice SET DEFAULT nextval('dcerpcservices_dcerpcservice_seq'::regclass);


--
-- Name: download; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE downloads ALTER COLUMN download SET DEFAULT nextval('downloads_download_seq'::regclass);


--
-- Name: emu_profile; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE emu_profiles ALTER COLUMN emu_profile SET DEFAULT nextval('emu_profiles_emu_profile_seq'::regclass);


--
-- Name: emu_service; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE emu_services ALTER COLUMN emu_service SET DEFAULT nextval('emu_services_emu_service_seq'::regclass);


--
-- Name: heatpoint; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE heatpoints ALTER COLUMN heatpoint SET DEFAULT nextval('heatpoints_heatpoint_seq'::regclass);


--
-- Name: login; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE logins ALTER COLUMN login SET DEFAULT nextval('logins_login_seq'::regclass);


--
-- Name: mssql_command; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE mssql_commands ALTER COLUMN mssql_command SET DEFAULT nextval('mssql_commands_mssql_command_seq'::regclass);


--
-- Name: mssql_fingerprint; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE mssql_fingerprints ALTER COLUMN mssql_fingerprint SET DEFAULT nextval('mssql_fingerprints_mssql_fingerprint_seq'::regclass);


--
-- Name: mysql_command_arg; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE mysql_command_args ALTER COLUMN mysql_command_arg SET DEFAULT nextval('mysql_command_args_mysql_command_arg_seq'::regclass);


--
-- Name: mysql_command; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE mysql_commands ALTER COLUMN mysql_command SET DEFAULT nextval('mysql_commands_mysql_command_seq'::regclass);


--
-- Name: offer; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE offers ALTER COLUMN offer SET DEFAULT nextval('offers_offer_seq'::regclass);


--
-- Name: p0f; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE p0fs ALTER COLUMN p0f SET DEFAULT nextval('p0fs_p0f_seq'::regclass);


--
-- Name: virustotal; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE virustotals ALTER COLUMN virustotal SET DEFAULT nextval('virustotals_virustotal_seq'::regclass);


--
-- Name: virustotalscan; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE virustotalscans ALTER COLUMN virustotalscan SET DEFAULT nextval('virustotalscans_virustotalscan_seq'::regclass);


SET search_path = kippo, pg_catalog;

--
-- Name: auth; Type: DEFAULT; Schema: kippo; Owner: -
--

ALTER TABLE auths ALTER COLUMN auth SET DEFAULT nextval('auths_auth_seq'::regclass);


--
-- Name: client; Type: DEFAULT; Schema: kippo; Owner: -
--

ALTER TABLE clients ALTER COLUMN client SET DEFAULT nextval('clients_client_seq'::regclass);


--
-- Name: input; Type: DEFAULT; Schema: kippo; Owner: -
--

ALTER TABLE inputs ALTER COLUMN input SET DEFAULT nextval('inputs_input_seq'::regclass);


--
-- Name: session; Type: DEFAULT; Schema: kippo; Owner: -
--

ALTER TABLE sessions ALTER COLUMN session SET DEFAULT nextval('sessions_session_seq'::regclass);


SET search_path = malware, pg_catalog;

--
-- Name: anubis; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE anubi ALTER COLUMN anubis SET DEFAULT nextval('anubi_anubis_seq'::regclass);


--
-- Name: cwsandbox; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE cwsandboxs ALTER COLUMN cwsandbox SET DEFAULT nextval('cwsandboxs_cwsandbox_seq'::regclass);


--
-- Name: malware; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE malwares ALTER COLUMN malware SET DEFAULT nextval('malwares_malware_seq'::regclass);


--
-- Name: norman; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE normans ALTER COLUMN norman SET DEFAULT nextval('normans_norman_seq'::regclass);


--
-- Name: virustotal; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE virustotals ALTER COLUMN virustotal SET DEFAULT nextval('virustotals_virustotal_seq'::regclass);


--
-- Name: virustotalscan; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE virustotalscans ALTER COLUMN virustotalscan SET DEFAULT nextval('virustotalscans_virustotalscan_seq'::regclass);


SET search_path = dionaea, pg_catalog;

--
-- Name: connections_connection_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY connections
    ADD CONSTRAINT connections_connection_pkey PRIMARY KEY (connection);


--
-- Name: dcerpcbinds_dcerpcbind_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcbinds
    ADD CONSTRAINT dcerpcbinds_dcerpcbind_pkey PRIMARY KEY (dcerpcbind);


--
-- Name: dcerpcrequests_dcerpcrequest_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcrequests
    ADD CONSTRAINT dcerpcrequests_dcerpcrequest_pkey PRIMARY KEY (dcerpcrequest);


--
-- Name: dcerpcserviceops_dcerpcserviceop_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcserviceops
    ADD CONSTRAINT dcerpcserviceops_dcerpcserviceop_pkey PRIMARY KEY (dcerpcserviceop);


--
-- Name: dcerpcservices_dcerpcservice_uuid_uniq; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcservices
    ADD CONSTRAINT dcerpcservices_dcerpcservice_uuid_uniq UNIQUE (dcerpcservice_uuid);


--
-- Name: dcerpcservices_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcservices
    ADD CONSTRAINT dcerpcservices_pkey PRIMARY KEY (dcerpcservice);


--
-- Name: downloads_download_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY downloads
    ADD CONSTRAINT downloads_download_pkey PRIMARY KEY (download);


--
-- Name: emu_profiles_emu_profile_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY emu_profiles
    ADD CONSTRAINT emu_profiles_emu_profile_pkey PRIMARY KEY (emu_profile);


--
-- Name: emu_services_emu_service_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY emu_services
    ADD CONSTRAINT emu_services_emu_service_pkey PRIMARY KEY (emu_service);


--
-- Name: heatpoints_heatpoint_pk; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY heatpoints
    ADD CONSTRAINT heatpoints_heatpoint_pk PRIMARY KEY (heatpoint);


--
-- Name: logins_login_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY logins
    ADD CONSTRAINT logins_login_pkey PRIMARY KEY (login);


--
-- Name: mssql_commands_mssql_command_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY mssql_commands
    ADD CONSTRAINT mssql_commands_mssql_command_pkey PRIMARY KEY (mssql_command);


--
-- Name: mssql_fingerprints_mssql_fingerprint_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY mssql_fingerprints
    ADD CONSTRAINT mssql_fingerprints_mssql_fingerprint_pkey PRIMARY KEY (mssql_fingerprint);


--
-- Name: mysql_command_args_mysql_command_arg_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY mysql_command_args
    ADD CONSTRAINT mysql_command_args_mysql_command_arg_pkey PRIMARY KEY (mysql_command_arg);


--
-- Name: mysql_commands_mysql_command_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY mysql_commands
    ADD CONSTRAINT mysql_commands_mysql_command_pkey PRIMARY KEY (mysql_command);


--
-- Name: offers_offer_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY offers
    ADD CONSTRAINT offers_offer_pkey PRIMARY KEY (offer);


--
-- Name: p0fs_p0f_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY p0fs
    ADD CONSTRAINT p0fs_p0f_pkey PRIMARY KEY (p0f);


--
-- Name: virustotals_virustotal_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY virustotals
    ADD CONSTRAINT virustotals_virustotal_pkey PRIMARY KEY (virustotal);


--
-- Name: virustotalscans_virustotalscan_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY virustotalscans
    ADD CONSTRAINT virustotalscans_virustotalscan_pkey PRIMARY KEY (virustotalscan);


SET search_path = kippo, pg_catalog;

--
-- Name: auths_pkey; Type: CONSTRAINT; Schema: kippo; Owner: -; Tablespace: 
--

ALTER TABLE ONLY auths
    ADD CONSTRAINT auths_pkey PRIMARY KEY (auth);


--
-- Name: clients_pkey; Type: CONSTRAINT; Schema: kippo; Owner: -; Tablespace: 
--

ALTER TABLE ONLY clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (client);


--
-- Name: inputs_pkey; Type: CONSTRAINT; Schema: kippo; Owner: -; Tablespace: 
--

ALTER TABLE ONLY inputs
    ADD CONSTRAINT inputs_pkey PRIMARY KEY (input);


--
-- Name: sessions_pkey; Type: CONSTRAINT; Schema: kippo; Owner: -; Tablespace: 
--

ALTER TABLE ONLY sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (session);


SET search_path = malware, pg_catalog;

--
-- Name: anubi_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY anubi
    ADD CONSTRAINT anubi_pkey PRIMARY KEY (anubis);


--
-- Name: cwsandbox_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY cwsandboxs
    ADD CONSTRAINT cwsandbox_pkey PRIMARY KEY (cwsandbox);


--
-- Name: malware_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY malwares
    ADD CONSTRAINT malware_pkey PRIMARY KEY (malware);


--
-- Name: norman_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY normans
    ADD CONSTRAINT norman_pkey PRIMARY KEY (norman);


--
-- Name: virustotals_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY virustotals
    ADD CONSTRAINT virustotals_pkey PRIMARY KEY (virustotal);


--
-- Name: virustotalscans_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY virustotalscans
    ADD CONSTRAINT virustotalscans_pkey PRIMARY KEY (virustotalscan);


SET search_path = dionaea, pg_catalog;

--
-- Name: connections_local_host_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_local_host_idx ON connections USING btree (local_host);


--
-- Name: connections_local_port_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_local_port_idx ON connections USING btree (local_port);


--
-- Name: connections_parent_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_parent_idx ON connections USING btree (connection_parent);


--
-- Name: connections_remote_host_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_remote_host_idx ON connections USING btree (remote_host);


--
-- Name: connections_root_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_root_idx ON connections USING btree (connection_root);


--
-- Name: connections_timestamp_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_timestamp_idx ON connections USING btree (connection_timestamp);


--
-- Name: connections_type_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_type_idx ON connections USING btree (connection_type);


--
-- Name: dcerpcbinds_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_connection_idx ON dcerpcbinds USING btree (connection);


--
-- Name: dcerpcbinds_transfersyntax_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_transfersyntax_idx ON dcerpcbinds USING btree (dcerpcbind_transfersyntax);


--
-- Name: dcerpcbinds_uuid_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_uuid_idx ON dcerpcbinds USING btree (dcerpcbind_uuid);


--
-- Name: dcerpcrequests_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_connection_idx ON dcerpcrequests USING btree (connection);


--
-- Name: dcerpcrequests_opnum_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_opnum_idx ON dcerpcrequests USING btree (dcerpcrequest_opnum);


--
-- Name: dcerpcrequests_uuid_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_uuid_idx ON dcerpcrequests USING btree (dcerpcrequest_uuid);


--
-- Name: downloads_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_connection_idx ON downloads USING btree (connection);


--
-- Name: downloads_md5_hash_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_md5_hash_idx ON downloads USING btree (download_md5_hash);


--
-- Name: downloads_url_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_url_idx ON downloads USING btree (download_url);


--
-- Name: fki_dcerpcbinds_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_dcerpcbinds_connection_fkey ON dcerpcbinds USING btree (connection);


--
-- Name: fki_dcerpcrequests_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_dcerpcrequests_connection_fkey ON dcerpcrequests USING btree (connection);


--
-- Name: fki_downloads_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_downloads_connection_fkey ON downloads USING btree (connection);


--
-- Name: fki_emu_profiles_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_emu_profiles_connection_fkey ON emu_profiles USING btree (connection);


--
-- Name: fki_emu_services_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_emu_services_connection_fkey ON emu_services USING btree (connection);


--
-- Name: fki_logins_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_logins_connection_fkey ON logins USING btree (connection);


--
-- Name: fki_mssql_commands_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_mssql_commands_connection_fkey ON mssql_commands USING btree (connection);


--
-- Name: fki_mssql_fingerprints_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_mssql_fingerprints_connection_fkey ON mssql_fingerprints USING btree (connection);


--
-- Name: fki_offers_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_offers_connection_fkey ON offers USING btree (connection);


--
-- Name: fki_p0fs_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_p0fs_connection_fkey ON p0fs USING btree (connection);


--
-- Name: fki_virustotalscans_virustotal_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_virustotalscans_virustotal_fkey ON virustotalscans USING btree (virustotal);


--
-- Name: heatpoints_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX heatpoints_connection_idx ON heatpoints USING btree (connection);


--
-- Name: heatpoints_lat_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX heatpoints_lat_idx ON heatpoints USING btree (lat);


--
-- Name: heatpoints_lng_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX heatpoints_lng_idx ON heatpoints USING btree (lng);


--
-- Name: offers_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX offers_connection_idx ON offers USING btree (connection);


--
-- Name: offers_url_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX offers_url_idx ON offers USING btree (offer_url);


--
-- Name: p0fs_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_connection_idx ON p0fs USING btree (connection);


--
-- Name: p0fs_detail_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_detail_idx ON p0fs USING btree (p0f_detail);


--
-- Name: p0fs_genre_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_genre_idx ON p0fs USING btree (p0f_genre);


--
-- Name: p0fs_uptime_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_uptime_idx ON p0fs USING btree (p0f_uptime);


SET search_path = malware, pg_catalog;

--
-- Name: anubi_malware_idx; Type: INDEX; Schema: malware; Owner: -; Tablespace: 
--

CREATE INDEX anubi_malware_idx ON anubi USING btree (malware);


--
-- Name: cwsandboxs_malware_idx; Type: INDEX; Schema: malware; Owner: -; Tablespace: 
--

CREATE INDEX cwsandboxs_malware_idx ON cwsandboxs USING btree (malware);


--
-- Name: malwares_malware_m5_idx; Type: INDEX; Schema: malware; Owner: -; Tablespace: 
--

CREATE INDEX malwares_malware_m5_idx ON malwares USING btree (malware_md5);


--
-- Name: normans_malware_idx; Type: INDEX; Schema: malware; Owner: -; Tablespace: 
--

CREATE INDEX normans_malware_idx ON normans USING btree (malware);


--
-- Name: virustotalscans_virustotal_idx; Type: INDEX; Schema: malware; Owner: -; Tablespace: 
--

CREATE INDEX virustotalscans_virustotal_idx ON virustotalscans USING btree (virustotal);


SET search_path = dionaea, pg_catalog;

--
-- Name: dcerpcbinds_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY dcerpcbinds
    ADD CONSTRAINT dcerpcbinds_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: dcerpcrequests_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY dcerpcrequests
    ADD CONSTRAINT dcerpcrequests_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: downloads_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY downloads
    ADD CONSTRAINT downloads_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: emu_profiles_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY emu_profiles
    ADD CONSTRAINT emu_profiles_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: emu_services_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY emu_services
    ADD CONSTRAINT emu_services_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: heatpoints_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY heatpoints
    ADD CONSTRAINT heatpoints_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection);


--
-- Name: logins_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY logins
    ADD CONSTRAINT logins_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: mssql_commands_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY mssql_commands
    ADD CONSTRAINT mssql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: mssql_fingerprints_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY mssql_fingerprints
    ADD CONSTRAINT mssql_fingerprints_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: mysql_command_args_mysql_command_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY mysql_command_args
    ADD CONSTRAINT mysql_command_args_mysql_command_fkey FOREIGN KEY (mysql_command) REFERENCES mysql_commands(mysql_command) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: mysql_commands_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY mysql_commands
    ADD CONSTRAINT mysql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: offers_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY offers
    ADD CONSTRAINT offers_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: p0fs_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY p0fs
    ADD CONSTRAINT p0fs_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: virustotalscans_virustotal_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY virustotalscans
    ADD CONSTRAINT virustotalscans_virustotal_fkey FOREIGN KEY (virustotal) REFERENCES virustotals(virustotal) ON UPDATE RESTRICT ON DELETE CASCADE;


SET search_path = malware, pg_catalog;

--
-- Name: anubi_malware_fkey; Type: FK CONSTRAINT; Schema: malware; Owner: -
--

ALTER TABLE ONLY anubi
    ADD CONSTRAINT anubi_malware_fkey FOREIGN KEY (malware) REFERENCES malwares(malware);


--
-- Name: cwsandbox_malware_fkey; Type: FK CONSTRAINT; Schema: malware; Owner: -
--

ALTER TABLE ONLY cwsandboxs
    ADD CONSTRAINT cwsandbox_malware_fkey FOREIGN KEY (malware) REFERENCES malwares(malware);


--
-- Name: norman_malware_fkey; Type: FK CONSTRAINT; Schema: malware; Owner: -
--

ALTER TABLE ONLY normans
    ADD CONSTRAINT norman_malware_fkey FOREIGN KEY (malware) REFERENCES malwares(malware);


--
-- Name: virustotals_malware_fkey; Type: FK CONSTRAINT; Schema: malware; Owner: -
--

ALTER TABLE ONLY virustotals
    ADD CONSTRAINT virustotals_malware_fkey FOREIGN KEY (malware) REFERENCES malwares(malware);


--
-- Name: virustotalscans_virustotal_fkey; Type: FK CONSTRAINT; Schema: malware; Owner: -
--

ALTER TABLE ONLY virustotalscans
    ADD CONSTRAINT virustotalscans_virustotal_fkey FOREIGN KEY (virustotal) REFERENCES virustotals(virustotal);


--
-- Name: dionaea; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA dionaea FROM PUBLIC;
REVOKE ALL ON SCHEMA dionaea FROM xmpp;
GRANT ALL ON SCHEMA dionaea TO xmpp;


--
-- Name: kippo; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA kippo FROM PUBLIC;
REVOKE ALL ON SCHEMA kippo FROM xmpp;
GRANT ALL ON SCHEMA kippo TO xmpp;


--
-- Name: malware; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA malware FROM PUBLIC;
REVOKE ALL ON SCHEMA malware FROM xmpp;
GRANT ALL ON SCHEMA malware TO xmpp;


--
-- Name: public; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


SET search_path = dionaea, pg_catalog;

--
-- Name: connections; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE connections FROM PUBLIC;
REVOKE ALL ON TABLE connections FROM xmpp;
GRANT ALL ON TABLE connections TO xmpp;


--
-- Name: dcerpcbinds; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE dcerpcbinds FROM PUBLIC;
REVOKE ALL ON TABLE dcerpcbinds FROM xmpp;
GRANT ALL ON TABLE dcerpcbinds TO xmpp;


--
-- Name: dcerpcrequests; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE dcerpcrequests FROM PUBLIC;
REVOKE ALL ON TABLE dcerpcrequests FROM xmpp;
GRANT ALL ON TABLE dcerpcrequests TO xmpp;


--
-- Name: dcerpcserviceops; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE dcerpcserviceops FROM PUBLIC;
REVOKE ALL ON TABLE dcerpcserviceops FROM xmpp;
GRANT ALL ON TABLE dcerpcserviceops TO xmpp;


--
-- Name: dcerpcservices; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE dcerpcservices FROM PUBLIC;
REVOKE ALL ON TABLE dcerpcservices FROM xmpp;
GRANT ALL ON TABLE dcerpcservices TO xmpp;


--
-- Name: downloads; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE downloads FROM PUBLIC;
REVOKE ALL ON TABLE downloads FROM xmpp;
GRANT ALL ON TABLE downloads TO xmpp;


--
-- Name: emu_profiles; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE emu_profiles FROM PUBLIC;
REVOKE ALL ON TABLE emu_profiles FROM xmpp;
GRANT ALL ON TABLE emu_profiles TO xmpp;


--
-- Name: emu_services; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE emu_services FROM PUBLIC;
REVOKE ALL ON TABLE emu_services FROM xmpp;
GRANT ALL ON TABLE emu_services TO xmpp;


--
-- Name: heatpoints; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE heatpoints FROM PUBLIC;
REVOKE ALL ON TABLE heatpoints FROM xmpp;
GRANT ALL ON TABLE heatpoints TO xmpp;


--
-- Name: logins; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE logins FROM PUBLIC;
REVOKE ALL ON TABLE logins FROM xmpp;
GRANT ALL ON TABLE logins TO xmpp;


--
-- Name: mssql_commands; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE mssql_commands FROM PUBLIC;
REVOKE ALL ON TABLE mssql_commands FROM xmpp;
GRANT ALL ON TABLE mssql_commands TO xmpp;


--
-- Name: mssql_fingerprints; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE mssql_fingerprints FROM PUBLIC;
REVOKE ALL ON TABLE mssql_fingerprints FROM xmpp;
GRANT ALL ON TABLE mssql_fingerprints TO xmpp;


--
-- Name: offers; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE offers FROM PUBLIC;
REVOKE ALL ON TABLE offers FROM xmpp;
GRANT ALL ON TABLE offers TO xmpp;


--
-- Name: p0fs; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE p0fs FROM PUBLIC;
REVOKE ALL ON TABLE p0fs FROM xmpp;
GRANT ALL ON TABLE p0fs TO xmpp;


--
-- Name: virustotals; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE virustotals FROM PUBLIC;
REVOKE ALL ON TABLE virustotals FROM xmpp;
GRANT ALL ON TABLE virustotals TO xmpp;


--
-- Name: virustotalscans; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE virustotalscans FROM PUBLIC;
REVOKE ALL ON TABLE virustotalscans FROM xmpp;
GRANT ALL ON TABLE virustotalscans TO xmpp;


SET search_path = kippo, pg_catalog;

--
-- Name: auths; Type: ACL; Schema: kippo; Owner: -
--

REVOKE ALL ON TABLE auths FROM PUBLIC;
REVOKE ALL ON TABLE auths FROM xmpp;
GRANT ALL ON TABLE auths TO xmpp;


--
-- Name: clients; Type: ACL; Schema: kippo; Owner: -
--

REVOKE ALL ON TABLE clients FROM PUBLIC;
REVOKE ALL ON TABLE clients FROM xmpp;
GRANT ALL ON TABLE clients TO xmpp;


--
-- Name: inputs; Type: ACL; Schema: kippo; Owner: -
--

REVOKE ALL ON TABLE inputs FROM PUBLIC;
REVOKE ALL ON TABLE inputs FROM xmpp;
GRANT ALL ON TABLE inputs TO xmpp;


--
-- Name: sessions; Type: ACL; Schema: kippo; Owner: -
--

REVOKE ALL ON TABLE sessions FROM PUBLIC;
REVOKE ALL ON TABLE sessions FROM xmpp;
GRANT ALL ON TABLE sessions TO xmpp;


SET search_path = malware, pg_catalog;

--
-- Name: anubi; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE anubi FROM PUBLIC;
REVOKE ALL ON TABLE anubi FROM xmpp;
GRANT ALL ON TABLE anubi TO xmpp;


--
-- Name: cwsandboxs; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE cwsandboxs FROM PUBLIC;
REVOKE ALL ON TABLE cwsandboxs FROM xmpp;
GRANT ALL ON TABLE cwsandboxs TO xmpp;


--
-- Name: malwares; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE malwares FROM PUBLIC;
REVOKE ALL ON TABLE malwares FROM xmpp;
GRANT ALL ON TABLE malwares TO xmpp;


--
-- Name: normans; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE normans FROM PUBLIC;
REVOKE ALL ON TABLE normans FROM xmpp;
GRANT ALL ON TABLE normans TO xmpp;


--
-- Name: virustotals; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE virustotals FROM PUBLIC;
REVOKE ALL ON TABLE virustotals FROM xmpp;
GRANT ALL ON TABLE virustotals TO xmpp;


--
-- Name: virustotalscans; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE virustotalscans FROM PUBLIC;
REVOKE ALL ON TABLE virustotalscans FROM xmpp;
GRANT ALL ON TABLE virustotalscans TO xmpp;


--
-- PostgreSQL database dump complete
--

