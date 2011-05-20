--
-- PostgreSQL database dump
--

-- Started on 2011-01-22 17:18:04 CET

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;

--
-- TOC entry 7 (class 2615 OID 16774)
-- Name: dionaea; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA dionaea;


--
-- TOC entry 9 (class 2615 OID 78446)
-- Name: kippo; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA kippo;


--
-- TOC entry 6 (class 2615 OID 16776)
-- Name: malware; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA malware;


SET search_path = dionaea, pg_catalog;

--
-- TOC entry 305 (class 1247 OID 16778)
-- Dependencies: 7
-- Name: connection_transport; Type: TYPE; Schema: dionaea; Owner: -
--

CREATE TYPE connection_transport AS ENUM (
    'udp',
    'tcp',
    'tls'
);


--
-- TOC entry 307 (class 1247 OID 16783)
-- Dependencies: 7
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
-- TOC entry 309 (class 1247 OID 16789)
-- Dependencies: 8
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
-- TOC entry 1585 (class 1259 OID 16794)
-- Dependencies: 305 307 7
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
-- TOC entry 1586 (class 1259 OID 16800)
-- Dependencies: 7 1585
-- Name: connections_connection_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE connections_connection_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2066 (class 0 OID 0)
-- Dependencies: 1586
-- Name: connections_connection_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE connections_connection_seq OWNED BY connections.connection;


--
-- TOC entry 1587 (class 1259 OID 16802)
-- Dependencies: 7
-- Name: dcerpcbinds; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE dcerpcbinds (
    dcerpcbind bigint NOT NULL,
    connection bigint NOT NULL,
    dcerpcbind_uuid uuid NOT NULL,
    dcerpcbind_transfersyntax uuid NOT NULL
);


--
-- TOC entry 1588 (class 1259 OID 16805)
-- Dependencies: 1587 7
-- Name: dcerpcbinds_dcerpcbind_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcbinds_dcerpcbind_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2068 (class 0 OID 0)
-- Dependencies: 1588
-- Name: dcerpcbinds_dcerpcbind_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcbinds_dcerpcbind_seq OWNED BY dcerpcbinds.dcerpcbind;


--
-- TOC entry 1589 (class 1259 OID 16807)
-- Dependencies: 7
-- Name: dcerpcrequests; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE dcerpcrequests (
    dcerpcrequest bigint NOT NULL,
    connection bigint NOT NULL,
    dcerpcrequest_uuid uuid NOT NULL,
    dcerpcrequest_opnum smallint NOT NULL
);


--
-- TOC entry 1590 (class 1259 OID 16810)
-- Dependencies: 1589 7
-- Name: dcerpcrequests_dcerpcrequest_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcrequests_dcerpcrequest_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2070 (class 0 OID 0)
-- Dependencies: 1590
-- Name: dcerpcrequests_dcerpcrequest_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcrequests_dcerpcrequest_seq OWNED BY dcerpcrequests.dcerpcrequest;


--
-- TOC entry 1591 (class 1259 OID 16812)
-- Dependencies: 7
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
-- TOC entry 1592 (class 1259 OID 16815)
-- Dependencies: 7 1591
-- Name: dcerpcserviceops_dcerpcserviceop_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcserviceops_dcerpcserviceop_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2072 (class 0 OID 0)
-- Dependencies: 1592
-- Name: dcerpcserviceops_dcerpcserviceop_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcserviceops_dcerpcserviceop_seq OWNED BY dcerpcserviceops.dcerpcserviceop;


--
-- TOC entry 1593 (class 1259 OID 16817)
-- Dependencies: 7
-- Name: dcerpcservices; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE dcerpcservices (
    dcerpcservice integer NOT NULL,
    dcerpcservice_uuid uuid NOT NULL,
    dcerpcservice_name character varying(32) NOT NULL
);


--
-- TOC entry 1594 (class 1259 OID 16820)
-- Dependencies: 7 1593
-- Name: dcerpcservices_dcerpcservice_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcservices_dcerpcservice_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2074 (class 0 OID 0)
-- Dependencies: 1594
-- Name: dcerpcservices_dcerpcservice_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcservices_dcerpcservice_seq OWNED BY dcerpcservices.dcerpcservice;


--
-- TOC entry 1595 (class 1259 OID 16822)
-- Dependencies: 7
-- Name: downloads; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE downloads (
    download bigint NOT NULL,
    connection bigint NOT NULL,
    download_md5_hash character varying(32) NOT NULL,
    download_url character varying(256) NOT NULL
);


--
-- TOC entry 1596 (class 1259 OID 16825)
-- Dependencies: 7 1595
-- Name: downloads_download_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE downloads_download_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2076 (class 0 OID 0)
-- Dependencies: 1596
-- Name: downloads_download_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE downloads_download_seq OWNED BY downloads.download;


--
-- TOC entry 1597 (class 1259 OID 16827)
-- Dependencies: 7
-- Name: emu_profiles; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE emu_profiles (
    emu_profile bigint NOT NULL,
    connection bigint NOT NULL,
    emu_profile_json text NOT NULL
);


--
-- TOC entry 1598 (class 1259 OID 16833)
-- Dependencies: 1597 7
-- Name: emu_profiles_emu_profile_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE emu_profiles_emu_profile_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2078 (class 0 OID 0)
-- Dependencies: 1598
-- Name: emu_profiles_emu_profile_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE emu_profiles_emu_profile_seq OWNED BY emu_profiles.emu_profile;


--
-- TOC entry 1599 (class 1259 OID 16835)
-- Dependencies: 7
-- Name: emu_services; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE emu_services (
    emu_service bigint NOT NULL,
    connection bigint,
    emu_service_url character varying(64)
);


--
-- TOC entry 1600 (class 1259 OID 16838)
-- Dependencies: 7 1599
-- Name: emu_services_emu_service_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE emu_services_emu_service_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2080 (class 0 OID 0)
-- Dependencies: 1600
-- Name: emu_services_emu_service_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE emu_services_emu_service_seq OWNED BY emu_services.emu_service;


--
-- TOC entry 1601 (class 1259 OID 16840)
-- Dependencies: 7
-- Name: heatpoints; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE heatpoints (
    heatpoint integer NOT NULL,
    connection integer NOT NULL,
    lat real NOT NULL,
    lng real NOT NULL
);


--
-- TOC entry 1602 (class 1259 OID 16843)
-- Dependencies: 1601 7
-- Name: heatpoints_heatpoint_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE heatpoints_heatpoint_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2082 (class 0 OID 0)
-- Dependencies: 1602
-- Name: heatpoints_heatpoint_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE heatpoints_heatpoint_seq OWNED BY heatpoints.heatpoint;


--
-- TOC entry 1603 (class 1259 OID 16845)
-- Dependencies: 7
-- Name: logins; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE logins (
    login bigint NOT NULL,
    connection bigint,
    login_username character varying(64),
    login_password character varying(64)
);


--
-- TOC entry 1604 (class 1259 OID 16848)
-- Dependencies: 7 1603
-- Name: logins_login_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE logins_login_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2084 (class 0 OID 0)
-- Dependencies: 1604
-- Name: logins_login_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE logins_login_seq OWNED BY logins.login;


--
-- TOC entry 1605 (class 1259 OID 16850)
-- Dependencies: 7
-- Name: mssql_commands; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE mssql_commands (
    mssql_command bigint NOT NULL,
    connection bigint NOT NULL,
    mssql_command_status character varying(8) NOT NULL,
    mssql_command_cmd text NOT NULL
);


--
-- TOC entry 1606 (class 1259 OID 16856)
-- Dependencies: 7 1605
-- Name: mssql_commands_mssql_command_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE mssql_commands_mssql_command_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2086 (class 0 OID 0)
-- Dependencies: 1606
-- Name: mssql_commands_mssql_command_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE mssql_commands_mssql_command_seq OWNED BY mssql_commands.mssql_command;


--
-- TOC entry 1607 (class 1259 OID 16858)
-- Dependencies: 7
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
-- TOC entry 1608 (class 1259 OID 16861)
-- Dependencies: 7 1607
-- Name: mssql_fingerprints_mssql_fingerprint_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE mssql_fingerprints_mssql_fingerprint_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2088 (class 0 OID 0)
-- Dependencies: 1608
-- Name: mssql_fingerprints_mssql_fingerprint_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE mssql_fingerprints_mssql_fingerprint_seq OWNED BY mssql_fingerprints.mssql_fingerprint;


--
-- TOC entry 1609 (class 1259 OID 16863)
-- Dependencies: 7
-- Name: offers; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE offers (
    offer bigint NOT NULL,
    connection bigint NOT NULL,
    offer_url character varying(256) NOT NULL
);


--
-- TOC entry 1610 (class 1259 OID 16866)
-- Dependencies: 7 1609
-- Name: offers_offer_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE offers_offer_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2090 (class 0 OID 0)
-- Dependencies: 1610
-- Name: offers_offer_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE offers_offer_seq OWNED BY offers.offer;


--
-- TOC entry 1611 (class 1259 OID 16868)
-- Dependencies: 7
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
-- TOC entry 1612 (class 1259 OID 16871)
-- Dependencies: 1611 7
-- Name: p0fs_p0f_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE p0fs_p0f_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2092 (class 0 OID 0)
-- Dependencies: 1612
-- Name: p0fs_p0f_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE p0fs_p0f_seq OWNED BY p0fs.p0f;


--
-- TOC entry 1613 (class 1259 OID 16873)
-- Dependencies: 7
-- Name: virustotals; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE virustotals (
    virustotal integer NOT NULL,
    virustotal_md5_hash character(32) NOT NULL,
    virustotal_timestamp timestamp with time zone NOT NULL,
    virustotal_permalink character varying(128) NOT NULL
);


--
-- TOC entry 1614 (class 1259 OID 16876)
-- Dependencies: 7 1613
-- Name: virustotals_virustotal_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE virustotals_virustotal_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2094 (class 0 OID 0)
-- Dependencies: 1614
-- Name: virustotals_virustotal_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE virustotals_virustotal_seq OWNED BY virustotals.virustotal;


--
-- TOC entry 1615 (class 1259 OID 16878)
-- Dependencies: 7
-- Name: virustotalscans; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE virustotalscans (
    virustotalscan integer NOT NULL,
    virustotal integer NOT NULL,
    virustotalscan_scanner character varying(32) NOT NULL,
    virustotalscan_result text
);


--
-- TOC entry 1616 (class 1259 OID 16884)
-- Dependencies: 7 1615
-- Name: virustotalscans_virustotalscan_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE virustotalscans_virustotalscan_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2096 (class 0 OID 0)
-- Dependencies: 1616
-- Name: virustotalscans_virustotalscan_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE virustotalscans_virustotalscan_seq OWNED BY virustotalscans.virustotalscan;


SET search_path = kippo, pg_catalog;

--
-- TOC entry 1629 (class 1259 OID 78457)
-- Dependencies: 9
-- Name: asns_asn_seq; Type: SEQUENCE; Schema: kippo; Owner: -
--

CREATE SEQUENCE asns_asn_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1630 (class 1259 OID 78459)
-- Dependencies: 9
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
-- TOC entry 1631 (class 1259 OID 78462)
-- Dependencies: 1630 9
-- Name: auths_auth_seq; Type: SEQUENCE; Schema: kippo; Owner: -
--

CREATE SEQUENCE auths_auth_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2098 (class 0 OID 0)
-- Dependencies: 1631
-- Name: auths_auth_seq; Type: SEQUENCE OWNED BY; Schema: kippo; Owner: -
--

ALTER SEQUENCE auths_auth_seq OWNED BY auths.auth;


--
-- TOC entry 1632 (class 1259 OID 78464)
-- Dependencies: 9
-- Name: clients; Type: TABLE; Schema: kippo; Owner: -; Tablespace: 
--

CREATE TABLE clients (
    client integer NOT NULL,
    version character varying(128) NOT NULL,
    session integer NOT NULL
);


--
-- TOC entry 1633 (class 1259 OID 78467)
-- Dependencies: 1632 9
-- Name: clients_client_seq; Type: SEQUENCE; Schema: kippo; Owner: -
--

CREATE SEQUENCE clients_client_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2100 (class 0 OID 0)
-- Dependencies: 1633
-- Name: clients_client_seq; Type: SEQUENCE OWNED BY; Schema: kippo; Owner: -
--

ALTER SEQUENCE clients_client_seq OWNED BY clients.client;


--
-- TOC entry 1634 (class 1259 OID 78481)
-- Dependencies: 9
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
-- TOC entry 1635 (class 1259 OID 78487)
-- Dependencies: 9 1634
-- Name: inputs_input_seq; Type: SEQUENCE; Schema: kippo; Owner: -
--

CREATE SEQUENCE inputs_input_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2102 (class 0 OID 0)
-- Dependencies: 1635
-- Name: inputs_input_seq; Type: SEQUENCE OWNED BY; Schema: kippo; Owner: -
--

ALTER SEQUENCE inputs_input_seq OWNED BY inputs.input;


--
-- TOC entry 1636 (class 1259 OID 78489)
-- Dependencies: 9
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
-- TOC entry 1637 (class 1259 OID 78495)
-- Dependencies: 1636 9
-- Name: sessions_session_seq; Type: SEQUENCE; Schema: kippo; Owner: -
--

CREATE SEQUENCE sessions_session_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2104 (class 0 OID 0)
-- Dependencies: 1637
-- Name: sessions_session_seq; Type: SEQUENCE OWNED BY; Schema: kippo; Owner: -
--

ALTER SEQUENCE sessions_session_seq OWNED BY sessions.session;


SET search_path = malware, pg_catalog;

--
-- TOC entry 1617 (class 1259 OID 16912)
-- Dependencies: 1931 6
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
-- TOC entry 1618 (class 1259 OID 16919)
-- Dependencies: 1617 6
-- Name: anubi_anubis_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE anubi_anubis_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2106 (class 0 OID 0)
-- Dependencies: 1618
-- Name: anubi_anubis_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE anubi_anubis_seq OWNED BY anubi.anubis;


--
-- TOC entry 1619 (class 1259 OID 16921)
-- Dependencies: 1933 6
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
-- TOC entry 1620 (class 1259 OID 16928)
-- Dependencies: 1619 6
-- Name: cwsandboxs_cwsandbox_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE cwsandboxs_cwsandbox_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2108 (class 0 OID 0)
-- Dependencies: 1620
-- Name: cwsandboxs_cwsandbox_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE cwsandboxs_cwsandbox_seq OWNED BY cwsandboxs.cwsandbox;


--
-- TOC entry 1621 (class 1259 OID 16930)
-- Dependencies: 6
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
-- TOC entry 1622 (class 1259 OID 16933)
-- Dependencies: 6 1621
-- Name: malwares_malware_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE malwares_malware_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2110 (class 0 OID 0)
-- Dependencies: 1622
-- Name: malwares_malware_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE malwares_malware_seq OWNED BY malwares.malware;


--
-- TOC entry 1623 (class 1259 OID 16935)
-- Dependencies: 1936 6
-- Name: normans; Type: TABLE; Schema: malware; Owner: -; Tablespace: 
--

CREATE TABLE normans (
    norman integer NOT NULL,
    malware integer NOT NULL,
    txt text NOT NULL,
    "timestamp" timestamp with time zone DEFAULT '2009-10-21 12:14:25+02'::timestamp with time zone NOT NULL
);


--
-- TOC entry 1624 (class 1259 OID 16942)
-- Dependencies: 1623 6
-- Name: normans_norman_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE normans_norman_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2112 (class 0 OID 0)
-- Dependencies: 1624
-- Name: normans_norman_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE normans_norman_seq OWNED BY normans.norman;


--
-- TOC entry 1625 (class 1259 OID 16944)
-- Dependencies: 1939 6
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
-- TOC entry 1626 (class 1259 OID 16947)
-- Dependencies: 1625 6
-- Name: virustotals_virustotal_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE virustotals_virustotal_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2114 (class 0 OID 0)
-- Dependencies: 1626
-- Name: virustotals_virustotal_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE virustotals_virustotal_seq OWNED BY virustotals.virustotal;


--
-- TOC entry 1627 (class 1259 OID 16949)
-- Dependencies: 6
-- Name: virustotalscans; Type: TABLE; Schema: malware; Owner: -; Tablespace: 
--

CREATE TABLE virustotalscans (
    virustotalscan integer NOT NULL,
    virustotal integer NOT NULL,
    virustotalscan_scanner character varying(128) NOT NULL,
    virustotalscan_result character varying(256)
);


--
-- TOC entry 1628 (class 1259 OID 16952)
-- Dependencies: 1627 6
-- Name: virustotalscans_virustotalscan_seq; Type: SEQUENCE; Schema: malware; Owner: -
--

CREATE SEQUENCE virustotalscans_virustotalscan_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 2116 (class 0 OID 0)
-- Dependencies: 1628
-- Name: virustotalscans_virustotalscan_seq; Type: SEQUENCE OWNED BY; Schema: malware; Owner: -
--

ALTER SEQUENCE virustotalscans_virustotalscan_seq OWNED BY virustotalscans.virustotalscan;


SET search_path = dionaea, pg_catalog;

--
-- TOC entry 1915 (class 2604 OID 16954)
-- Dependencies: 1586 1585
-- Name: connection; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE connections ALTER COLUMN connection SET DEFAULT nextval('connections_connection_seq'::regclass);


--
-- TOC entry 1916 (class 2604 OID 16955)
-- Dependencies: 1588 1587
-- Name: dcerpcbind; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcbinds ALTER COLUMN dcerpcbind SET DEFAULT nextval('dcerpcbinds_dcerpcbind_seq'::regclass);


--
-- TOC entry 1917 (class 2604 OID 16956)
-- Dependencies: 1590 1589
-- Name: dcerpcrequest; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcrequests ALTER COLUMN dcerpcrequest SET DEFAULT nextval('dcerpcrequests_dcerpcrequest_seq'::regclass);


--
-- TOC entry 1918 (class 2604 OID 16957)
-- Dependencies: 1592 1591
-- Name: dcerpcserviceop; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcserviceops ALTER COLUMN dcerpcserviceop SET DEFAULT nextval('dcerpcserviceops_dcerpcserviceop_seq'::regclass);


--
-- TOC entry 1919 (class 2604 OID 16958)
-- Dependencies: 1594 1593
-- Name: dcerpcservice; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcservices ALTER COLUMN dcerpcservice SET DEFAULT nextval('dcerpcservices_dcerpcservice_seq'::regclass);


--
-- TOC entry 1920 (class 2604 OID 16959)
-- Dependencies: 1596 1595
-- Name: download; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE downloads ALTER COLUMN download SET DEFAULT nextval('downloads_download_seq'::regclass);


--
-- TOC entry 1921 (class 2604 OID 16960)
-- Dependencies: 1598 1597
-- Name: emu_profile; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE emu_profiles ALTER COLUMN emu_profile SET DEFAULT nextval('emu_profiles_emu_profile_seq'::regclass);


--
-- TOC entry 1922 (class 2604 OID 16961)
-- Dependencies: 1600 1599
-- Name: emu_service; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE emu_services ALTER COLUMN emu_service SET DEFAULT nextval('emu_services_emu_service_seq'::regclass);


--
-- TOC entry 1923 (class 2604 OID 16962)
-- Dependencies: 1602 1601
-- Name: heatpoint; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE heatpoints ALTER COLUMN heatpoint SET DEFAULT nextval('heatpoints_heatpoint_seq'::regclass);


--
-- TOC entry 1924 (class 2604 OID 16963)
-- Dependencies: 1604 1603
-- Name: login; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE logins ALTER COLUMN login SET DEFAULT nextval('logins_login_seq'::regclass);


--
-- TOC entry 1925 (class 2604 OID 16964)
-- Dependencies: 1606 1605
-- Name: mssql_command; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE mssql_commands ALTER COLUMN mssql_command SET DEFAULT nextval('mssql_commands_mssql_command_seq'::regclass);


--
-- TOC entry 1926 (class 2604 OID 16965)
-- Dependencies: 1608 1607
-- Name: mssql_fingerprint; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE mssql_fingerprints ALTER COLUMN mssql_fingerprint SET DEFAULT nextval('mssql_fingerprints_mssql_fingerprint_seq'::regclass);


--
-- TOC entry 1927 (class 2604 OID 16966)
-- Dependencies: 1610 1609
-- Name: offer; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE offers ALTER COLUMN offer SET DEFAULT nextval('offers_offer_seq'::regclass);


--
-- TOC entry 1928 (class 2604 OID 16967)
-- Dependencies: 1612 1611
-- Name: p0f; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE p0fs ALTER COLUMN p0f SET DEFAULT nextval('p0fs_p0f_seq'::regclass);


--
-- TOC entry 1929 (class 2604 OID 16968)
-- Dependencies: 1614 1613
-- Name: virustotal; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE virustotals ALTER COLUMN virustotal SET DEFAULT nextval('virustotals_virustotal_seq'::regclass);


--
-- TOC entry 1930 (class 2604 OID 16969)
-- Dependencies: 1616 1615
-- Name: virustotalscan; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE virustotalscans ALTER COLUMN virustotalscan SET DEFAULT nextval('virustotalscans_virustotalscan_seq'::regclass);


SET search_path = kippo, pg_catalog;

--
-- TOC entry 1941 (class 2604 OID 78497)
-- Dependencies: 1631 1630
-- Name: auth; Type: DEFAULT; Schema: kippo; Owner: -
--

ALTER TABLE auths ALTER COLUMN auth SET DEFAULT nextval('auths_auth_seq'::regclass);


--
-- TOC entry 1942 (class 2604 OID 78498)
-- Dependencies: 1633 1632
-- Name: client; Type: DEFAULT; Schema: kippo; Owner: -
--

ALTER TABLE clients ALTER COLUMN client SET DEFAULT nextval('clients_client_seq'::regclass);


--
-- TOC entry 1943 (class 2604 OID 78499)
-- Dependencies: 1635 1634
-- Name: input; Type: DEFAULT; Schema: kippo; Owner: -
--

ALTER TABLE inputs ALTER COLUMN input SET DEFAULT nextval('inputs_input_seq'::regclass);


--
-- TOC entry 1944 (class 2604 OID 78500)
-- Dependencies: 1637 1636
-- Name: session; Type: DEFAULT; Schema: kippo; Owner: -
--

ALTER TABLE sessions ALTER COLUMN session SET DEFAULT nextval('sessions_session_seq'::regclass);


SET search_path = malware, pg_catalog;

--
-- TOC entry 1932 (class 2604 OID 16974)
-- Dependencies: 1618 1617
-- Name: anubis; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE anubi ALTER COLUMN anubis SET DEFAULT nextval('anubi_anubis_seq'::regclass);


--
-- TOC entry 1934 (class 2604 OID 16975)
-- Dependencies: 1620 1619
-- Name: cwsandbox; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE cwsandboxs ALTER COLUMN cwsandbox SET DEFAULT nextval('cwsandboxs_cwsandbox_seq'::regclass);


--
-- TOC entry 1935 (class 2604 OID 16976)
-- Dependencies: 1622 1621
-- Name: malware; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE malwares ALTER COLUMN malware SET DEFAULT nextval('malwares_malware_seq'::regclass);


--
-- TOC entry 1937 (class 2604 OID 16977)
-- Dependencies: 1624 1623
-- Name: norman; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE normans ALTER COLUMN norman SET DEFAULT nextval('normans_norman_seq'::regclass);


--
-- TOC entry 1938 (class 2604 OID 16978)
-- Dependencies: 1626 1625
-- Name: virustotal; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE virustotals ALTER COLUMN virustotal SET DEFAULT nextval('virustotals_virustotal_seq'::regclass);


--
-- TOC entry 1940 (class 2604 OID 16979)
-- Dependencies: 1628 1627
-- Name: virustotalscan; Type: DEFAULT; Schema: malware; Owner: -
--

ALTER TABLE virustotalscans ALTER COLUMN virustotalscan SET DEFAULT nextval('virustotalscans_virustotalscan_seq'::regclass);


SET search_path = dionaea, pg_catalog;

--
-- TOC entry 1946 (class 2606 OID 46116)
-- Dependencies: 1585 1585
-- Name: connections_connection_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY connections
    ADD CONSTRAINT connections_connection_pkey PRIMARY KEY (connection);


--
-- TOC entry 1956 (class 2606 OID 29496)
-- Dependencies: 1587 1587
-- Name: dcerpcbinds_dcerpcbind_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcbinds
    ADD CONSTRAINT dcerpcbinds_dcerpcbind_pkey PRIMARY KEY (dcerpcbind);


--
-- TOC entry 1962 (class 2606 OID 33070)
-- Dependencies: 1589 1589
-- Name: dcerpcrequests_dcerpcrequest_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcrequests
    ADD CONSTRAINT dcerpcrequests_dcerpcrequest_pkey PRIMARY KEY (dcerpcrequest);


--
-- TOC entry 1967 (class 2606 OID 35556)
-- Dependencies: 1591 1591
-- Name: dcerpcserviceops_dcerpcserviceop_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcserviceops
    ADD CONSTRAINT dcerpcserviceops_dcerpcserviceop_pkey PRIMARY KEY (dcerpcserviceop);


--
-- TOC entry 1969 (class 2606 OID 35835)
-- Dependencies: 1593 1593
-- Name: dcerpcservices_dcerpcservice_uuid_uniq; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcservices
    ADD CONSTRAINT dcerpcservices_dcerpcservice_uuid_uniq UNIQUE (dcerpcservice_uuid);


--
-- TOC entry 1971 (class 2606 OID 35913)
-- Dependencies: 1593 1593
-- Name: dcerpcservices_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcservices
    ADD CONSTRAINT dcerpcservices_pkey PRIMARY KEY (dcerpcservice);


--
-- TOC entry 1974 (class 2606 OID 36009)
-- Dependencies: 1595 1595
-- Name: downloads_download_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY downloads
    ADD CONSTRAINT downloads_download_pkey PRIMARY KEY (download);


--
-- TOC entry 1979 (class 2606 OID 36845)
-- Dependencies: 1597 1597
-- Name: emu_profiles_emu_profile_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY emu_profiles
    ADD CONSTRAINT emu_profiles_emu_profile_pkey PRIMARY KEY (emu_profile);


--
-- TOC entry 1982 (class 2606 OID 38860)
-- Dependencies: 1599 1599
-- Name: emu_services_emu_service_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY emu_services
    ADD CONSTRAINT emu_services_emu_service_pkey PRIMARY KEY (emu_service);


--
-- TOC entry 1986 (class 2606 OID 38921)
-- Dependencies: 1601 1601
-- Name: heatpoints_heatpoint_pk; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY heatpoints
    ADD CONSTRAINT heatpoints_heatpoint_pk PRIMARY KEY (heatpoint);


--
-- TOC entry 1991 (class 2606 OID 46139)
-- Dependencies: 1603 1603
-- Name: logins_login_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY logins
    ADD CONSTRAINT logins_login_pkey PRIMARY KEY (login);


--
-- TOC entry 1994 (class 2606 OID 46251)
-- Dependencies: 1605 1605
-- Name: mssql_commands_mssql_command_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY mssql_commands
    ADD CONSTRAINT mssql_commands_mssql_command_pkey PRIMARY KEY (mssql_command);


--
-- TOC entry 1997 (class 2606 OID 46384)
-- Dependencies: 1607 1607
-- Name: mssql_fingerprints_mssql_fingerprint_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY mssql_fingerprints
    ADD CONSTRAINT mssql_fingerprints_mssql_fingerprint_pkey PRIMARY KEY (mssql_fingerprint);


--
-- TOC entry 2001 (class 2606 OID 46533)
-- Dependencies: 1609 1609
-- Name: offers_offer_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY offers
    ADD CONSTRAINT offers_offer_pkey PRIMARY KEY (offer);


--
-- TOC entry 2008 (class 2606 OID 47827)
-- Dependencies: 1611 1611
-- Name: p0fs_p0f_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY p0fs
    ADD CONSTRAINT p0fs_p0f_pkey PRIMARY KEY (p0f);


--
-- TOC entry 2011 (class 2606 OID 47830)
-- Dependencies: 1613 1613
-- Name: virustotals_virustotal_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY virustotals
    ADD CONSTRAINT virustotals_virustotal_pkey PRIMARY KEY (virustotal);


--
-- TOC entry 2014 (class 2606 OID 47838)
-- Dependencies: 1615 1615
-- Name: virustotalscans_virustotalscan_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY virustotalscans
    ADD CONSTRAINT virustotalscans_virustotalscan_pkey PRIMARY KEY (virustotalscan);


SET search_path = kippo, pg_catalog;

--
-- TOC entry 2033 (class 2606 OID 78504)
-- Dependencies: 1630 1630
-- Name: auths_pkey; Type: CONSTRAINT; Schema: kippo; Owner: -; Tablespace: 
--

ALTER TABLE ONLY auths
    ADD CONSTRAINT auths_pkey PRIMARY KEY (auth);


--
-- TOC entry 2035 (class 2606 OID 78506)
-- Dependencies: 1632 1632
-- Name: clients_pkey; Type: CONSTRAINT; Schema: kippo; Owner: -; Tablespace: 
--

ALTER TABLE ONLY clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (client);


--
-- TOC entry 2037 (class 2606 OID 78510)
-- Dependencies: 1634 1634
-- Name: inputs_pkey; Type: CONSTRAINT; Schema: kippo; Owner: -; Tablespace: 
--

ALTER TABLE ONLY inputs
    ADD CONSTRAINT inputs_pkey PRIMARY KEY (input);


--
-- TOC entry 2039 (class 2606 OID 78512)
-- Dependencies: 1636 1636
-- Name: sessions_pkey; Type: CONSTRAINT; Schema: kippo; Owner: -; Tablespace: 
--

ALTER TABLE ONLY sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (session);


SET search_path = malware, pg_catalog;

--
-- TOC entry 2017 (class 2606 OID 78400)
-- Dependencies: 1617 1617
-- Name: anubi_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY anubi
    ADD CONSTRAINT anubi_pkey PRIMARY KEY (anubis);


--
-- TOC entry 2019 (class 2606 OID 50080)
-- Dependencies: 1619 1619
-- Name: cwsandbox_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY cwsandboxs
    ADD CONSTRAINT cwsandbox_pkey PRIMARY KEY (cwsandbox);


--
-- TOC entry 2022 (class 2606 OID 48141)
-- Dependencies: 1621 1621
-- Name: malware_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY malwares
    ADD CONSTRAINT malware_pkey PRIMARY KEY (malware);


--
-- TOC entry 2025 (class 2606 OID 48604)
-- Dependencies: 1623 1623
-- Name: norman_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY normans
    ADD CONSTRAINT norman_pkey PRIMARY KEY (norman);


--
-- TOC entry 2028 (class 2606 OID 48826)
-- Dependencies: 1625 1625
-- Name: virustotals_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY virustotals
    ADD CONSTRAINT virustotals_pkey PRIMARY KEY (virustotal);


--
-- TOC entry 2030 (class 2606 OID 49107)
-- Dependencies: 1627 1627
-- Name: virustotalscans_pkey; Type: CONSTRAINT; Schema: malware; Owner: -; Tablespace: 
--

ALTER TABLE ONLY virustotalscans
    ADD CONSTRAINT virustotalscans_pkey PRIMARY KEY (virustotalscan);


SET search_path = dionaea, pg_catalog;

--
-- TOC entry 1947 (class 1259 OID 51121)
-- Dependencies: 1585
-- Name: connections_local_host_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_local_host_idx ON connections USING btree (local_host);


--
-- TOC entry 1948 (class 1259 OID 60417)
-- Dependencies: 1585
-- Name: connections_local_port_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_local_port_idx ON connections USING btree (local_port);


--
-- TOC entry 1949 (class 1259 OID 60416)
-- Dependencies: 1585
-- Name: connections_parent_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_parent_idx ON connections USING btree (connection_parent);


--
-- TOC entry 1950 (class 1259 OID 60418)
-- Dependencies: 1585
-- Name: connections_remote_host_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_remote_host_idx ON connections USING btree (remote_host);


--
-- TOC entry 1951 (class 1259 OID 63336)
-- Dependencies: 1585
-- Name: connections_root_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_root_idx ON connections USING btree (connection_root);


--
-- TOC entry 1952 (class 1259 OID 64538)
-- Dependencies: 1585
-- Name: connections_timestamp_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_timestamp_idx ON connections USING btree (connection_timestamp);


--
-- TOC entry 1953 (class 1259 OID 64690)
-- Dependencies: 1585
-- Name: connections_type_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_type_idx ON connections USING btree (connection_type);


--
-- TOC entry 1954 (class 1259 OID 50081)
-- Dependencies: 1587
-- Name: dcerpcbinds_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_connection_idx ON dcerpcbinds USING btree (connection);


--
-- TOC entry 1957 (class 1259 OID 50129)
-- Dependencies: 1587
-- Name: dcerpcbinds_transfersyntax_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_transfersyntax_idx ON dcerpcbinds USING btree (dcerpcbind_transfersyntax);


--
-- TOC entry 1958 (class 1259 OID 51120)
-- Dependencies: 1587
-- Name: dcerpcbinds_uuid_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_uuid_idx ON dcerpcbinds USING btree (dcerpcbind_uuid);


--
-- TOC entry 1960 (class 1259 OID 66354)
-- Dependencies: 1589
-- Name: dcerpcrequests_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_connection_idx ON dcerpcrequests USING btree (connection);


--
-- TOC entry 1963 (class 1259 OID 67134)
-- Dependencies: 1589
-- Name: dcerpcrequests_opnum_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_opnum_idx ON dcerpcrequests USING btree (dcerpcrequest_opnum);


--
-- TOC entry 1964 (class 1259 OID 67170)
-- Dependencies: 1589
-- Name: dcerpcrequests_uuid_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_uuid_idx ON dcerpcrequests USING btree (dcerpcrequest_uuid);


--
-- TOC entry 1972 (class 1259 OID 67893)
-- Dependencies: 1595
-- Name: downloads_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_connection_idx ON downloads USING btree (connection);


--
-- TOC entry 1975 (class 1259 OID 67927)
-- Dependencies: 1595
-- Name: downloads_md5_hash_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_md5_hash_idx ON downloads USING btree (download_md5_hash);


--
-- TOC entry 1976 (class 1259 OID 68282)
-- Dependencies: 1595
-- Name: downloads_url_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_url_idx ON downloads USING btree (download_url);


--
-- TOC entry 1959 (class 1259 OID 68381)
-- Dependencies: 1587
-- Name: fki_dcerpcbinds_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_dcerpcbinds_connection_fkey ON dcerpcbinds USING btree (connection);


--
-- TOC entry 1965 (class 1259 OID 69172)
-- Dependencies: 1589
-- Name: fki_dcerpcrequests_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_dcerpcrequests_connection_fkey ON dcerpcrequests USING btree (connection);


--
-- TOC entry 1977 (class 1259 OID 69458)
-- Dependencies: 1595
-- Name: fki_downloads_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_downloads_connection_fkey ON downloads USING btree (connection);


--
-- TOC entry 1980 (class 1259 OID 69712)
-- Dependencies: 1597
-- Name: fki_emu_profiles_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_emu_profiles_connection_fkey ON emu_profiles USING btree (connection);


--
-- TOC entry 1983 (class 1259 OID 69782)
-- Dependencies: 1599
-- Name: fki_emu_services_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_emu_services_connection_fkey ON emu_services USING btree (connection);


--
-- TOC entry 1989 (class 1259 OID 69815)
-- Dependencies: 1603
-- Name: fki_logins_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_logins_connection_fkey ON logins USING btree (connection);


--
-- TOC entry 1992 (class 1259 OID 69829)
-- Dependencies: 1605
-- Name: fki_mssql_commands_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_mssql_commands_connection_fkey ON mssql_commands USING btree (connection);


--
-- TOC entry 1995 (class 1259 OID 69837)
-- Dependencies: 1607
-- Name: fki_mssql_fingerprints_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_mssql_fingerprints_connection_fkey ON mssql_fingerprints USING btree (connection);


--
-- TOC entry 1998 (class 1259 OID 70088)
-- Dependencies: 1609
-- Name: fki_offers_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_offers_connection_fkey ON offers USING btree (connection);


--
-- TOC entry 2003 (class 1259 OID 69850)
-- Dependencies: 1611
-- Name: fki_p0fs_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_p0fs_connection_fkey ON p0fs USING btree (connection);


--
-- TOC entry 2012 (class 1259 OID 69860)
-- Dependencies: 1615
-- Name: fki_virustotalscans_virustotal_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_virustotalscans_virustotal_fkey ON virustotalscans USING btree (virustotal);


--
-- TOC entry 1984 (class 1259 OID 70105)
-- Dependencies: 1601
-- Name: heatpoints_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX heatpoints_connection_idx ON heatpoints USING btree (connection);


--
-- TOC entry 1987 (class 1259 OID 70106)
-- Dependencies: 1601
-- Name: heatpoints_lat_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX heatpoints_lat_idx ON heatpoints USING btree (lat);


--
-- TOC entry 1988 (class 1259 OID 70302)
-- Dependencies: 1601
-- Name: heatpoints_lng_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX heatpoints_lng_idx ON heatpoints USING btree (lng);


--
-- TOC entry 1999 (class 1259 OID 70667)
-- Dependencies: 1609
-- Name: offers_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX offers_connection_idx ON offers USING btree (connection);


--
-- TOC entry 2002 (class 1259 OID 70889)
-- Dependencies: 1609
-- Name: offers_url_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX offers_url_idx ON offers USING btree (offer_url);


--
-- TOC entry 2004 (class 1259 OID 71505)
-- Dependencies: 1611
-- Name: p0fs_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_connection_idx ON p0fs USING btree (connection);


--
-- TOC entry 2005 (class 1259 OID 71569)
-- Dependencies: 1611
-- Name: p0fs_detail_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_detail_idx ON p0fs USING btree (p0f_detail);


--
-- TOC entry 2006 (class 1259 OID 71580)
-- Dependencies: 1611
-- Name: p0fs_genre_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_genre_idx ON p0fs USING btree (p0f_genre);


--
-- TOC entry 2009 (class 1259 OID 71591)
-- Dependencies: 1611
-- Name: p0fs_uptime_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_uptime_idx ON p0fs USING btree (p0f_uptime);


SET search_path = malware, pg_catalog;

--
-- TOC entry 2015 (class 1259 OID 78401)
-- Dependencies: 1617
-- Name: anubi_malware_idx; Type: INDEX; Schema: malware; Owner: -; Tablespace: 
--

CREATE INDEX anubi_malware_idx ON anubi USING btree (malware);


--
-- TOC entry 2020 (class 1259 OID 71847)
-- Dependencies: 1619
-- Name: cwsandboxs_malware_idx; Type: INDEX; Schema: malware; Owner: -; Tablespace: 
--

CREATE INDEX cwsandboxs_malware_idx ON cwsandboxs USING btree (malware);


--
-- TOC entry 2023 (class 1259 OID 71909)
-- Dependencies: 1621
-- Name: malwares_malware_m5_idx; Type: INDEX; Schema: malware; Owner: -; Tablespace: 
--

CREATE INDEX malwares_malware_m5_idx ON malwares USING btree (malware_md5);


--
-- TOC entry 2026 (class 1259 OID 72205)
-- Dependencies: 1623
-- Name: normans_malware_idx; Type: INDEX; Schema: malware; Owner: -; Tablespace: 
--

CREATE INDEX normans_malware_idx ON normans USING btree (malware);


--
-- TOC entry 2031 (class 1259 OID 72279)
-- Dependencies: 1627
-- Name: virustotalscans_virustotal_idx; Type: INDEX; Schema: malware; Owner: -; Tablespace: 
--

CREATE INDEX virustotalscans_virustotal_idx ON virustotalscans USING btree (virustotal);


SET search_path = dionaea, pg_catalog;

--
-- TOC entry 2040 (class 2606 OID 72422)
-- Dependencies: 1585 1587 1945
-- Name: dcerpcbinds_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY dcerpcbinds
    ADD CONSTRAINT dcerpcbinds_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 2041 (class 2606 OID 73178)
-- Dependencies: 1945 1585 1589
-- Name: dcerpcrequests_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY dcerpcrequests
    ADD CONSTRAINT dcerpcrequests_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 2042 (class 2606 OID 73934)
-- Dependencies: 1595 1945 1585
-- Name: downloads_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY downloads
    ADD CONSTRAINT downloads_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 2043 (class 2606 OID 74937)
-- Dependencies: 1945 1585 1597
-- Name: emu_profiles_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY emu_profiles
    ADD CONSTRAINT emu_profiles_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 2044 (class 2606 OID 75435)
-- Dependencies: 1945 1585 1599
-- Name: emu_services_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY emu_services
    ADD CONSTRAINT emu_services_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 2045 (class 2606 OID 75606)
-- Dependencies: 1945 1585 1601
-- Name: heatpoints_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY heatpoints
    ADD CONSTRAINT heatpoints_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection);


--
-- TOC entry 2046 (class 2606 OID 76483)
-- Dependencies: 1945 1585 1603
-- Name: logins_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY logins
    ADD CONSTRAINT logins_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 2047 (class 2606 OID 76488)
-- Dependencies: 1585 1605 1945
-- Name: mssql_commands_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY mssql_commands
    ADD CONSTRAINT mssql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 2048 (class 2606 OID 76495)
-- Dependencies: 1585 1607 1945
-- Name: mssql_fingerprints_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY mssql_fingerprints
    ADD CONSTRAINT mssql_fingerprints_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 2049 (class 2606 OID 76501)
-- Dependencies: 1585 1945 1609
-- Name: offers_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY offers
    ADD CONSTRAINT offers_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 2050 (class 2606 OID 76937)
-- Dependencies: 1611 1585 1945
-- Name: p0fs_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY p0fs
    ADD CONSTRAINT p0fs_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 2051 (class 2606 OID 72943)
-- Dependencies: 1613 2010 1615
-- Name: virustotalscans_virustotal_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY virustotalscans
    ADD CONSTRAINT virustotalscans_virustotal_fkey FOREIGN KEY (virustotal) REFERENCES virustotals(virustotal) ON UPDATE RESTRICT ON DELETE CASCADE;


SET search_path = malware, pg_catalog;

--
-- TOC entry 2052 (class 2606 OID 78402)
-- Dependencies: 1621 1617 2021
-- Name: anubi_malware_fkey; Type: FK CONSTRAINT; Schema: malware; Owner: -
--

ALTER TABLE ONLY anubi
    ADD CONSTRAINT anubi_malware_fkey FOREIGN KEY (malware) REFERENCES malwares(malware);


--
-- TOC entry 2053 (class 2606 OID 72954)
-- Dependencies: 2021 1619 1621
-- Name: cwsandbox_malware_fkey; Type: FK CONSTRAINT; Schema: malware; Owner: -
--

ALTER TABLE ONLY cwsandboxs
    ADD CONSTRAINT cwsandbox_malware_fkey FOREIGN KEY (malware) REFERENCES malwares(malware);


--
-- TOC entry 2054 (class 2606 OID 72959)
-- Dependencies: 1623 2021 1621
-- Name: norman_malware_fkey; Type: FK CONSTRAINT; Schema: malware; Owner: -
--

ALTER TABLE ONLY normans
    ADD CONSTRAINT norman_malware_fkey FOREIGN KEY (malware) REFERENCES malwares(malware);


--
-- TOC entry 2055 (class 2606 OID 73096)
-- Dependencies: 2021 1621 1625
-- Name: virustotals_malware_fkey; Type: FK CONSTRAINT; Schema: malware; Owner: -
--

ALTER TABLE ONLY virustotals
    ADD CONSTRAINT virustotals_malware_fkey FOREIGN KEY (malware) REFERENCES malwares(malware);


--
-- TOC entry 2056 (class 2606 OID 73120)
-- Dependencies: 1627 2027 1625
-- Name: virustotalscans_virustotal_fkey; Type: FK CONSTRAINT; Schema: malware; Owner: -
--

ALTER TABLE ONLY virustotalscans
    ADD CONSTRAINT virustotalscans_virustotal_fkey FOREIGN KEY (virustotal) REFERENCES virustotals(virustotal);


--
-- TOC entry 2060 (class 0 OID 0)
-- Dependencies: 7
-- Name: dionaea; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA dionaea FROM PUBLIC;
REVOKE ALL ON SCHEMA dionaea FROM xmpp;
GRANT ALL ON SCHEMA dionaea TO xmpp;
GRANT USAGE ON SCHEMA dionaea TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2061 (class 0 OID 0)
-- Dependencies: 9
-- Name: kippo; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA kippo FROM PUBLIC;
REVOKE ALL ON SCHEMA kippo FROM xmpp;
GRANT ALL ON SCHEMA kippo TO xmpp;
GRANT USAGE ON SCHEMA kippo TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2062 (class 0 OID 0)
-- Dependencies: 6
-- Name: malware; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA malware FROM PUBLIC;
REVOKE ALL ON SCHEMA malware FROM xmpp;
GRANT ALL ON SCHEMA malware TO xmpp;
GRANT USAGE ON SCHEMA malware TO xmpp_read;


--
-- TOC entry 2064 (class 0 OID 0)
-- Dependencies: 8
-- Name: public; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


SET search_path = dionaea, pg_catalog;

--
-- TOC entry 2065 (class 0 OID 0)
-- Dependencies: 1585
-- Name: connections; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE connections FROM PUBLIC;
REVOKE ALL ON TABLE connections FROM xmpp;
GRANT ALL ON TABLE connections TO xmpp;
GRANT SELECT ON TABLE connections TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2067 (class 0 OID 0)
-- Dependencies: 1587
-- Name: dcerpcbinds; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE dcerpcbinds FROM PUBLIC;
REVOKE ALL ON TABLE dcerpcbinds FROM xmpp;
GRANT ALL ON TABLE dcerpcbinds TO xmpp;
GRANT SELECT ON TABLE dcerpcbinds TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2069 (class 0 OID 0)
-- Dependencies: 1589
-- Name: dcerpcrequests; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE dcerpcrequests FROM PUBLIC;
REVOKE ALL ON TABLE dcerpcrequests FROM xmpp;
GRANT ALL ON TABLE dcerpcrequests TO xmpp;
GRANT SELECT ON TABLE dcerpcrequests TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2071 (class 0 OID 0)
-- Dependencies: 1591
-- Name: dcerpcserviceops; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE dcerpcserviceops FROM PUBLIC;
REVOKE ALL ON TABLE dcerpcserviceops FROM xmpp;
GRANT ALL ON TABLE dcerpcserviceops TO xmpp;
GRANT SELECT ON TABLE dcerpcserviceops TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2073 (class 0 OID 0)
-- Dependencies: 1593
-- Name: dcerpcservices; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE dcerpcservices FROM PUBLIC;
REVOKE ALL ON TABLE dcerpcservices FROM xmpp;
GRANT ALL ON TABLE dcerpcservices TO xmpp;
GRANT SELECT ON TABLE dcerpcservices TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2075 (class 0 OID 0)
-- Dependencies: 1595
-- Name: downloads; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE downloads FROM PUBLIC;
REVOKE ALL ON TABLE downloads FROM xmpp;
GRANT ALL ON TABLE downloads TO xmpp;
GRANT SELECT ON TABLE downloads TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2077 (class 0 OID 0)
-- Dependencies: 1597
-- Name: emu_profiles; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE emu_profiles FROM PUBLIC;
REVOKE ALL ON TABLE emu_profiles FROM xmpp;
GRANT ALL ON TABLE emu_profiles TO xmpp;
GRANT SELECT ON TABLE emu_profiles TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2079 (class 0 OID 0)
-- Dependencies: 1599
-- Name: emu_services; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE emu_services FROM PUBLIC;
REVOKE ALL ON TABLE emu_services FROM xmpp;
GRANT ALL ON TABLE emu_services TO xmpp;
GRANT SELECT ON TABLE emu_services TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2081 (class 0 OID 0)
-- Dependencies: 1601
-- Name: heatpoints; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE heatpoints FROM PUBLIC;
REVOKE ALL ON TABLE heatpoints FROM xmpp;
GRANT ALL ON TABLE heatpoints TO xmpp;
GRANT SELECT ON TABLE heatpoints TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2083 (class 0 OID 0)
-- Dependencies: 1603
-- Name: logins; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE logins FROM PUBLIC;
REVOKE ALL ON TABLE logins FROM xmpp;
GRANT ALL ON TABLE logins TO xmpp;
GRANT SELECT ON TABLE logins TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2085 (class 0 OID 0)
-- Dependencies: 1605
-- Name: mssql_commands; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE mssql_commands FROM PUBLIC;
REVOKE ALL ON TABLE mssql_commands FROM xmpp;
GRANT ALL ON TABLE mssql_commands TO xmpp;
GRANT SELECT ON TABLE mssql_commands TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2087 (class 0 OID 0)
-- Dependencies: 1607
-- Name: mssql_fingerprints; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE mssql_fingerprints FROM PUBLIC;
REVOKE ALL ON TABLE mssql_fingerprints FROM xmpp;
GRANT ALL ON TABLE mssql_fingerprints TO xmpp;
GRANT SELECT ON TABLE mssql_fingerprints TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2089 (class 0 OID 0)
-- Dependencies: 1609
-- Name: offers; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE offers FROM PUBLIC;
REVOKE ALL ON TABLE offers FROM xmpp;
GRANT ALL ON TABLE offers TO xmpp;
GRANT SELECT ON TABLE offers TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2091 (class 0 OID 0)
-- Dependencies: 1611
-- Name: p0fs; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE p0fs FROM PUBLIC;
REVOKE ALL ON TABLE p0fs FROM xmpp;
GRANT ALL ON TABLE p0fs TO xmpp;
GRANT SELECT ON TABLE p0fs TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2093 (class 0 OID 0)
-- Dependencies: 1613
-- Name: virustotals; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE virustotals FROM PUBLIC;
REVOKE ALL ON TABLE virustotals FROM xmpp;
GRANT ALL ON TABLE virustotals TO xmpp;
GRANT SELECT ON TABLE virustotals TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2095 (class 0 OID 0)
-- Dependencies: 1615
-- Name: virustotalscans; Type: ACL; Schema: dionaea; Owner: -
--

REVOKE ALL ON TABLE virustotalscans FROM PUBLIC;
REVOKE ALL ON TABLE virustotalscans FROM xmpp;
GRANT ALL ON TABLE virustotalscans TO xmpp;
GRANT SELECT ON TABLE virustotalscans TO xmpp_read WITH GRANT OPTION;


SET search_path = kippo, pg_catalog;

--
-- TOC entry 2097 (class 0 OID 0)
-- Dependencies: 1630
-- Name: auths; Type: ACL; Schema: kippo; Owner: -
--

REVOKE ALL ON TABLE auths FROM PUBLIC;
REVOKE ALL ON TABLE auths FROM xmpp;
GRANT ALL ON TABLE auths TO xmpp;
GRANT SELECT ON TABLE auths TO xmpp_read;


--
-- TOC entry 2099 (class 0 OID 0)
-- Dependencies: 1632
-- Name: clients; Type: ACL; Schema: kippo; Owner: -
--

REVOKE ALL ON TABLE clients FROM PUBLIC;
REVOKE ALL ON TABLE clients FROM xmpp;
GRANT ALL ON TABLE clients TO xmpp;
GRANT SELECT ON TABLE clients TO xmpp_read;


--
-- TOC entry 2101 (class 0 OID 0)
-- Dependencies: 1634
-- Name: inputs; Type: ACL; Schema: kippo; Owner: -
--

REVOKE ALL ON TABLE inputs FROM PUBLIC;
REVOKE ALL ON TABLE inputs FROM xmpp;
GRANT ALL ON TABLE inputs TO xmpp;
GRANT SELECT ON TABLE inputs TO xmpp_read;


--
-- TOC entry 2103 (class 0 OID 0)
-- Dependencies: 1636
-- Name: sessions; Type: ACL; Schema: kippo; Owner: -
--

REVOKE ALL ON TABLE sessions FROM PUBLIC;
REVOKE ALL ON TABLE sessions FROM xmpp;
GRANT ALL ON TABLE sessions TO xmpp;
GRANT SELECT ON TABLE sessions TO xmpp_read;


SET search_path = malware, pg_catalog;

--
-- TOC entry 2105 (class 0 OID 0)
-- Dependencies: 1617
-- Name: anubi; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE anubi FROM PUBLIC;
REVOKE ALL ON TABLE anubi FROM xmpp;
GRANT ALL ON TABLE anubi TO xmpp;
GRANT SELECT ON TABLE anubi TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2107 (class 0 OID 0)
-- Dependencies: 1619
-- Name: cwsandboxs; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE cwsandboxs FROM PUBLIC;
REVOKE ALL ON TABLE cwsandboxs FROM xmpp;
GRANT ALL ON TABLE cwsandboxs TO xmpp;
GRANT SELECT ON TABLE cwsandboxs TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2109 (class 0 OID 0)
-- Dependencies: 1621
-- Name: malwares; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE malwares FROM PUBLIC;
REVOKE ALL ON TABLE malwares FROM xmpp;
GRANT ALL ON TABLE malwares TO xmpp;
GRANT SELECT ON TABLE malwares TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2111 (class 0 OID 0)
-- Dependencies: 1623
-- Name: normans; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE normans FROM PUBLIC;
REVOKE ALL ON TABLE normans FROM xmpp;
GRANT ALL ON TABLE normans TO xmpp;
GRANT SELECT ON TABLE normans TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2113 (class 0 OID 0)
-- Dependencies: 1625
-- Name: virustotals; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE virustotals FROM PUBLIC;
REVOKE ALL ON TABLE virustotals FROM xmpp;
GRANT ALL ON TABLE virustotals TO xmpp;
GRANT SELECT ON TABLE virustotals TO xmpp_read WITH GRANT OPTION;


--
-- TOC entry 2115 (class 0 OID 0)
-- Dependencies: 1627
-- Name: virustotalscans; Type: ACL; Schema: malware; Owner: -
--

REVOKE ALL ON TABLE virustotalscans FROM PUBLIC;
REVOKE ALL ON TABLE virustotalscans FROM xmpp;
GRANT ALL ON TABLE virustotalscans TO xmpp;
GRANT SELECT ON TABLE virustotalscans TO xmpp_read WITH GRANT OPTION;


-- Completed on 2011-01-22 17:18:12 CET

--
-- PostgreSQL database dump complete
--

