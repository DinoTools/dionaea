--
-- PostgreSQL database dump
--

-- Started on 2010-11-18 17:17:33 CET

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;

--
-- TOC entry 5 (class 2615 OID 16958)
-- Name: dionaea; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA dionaea;


SET search_path = dionaea, pg_catalog;

--
-- TOC entry 303 (class 1247 OID 16960)
-- Dependencies: 5
-- Name: connection_transport; Type: TYPE; Schema: dionaea; Owner: -
--

CREATE TYPE connection_transport AS ENUM (
    'udp',
    'tcp',
    'tls'
);


--
-- TOC entry 305 (class 1247 OID 16965)
-- Dependencies: 5
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
-- TOC entry 307 (class 1247 OID 16971)
-- Dependencies: 7
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
-- TOC entry 1544 (class 1259 OID 16976)
-- Dependencies: 5 303 305
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
-- TOC entry 1545 (class 1259 OID 16982)
-- Dependencies: 5 1544
-- Name: connections_connection_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE connections_connection_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1947 (class 0 OID 0)
-- Dependencies: 1545
-- Name: connections_connection_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE connections_connection_seq OWNED BY connections.connection;


--
-- TOC entry 1546 (class 1259 OID 16984)
-- Dependencies: 5
-- Name: dcerpcbinds; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE dcerpcbinds (
    dcerpcbind bigint NOT NULL,
    connection bigint NOT NULL,
    dcerpcbind_uuid uuid NOT NULL,
    dcerpcbind_transfersyntax uuid NOT NULL
);


--
-- TOC entry 1547 (class 1259 OID 16987)
-- Dependencies: 5 1546
-- Name: dcerpcbinds_dcerpcbind_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcbinds_dcerpcbind_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1948 (class 0 OID 0)
-- Dependencies: 1547
-- Name: dcerpcbinds_dcerpcbind_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcbinds_dcerpcbind_seq OWNED BY dcerpcbinds.dcerpcbind;


--
-- TOC entry 1548 (class 1259 OID 16989)
-- Dependencies: 5
-- Name: dcerpcrequests; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE dcerpcrequests (
    dcerpcrequest bigint NOT NULL,
    connection bigint NOT NULL,
    dcerpcrequest_uuid uuid NOT NULL,
    dcerpcrequest_opnum smallint NOT NULL
);


--
-- TOC entry 1549 (class 1259 OID 16992)
-- Dependencies: 5 1548
-- Name: dcerpcrequests_dcerpcrequest_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcrequests_dcerpcrequest_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1949 (class 0 OID 0)
-- Dependencies: 1549
-- Name: dcerpcrequests_dcerpcrequest_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcrequests_dcerpcrequest_seq OWNED BY dcerpcrequests.dcerpcrequest;


--
-- TOC entry 1567 (class 1259 OID 17159)
-- Dependencies: 5
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
-- TOC entry 1566 (class 1259 OID 17157)
-- Dependencies: 5 1567
-- Name: dcerpcserviceops_dcerpcserviceop_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcserviceops_dcerpcserviceop_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1950 (class 0 OID 0)
-- Dependencies: 1566
-- Name: dcerpcserviceops_dcerpcserviceop_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcserviceops_dcerpcserviceop_seq OWNED BY dcerpcserviceops.dcerpcserviceop;


--
-- TOC entry 1569 (class 1259 OID 17167)
-- Dependencies: 5
-- Name: dcerpcservices; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE dcerpcservices (
    dcerpcservice integer NOT NULL,
    dcerpcservice_uuid uuid NOT NULL,
    dcerpcservice_name character varying(32) NOT NULL
);


--
-- TOC entry 1568 (class 1259 OID 17165)
-- Dependencies: 1569 5
-- Name: dcerpcservices_dcerpcservice_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcservices_dcerpcservice_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1951 (class 0 OID 0)
-- Dependencies: 1568
-- Name: dcerpcservices_dcerpcservice_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcservices_dcerpcservice_seq OWNED BY dcerpcservices.dcerpcservice;


--
-- TOC entry 1550 (class 1259 OID 16994)
-- Dependencies: 5
-- Name: downloads; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE downloads (
    download bigint NOT NULL,
    connection bigint NOT NULL,
    download_md5_hash character varying(32) NOT NULL,
    download_url character varying(256) NOT NULL
);


--
-- TOC entry 1551 (class 1259 OID 16997)
-- Dependencies: 5 1550
-- Name: downloads_download_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE downloads_download_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1952 (class 0 OID 0)
-- Dependencies: 1551
-- Name: downloads_download_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE downloads_download_seq OWNED BY downloads.download;


--
-- TOC entry 1552 (class 1259 OID 16999)
-- Dependencies: 5
-- Name: emu_profiles; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE emu_profiles (
    emu_profile bigint NOT NULL,
    connection bigint NOT NULL,
    emu_profile_json text NOT NULL
);


--
-- TOC entry 1553 (class 1259 OID 17005)
-- Dependencies: 5 1552
-- Name: emu_profiles_emu_profile_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE emu_profiles_emu_profile_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1953 (class 0 OID 0)
-- Dependencies: 1553
-- Name: emu_profiles_emu_profile_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE emu_profiles_emu_profile_seq OWNED BY emu_profiles.emu_profile;


--
-- TOC entry 1554 (class 1259 OID 17007)
-- Dependencies: 5
-- Name: emu_services; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE emu_services (
    emu_service bigint NOT NULL,
    connection bigint,
    emu_service_url character varying(64)
);


--
-- TOC entry 1555 (class 1259 OID 17010)
-- Dependencies: 1554 5
-- Name: emu_services_emu_service_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE emu_services_emu_service_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1954 (class 0 OID 0)
-- Dependencies: 1555
-- Name: emu_services_emu_service_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE emu_services_emu_service_seq OWNED BY emu_services.emu_service;


--
-- TOC entry 1565 (class 1259 OID 17146)
-- Dependencies: 5
-- Name: logins; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE logins (
    login bigint NOT NULL,
    connection bigint,
    login_username character varying(64),
    login_password character varying(64)
);


--
-- TOC entry 1564 (class 1259 OID 17144)
-- Dependencies: 1565 5
-- Name: logins_login_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE logins_login_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1955 (class 0 OID 0)
-- Dependencies: 1564
-- Name: logins_login_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE logins_login_seq OWNED BY logins.login;


--
-- TOC entry 1561 (class 1259 OID 17113)
-- Dependencies: 5
-- Name: mssql_commands; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE mssql_commands (
    mssql_command bigint NOT NULL,
    connection bigint NOT NULL,
    mssql_command_status character varying(8) NOT NULL,
    mssql_command_cmd text NOT NULL
);


--
-- TOC entry 1560 (class 1259 OID 17111)
-- Dependencies: 5 1561
-- Name: mssql_commands_mssql_command_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE mssql_commands_mssql_command_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1956 (class 0 OID 0)
-- Dependencies: 1560
-- Name: mssql_commands_mssql_command_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE mssql_commands_mssql_command_seq OWNED BY mssql_commands.mssql_command;


--
-- TOC entry 1563 (class 1259 OID 17133)
-- Dependencies: 5
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
-- TOC entry 1562 (class 1259 OID 17131)
-- Dependencies: 5 1563
-- Name: mssql_fingerprints_mssql_fingerprint_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE mssql_fingerprints_mssql_fingerprint_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1957 (class 0 OID 0)
-- Dependencies: 1562
-- Name: mssql_fingerprints_mssql_fingerprint_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE mssql_fingerprints_mssql_fingerprint_seq OWNED BY mssql_fingerprints.mssql_fingerprint;


--
-- TOC entry 1556 (class 1259 OID 17012)
-- Dependencies: 5
-- Name: offers; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE offers (
    offer bigint NOT NULL,
    connection bigint NOT NULL,
    offer_url character varying(256) NOT NULL
);


--
-- TOC entry 1557 (class 1259 OID 17015)
-- Dependencies: 5 1556
-- Name: offers_offer_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE offers_offer_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1958 (class 0 OID 0)
-- Dependencies: 1557
-- Name: offers_offer_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE offers_offer_seq OWNED BY offers.offer;


--
-- TOC entry 1558 (class 1259 OID 17017)
-- Dependencies: 5
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
-- TOC entry 1559 (class 1259 OID 17020)
-- Dependencies: 1558 5
-- Name: p0fs_p0f_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE p0fs_p0f_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1959 (class 0 OID 0)
-- Dependencies: 1559
-- Name: p0fs_p0f_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE p0fs_p0f_seq OWNED BY p0fs.p0f;


--
-- TOC entry 1571 (class 1259 OID 17177)
-- Dependencies: 5
-- Name: virustotals; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE virustotals (
    virustotal integer NOT NULL,
    virustotal_md5_hash character(32) NOT NULL,
    virustotal_timestamp timestamp with time zone NOT NULL,
    virustotal_permalink character varying(128) NOT NULL
);


--
-- TOC entry 1570 (class 1259 OID 17175)
-- Dependencies: 5 1571
-- Name: virustotals_virustotal_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE virustotals_virustotal_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1960 (class 0 OID 0)
-- Dependencies: 1570
-- Name: virustotals_virustotal_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE virustotals_virustotal_seq OWNED BY virustotals.virustotal;


--
-- TOC entry 1573 (class 1259 OID 17185)
-- Dependencies: 5
-- Name: virustotalscans; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE virustotalscans (
    virustotalscan integer NOT NULL,
    virustotal integer NOT NULL,
    virustotalscan_scanner character varying(32) NOT NULL,
    virustotalscan_result text
);


--
-- TOC entry 1572 (class 1259 OID 17183)
-- Dependencies: 5 1573
-- Name: virustotalscans_virustotalscan_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE virustotalscans_virustotalscan_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1961 (class 0 OID 0)
-- Dependencies: 1572
-- Name: virustotalscans_virustotalscan_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE virustotalscans_virustotalscan_seq OWNED BY virustotalscans.virustotalscan;


--
-- TOC entry 1851 (class 2604 OID 17022)
-- Dependencies: 1545 1544
-- Name: connection; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE connections ALTER COLUMN connection SET DEFAULT nextval('connections_connection_seq'::regclass);


--
-- TOC entry 1852 (class 2604 OID 17023)
-- Dependencies: 1547 1546
-- Name: dcerpcbind; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcbinds ALTER COLUMN dcerpcbind SET DEFAULT nextval('dcerpcbinds_dcerpcbind_seq'::regclass);


--
-- TOC entry 1853 (class 2604 OID 17024)
-- Dependencies: 1549 1548
-- Name: dcerpcrequest; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcrequests ALTER COLUMN dcerpcrequest SET DEFAULT nextval('dcerpcrequests_dcerpcrequest_seq'::regclass);


--
-- TOC entry 1862 (class 2604 OID 17162)
-- Dependencies: 1566 1567 1567
-- Name: dcerpcserviceop; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcserviceops ALTER COLUMN dcerpcserviceop SET DEFAULT nextval('dcerpcserviceops_dcerpcserviceop_seq'::regclass);


--
-- TOC entry 1863 (class 2604 OID 17170)
-- Dependencies: 1569 1568 1569
-- Name: dcerpcservice; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcservices ALTER COLUMN dcerpcservice SET DEFAULT nextval('dcerpcservices_dcerpcservice_seq'::regclass);


--
-- TOC entry 1854 (class 2604 OID 17025)
-- Dependencies: 1551 1550
-- Name: download; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE downloads ALTER COLUMN download SET DEFAULT nextval('downloads_download_seq'::regclass);


--
-- TOC entry 1855 (class 2604 OID 17026)
-- Dependencies: 1553 1552
-- Name: emu_profile; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE emu_profiles ALTER COLUMN emu_profile SET DEFAULT nextval('emu_profiles_emu_profile_seq'::regclass);


--
-- TOC entry 1856 (class 2604 OID 17027)
-- Dependencies: 1555 1554
-- Name: emu_service; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE emu_services ALTER COLUMN emu_service SET DEFAULT nextval('emu_services_emu_service_seq'::regclass);


--
-- TOC entry 1861 (class 2604 OID 17149)
-- Dependencies: 1564 1565 1565
-- Name: login; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE logins ALTER COLUMN login SET DEFAULT nextval('logins_login_seq'::regclass);


--
-- TOC entry 1859 (class 2604 OID 17116)
-- Dependencies: 1560 1561 1561
-- Name: mssql_command; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE mssql_commands ALTER COLUMN mssql_command SET DEFAULT nextval('mssql_commands_mssql_command_seq'::regclass);


--
-- TOC entry 1860 (class 2604 OID 17136)
-- Dependencies: 1563 1562 1563
-- Name: mssql_fingerprint; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE mssql_fingerprints ALTER COLUMN mssql_fingerprint SET DEFAULT nextval('mssql_fingerprints_mssql_fingerprint_seq'::regclass);


--
-- TOC entry 1857 (class 2604 OID 17028)
-- Dependencies: 1557 1556
-- Name: offer; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE offers ALTER COLUMN offer SET DEFAULT nextval('offers_offer_seq'::regclass);


--
-- TOC entry 1858 (class 2604 OID 17029)
-- Dependencies: 1559 1558
-- Name: p0f; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE p0fs ALTER COLUMN p0f SET DEFAULT nextval('p0fs_p0f_seq'::regclass);


--
-- TOC entry 1864 (class 2604 OID 17180)
-- Dependencies: 1571 1570 1571
-- Name: virustotal; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE virustotals ALTER COLUMN virustotal SET DEFAULT nextval('virustotals_virustotal_seq'::regclass);


--
-- TOC entry 1865 (class 2604 OID 17188)
-- Dependencies: 1573 1572 1573
-- Name: virustotalscan; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE virustotalscans ALTER COLUMN virustotalscan SET DEFAULT nextval('virustotalscans_virustotalscan_seq'::regclass);


--
-- TOC entry 1867 (class 2606 OID 17031)
-- Dependencies: 1544 1544
-- Name: connections_connection_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY connections
    ADD CONSTRAINT connections_connection_pkey PRIMARY KEY (connection);


--
-- TOC entry 1877 (class 2606 OID 17033)
-- Dependencies: 1546 1546
-- Name: dcerpcbinds_dcerpcbind_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcbinds
    ADD CONSTRAINT dcerpcbinds_dcerpcbind_pkey PRIMARY KEY (dcerpcbind);


--
-- TOC entry 1883 (class 2606 OID 17035)
-- Dependencies: 1548 1548
-- Name: dcerpcrequests_dcerpcrequest_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcrequests
    ADD CONSTRAINT dcerpcrequests_dcerpcrequest_pkey PRIMARY KEY (dcerpcrequest);


--
-- TOC entry 1921 (class 2606 OID 17164)
-- Dependencies: 1567 1567
-- Name: dcerpcserviceops_dcerpcserviceop_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcserviceops
    ADD CONSTRAINT dcerpcserviceops_dcerpcserviceop_pkey PRIMARY KEY (dcerpcserviceop);


--
-- TOC entry 1923 (class 2606 OID 17174)
-- Dependencies: 1569 1569
-- Name: dcerpcservices_dcerpcservice_uuid_uniq; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcservices
    ADD CONSTRAINT dcerpcservices_dcerpcservice_uuid_uniq UNIQUE (dcerpcservice_uuid);


--
-- TOC entry 1925 (class 2606 OID 17172)
-- Dependencies: 1569 1569
-- Name: dcerpcservices_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcservices
    ADD CONSTRAINT dcerpcservices_pkey PRIMARY KEY (dcerpcservice);


--
-- TOC entry 1889 (class 2606 OID 17037)
-- Dependencies: 1550 1550
-- Name: downloads_download_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY downloads
    ADD CONSTRAINT downloads_download_pkey PRIMARY KEY (download);


--
-- TOC entry 1894 (class 2606 OID 17039)
-- Dependencies: 1552 1552
-- Name: emu_profiles_emu_profile_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY emu_profiles
    ADD CONSTRAINT emu_profiles_emu_profile_pkey PRIMARY KEY (emu_profile);


--
-- TOC entry 1897 (class 2606 OID 17041)
-- Dependencies: 1554 1554
-- Name: emu_services_emu_service_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY emu_services
    ADD CONSTRAINT emu_services_emu_service_pkey PRIMARY KEY (emu_service);


--
-- TOC entry 1919 (class 2606 OID 17151)
-- Dependencies: 1565 1565
-- Name: logins_login_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY logins
    ADD CONSTRAINT logins_login_pkey PRIMARY KEY (login);


--
-- TOC entry 1913 (class 2606 OID 17130)
-- Dependencies: 1561 1561
-- Name: mssql_commands_mssql_command_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY mssql_commands
    ADD CONSTRAINT mssql_commands_mssql_command_pkey PRIMARY KEY (mssql_command);


--
-- TOC entry 1916 (class 2606 OID 17138)
-- Dependencies: 1563 1563
-- Name: mssql_fingerprints_mssql_fingerprint_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY mssql_fingerprints
    ADD CONSTRAINT mssql_fingerprints_mssql_fingerprint_pkey PRIMARY KEY (mssql_fingerprint);


--
-- TOC entry 1902 (class 2606 OID 17043)
-- Dependencies: 1556 1556
-- Name: offers_offer_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY offers
    ADD CONSTRAINT offers_offer_pkey PRIMARY KEY (offer);


--
-- TOC entry 1909 (class 2606 OID 17045)
-- Dependencies: 1558 1558
-- Name: p0fs_p0f_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY p0fs
    ADD CONSTRAINT p0fs_p0f_pkey PRIMARY KEY (p0f);


--
-- TOC entry 1927 (class 2606 OID 17182)
-- Dependencies: 1571 1571
-- Name: virustotals_virustotal_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY virustotals
    ADD CONSTRAINT virustotals_virustotal_pkey PRIMARY KEY (virustotal);


--
-- TOC entry 1930 (class 2606 OID 17190)
-- Dependencies: 1573 1573
-- Name: virustotalscans_virustotalscan_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY virustotalscans
    ADD CONSTRAINT virustotalscans_virustotalscan_pkey PRIMARY KEY (virustotalscan);


--
-- TOC entry 1868 (class 1259 OID 17046)
-- Dependencies: 1544
-- Name: connections_local_host_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_local_host_idx ON connections USING btree (local_host);


--
-- TOC entry 1869 (class 1259 OID 17047)
-- Dependencies: 1544
-- Name: connections_local_port_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_local_port_idx ON connections USING btree (local_port);


--
-- TOC entry 1870 (class 1259 OID 17048)
-- Dependencies: 1544
-- Name: connections_parent_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_parent_idx ON connections USING btree (connection_parent);


--
-- TOC entry 1871 (class 1259 OID 17049)
-- Dependencies: 1544
-- Name: connections_remote_host_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_remote_host_idx ON connections USING btree (remote_host);


--
-- TOC entry 1872 (class 1259 OID 17050)
-- Dependencies: 1544
-- Name: connections_root_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_root_idx ON connections USING btree (connection_root);


--
-- TOC entry 1873 (class 1259 OID 17051)
-- Dependencies: 1544
-- Name: connections_timestamp_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_timestamp_idx ON connections USING btree (connection_timestamp);


--
-- TOC entry 1874 (class 1259 OID 17052)
-- Dependencies: 1544
-- Name: connections_type_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_type_idx ON connections USING btree (connection_type);


--
-- TOC entry 1875 (class 1259 OID 17053)
-- Dependencies: 1546
-- Name: dcerpcbinds_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_connection_idx ON dcerpcbinds USING btree (connection);


--
-- TOC entry 1878 (class 1259 OID 17054)
-- Dependencies: 1546
-- Name: dcerpcbinds_transfersyntax_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_transfersyntax_idx ON dcerpcbinds USING btree (dcerpcbind_transfersyntax);


--
-- TOC entry 1879 (class 1259 OID 17055)
-- Dependencies: 1546
-- Name: dcerpcbinds_uuid_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_uuid_idx ON dcerpcbinds USING btree (dcerpcbind_uuid);


--
-- TOC entry 1881 (class 1259 OID 17056)
-- Dependencies: 1548
-- Name: dcerpcrequests_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_connection_idx ON dcerpcrequests USING btree (connection);


--
-- TOC entry 1884 (class 1259 OID 17057)
-- Dependencies: 1548
-- Name: dcerpcrequests_opnum_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_opnum_idx ON dcerpcrequests USING btree (dcerpcrequest_opnum);


--
-- TOC entry 1885 (class 1259 OID 17058)
-- Dependencies: 1548
-- Name: dcerpcrequests_uuid_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_uuid_idx ON dcerpcrequests USING btree (dcerpcrequest_uuid);


--
-- TOC entry 1887 (class 1259 OID 17059)
-- Dependencies: 1550
-- Name: downloads_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_connection_idx ON downloads USING btree (connection);


--
-- TOC entry 1890 (class 1259 OID 17060)
-- Dependencies: 1550
-- Name: downloads_md5_hash_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_md5_hash_idx ON downloads USING btree (download_md5_hash);


--
-- TOC entry 1891 (class 1259 OID 17061)
-- Dependencies: 1550
-- Name: downloads_url_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_url_idx ON downloads USING btree (download_url);


--
-- TOC entry 1880 (class 1259 OID 17062)
-- Dependencies: 1546
-- Name: fki_dcerpcbinds_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_dcerpcbinds_connection_fkey ON dcerpcbinds USING btree (connection);


--
-- TOC entry 1886 (class 1259 OID 17063)
-- Dependencies: 1548
-- Name: fki_dcerpcrequests_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_dcerpcrequests_connection_fkey ON dcerpcrequests USING btree (connection);


--
-- TOC entry 1892 (class 1259 OID 17064)
-- Dependencies: 1550
-- Name: fki_downloads_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_downloads_connection_fkey ON downloads USING btree (connection);


--
-- TOC entry 1895 (class 1259 OID 17065)
-- Dependencies: 1552
-- Name: fki_emu_profiles_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_emu_profiles_connection_fkey ON emu_profiles USING btree (connection);


--
-- TOC entry 1898 (class 1259 OID 17066)
-- Dependencies: 1554
-- Name: fki_emu_services_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_emu_services_connection_fkey ON emu_services USING btree (connection);


--
-- TOC entry 1917 (class 1259 OID 17302)
-- Dependencies: 1565
-- Name: fki_logins_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_logins_connection_fkey ON logins USING btree (connection);


--
-- TOC entry 1911 (class 1259 OID 17296)
-- Dependencies: 1561
-- Name: fki_mssql_commands_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_mssql_commands_connection_fkey ON mssql_commands USING btree (connection);


--
-- TOC entry 1914 (class 1259 OID 17290)
-- Dependencies: 1563
-- Name: fki_mssql_fingerprints_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_mssql_fingerprints_connection_fkey ON mssql_fingerprints USING btree (connection);


--
-- TOC entry 1899 (class 1259 OID 17067)
-- Dependencies: 1556
-- Name: fki_offers_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_offers_connection_fkey ON offers USING btree (connection);


--
-- TOC entry 1904 (class 1259 OID 17068)
-- Dependencies: 1558
-- Name: fki_p0fs_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_p0fs_connection_fkey ON p0fs USING btree (connection);


--
-- TOC entry 1928 (class 1259 OID 17261)
-- Dependencies: 1573
-- Name: fki_virustotalscans_virustotal_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_virustotalscans_virustotal_fkey ON virustotalscans USING btree (virustotal);


--
-- TOC entry 1900 (class 1259 OID 17069)
-- Dependencies: 1556
-- Name: offers_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX offers_connection_idx ON offers USING btree (connection);


--
-- TOC entry 1903 (class 1259 OID 17070)
-- Dependencies: 1556
-- Name: offers_url_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX offers_url_idx ON offers USING btree (offer_url);


--
-- TOC entry 1905 (class 1259 OID 17071)
-- Dependencies: 1558
-- Name: p0fs_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_connection_idx ON p0fs USING btree (connection);


--
-- TOC entry 1906 (class 1259 OID 17072)
-- Dependencies: 1558
-- Name: p0fs_detail_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_detail_idx ON p0fs USING btree (p0f_detail);


--
-- TOC entry 1907 (class 1259 OID 17073)
-- Dependencies: 1558
-- Name: p0fs_genre_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_genre_idx ON p0fs USING btree (p0f_genre);


--
-- TOC entry 1910 (class 1259 OID 17074)
-- Dependencies: 1558
-- Name: p0fs_uptime_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_uptime_idx ON p0fs USING btree (p0f_uptime);


--
-- TOC entry 1931 (class 2606 OID 17075)
-- Dependencies: 1546 1544 1866
-- Name: dcerpcbinds_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY dcerpcbinds
    ADD CONSTRAINT dcerpcbinds_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1932 (class 2606 OID 17080)
-- Dependencies: 1548 1866 1544
-- Name: dcerpcrequests_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY dcerpcrequests
    ADD CONSTRAINT dcerpcrequests_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1933 (class 2606 OID 17085)
-- Dependencies: 1544 1550 1866
-- Name: downloads_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY downloads
    ADD CONSTRAINT downloads_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1934 (class 2606 OID 17090)
-- Dependencies: 1544 1866 1552
-- Name: emu_profiles_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY emu_profiles
    ADD CONSTRAINT emu_profiles_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1935 (class 2606 OID 17095)
-- Dependencies: 1544 1866 1554
-- Name: emu_services_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY emu_services
    ADD CONSTRAINT emu_services_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1940 (class 2606 OID 17297)
-- Dependencies: 1866 1544 1565
-- Name: logins_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY logins
    ADD CONSTRAINT logins_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1938 (class 2606 OID 17291)
-- Dependencies: 1561 1544 1866
-- Name: mssql_commands_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY mssql_commands
    ADD CONSTRAINT mssql_commands_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1939 (class 2606 OID 17285)
-- Dependencies: 1563 1544 1866
-- Name: mssql_fingerprints_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY mssql_fingerprints
    ADD CONSTRAINT mssql_fingerprints_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1936 (class 2606 OID 17100)
-- Dependencies: 1544 1556 1866
-- Name: offers_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY offers
    ADD CONSTRAINT offers_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1937 (class 2606 OID 17105)
-- Dependencies: 1544 1558 1866
-- Name: p0fs_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY p0fs
    ADD CONSTRAINT p0fs_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1941 (class 2606 OID 17256)
-- Dependencies: 1573 1926 1571
-- Name: virustotalscans_virustotal_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY virustotalscans
    ADD CONSTRAINT virustotalscans_virustotal_fkey FOREIGN KEY (virustotal) REFERENCES virustotals(virustotal) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1946 (class 0 OID 0)
-- Dependencies: 7
-- Name: public; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


-- Completed on 2010-11-18 17:17:33 CET

--
-- PostgreSQL database dump complete
--

