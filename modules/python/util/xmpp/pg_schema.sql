--
-- PostgreSQL database dump
--

-- Started on 2010-02-10 22:08:44 CET

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;

--
-- TOC entry 7 (class 2615 OID 16470)
-- Name: dionaea; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA dionaea;


SET search_path = dionaea, pg_catalog;

--
-- TOC entry 305 (class 1247 OID 16472)
-- Dependencies: 7
-- Name: connection_transport; Type: TYPE; Schema: dionaea; Owner: -
--

CREATE TYPE connection_transport AS ENUM (
    'udp',
    'tcp',
    'tls'
);


--
-- TOC entry 307 (class 1247 OID 16477)
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
-- TOC entry 303 (class 1247 OID 16388)
-- Dependencies: 3
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
-- TOC entry 1522 (class 1259 OID 16484)
-- Dependencies: 307 305 7
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
-- TOC entry 1521 (class 1259 OID 16482)
-- Dependencies: 1522 7
-- Name: connections_connection_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE connections_connection_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1879 (class 0 OID 0)
-- Dependencies: 1521
-- Name: connections_connection_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE connections_connection_seq OWNED BY connections.connection;


--
-- TOC entry 1524 (class 1259 OID 16493)
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
-- TOC entry 1523 (class 1259 OID 16491)
-- Dependencies: 7 1524
-- Name: dcerpcbinds_dcerpcbind_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcbinds_dcerpcbind_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1880 (class 0 OID 0)
-- Dependencies: 1523
-- Name: dcerpcbinds_dcerpcbind_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcbinds_dcerpcbind_seq OWNED BY dcerpcbinds.dcerpcbind;


--
-- TOC entry 1526 (class 1259 OID 16506)
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
-- TOC entry 1525 (class 1259 OID 16504)
-- Dependencies: 1526 7
-- Name: dcerpcrequests_dcerpcrequest_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE dcerpcrequests_dcerpcrequest_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1881 (class 0 OID 0)
-- Dependencies: 1525
-- Name: dcerpcrequests_dcerpcrequest_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE dcerpcrequests_dcerpcrequest_seq OWNED BY dcerpcrequests.dcerpcrequest;


--
-- TOC entry 1528 (class 1259 OID 16514)
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
-- TOC entry 1527 (class 1259 OID 16512)
-- Dependencies: 7 1528
-- Name: downloads_download_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE downloads_download_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1882 (class 0 OID 0)
-- Dependencies: 1527
-- Name: downloads_download_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE downloads_download_seq OWNED BY downloads.download;


--
-- TOC entry 1530 (class 1259 OID 16522)
-- Dependencies: 7
-- Name: emu_profiles; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE emu_profiles (
    emu_profile bigint NOT NULL,
    connection bigint NOT NULL,
    emu_profile_json text NOT NULL
);


--
-- TOC entry 1529 (class 1259 OID 16520)
-- Dependencies: 7 1530
-- Name: emu_profiles_emu_profile_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE emu_profiles_emu_profile_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1883 (class 0 OID 0)
-- Dependencies: 1529
-- Name: emu_profiles_emu_profile_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE emu_profiles_emu_profile_seq OWNED BY emu_profiles.emu_profile;


--
-- TOC entry 1536 (class 1259 OID 16582)
-- Dependencies: 7
-- Name: emu_services; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE emu_services (
    emu_service bigint NOT NULL,
    connection bigint,
    emu_service_url character varying(64)
);


--
-- TOC entry 1535 (class 1259 OID 16580)
-- Dependencies: 7 1536
-- Name: emu_services_emu_service_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE emu_services_emu_service_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1884 (class 0 OID 0)
-- Dependencies: 1535
-- Name: emu_services_emu_service_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE emu_services_emu_service_seq OWNED BY emu_services.emu_service;


--
-- TOC entry 1532 (class 1259 OID 16533)
-- Dependencies: 7
-- Name: offers; Type: TABLE; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE TABLE offers (
    offer bigint NOT NULL,
    connection bigint NOT NULL,
    offer_url character varying(256) NOT NULL
);


--
-- TOC entry 1531 (class 1259 OID 16531)
-- Dependencies: 7 1532
-- Name: offers_offer_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE offers_offer_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1885 (class 0 OID 0)
-- Dependencies: 1531
-- Name: offers_offer_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE offers_offer_seq OWNED BY offers.offer;


--
-- TOC entry 1534 (class 1259 OID 16567)
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
-- TOC entry 1533 (class 1259 OID 16565)
-- Dependencies: 1534 7
-- Name: p0fs_p0f_seq; Type: SEQUENCE; Schema: dionaea; Owner: -
--

CREATE SEQUENCE p0fs_p0f_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


--
-- TOC entry 1886 (class 0 OID 0)
-- Dependencies: 1533
-- Name: p0fs_p0f_seq; Type: SEQUENCE OWNED BY; Schema: dionaea; Owner: -
--

ALTER SEQUENCE p0fs_p0f_seq OWNED BY p0fs.p0f;


--
-- TOC entry 1814 (class 2604 OID 16497)
-- Dependencies: 1521 1522 1522
-- Name: connection; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE connections ALTER COLUMN connection SET DEFAULT nextval('connections_connection_seq'::regclass);


--
-- TOC entry 1815 (class 2604 OID 16498)
-- Dependencies: 1523 1524 1524
-- Name: dcerpcbind; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcbinds ALTER COLUMN dcerpcbind SET DEFAULT nextval('dcerpcbinds_dcerpcbind_seq'::regclass);


--
-- TOC entry 1816 (class 2604 OID 16509)
-- Dependencies: 1526 1525 1526
-- Name: dcerpcrequest; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE dcerpcrequests ALTER COLUMN dcerpcrequest SET DEFAULT nextval('dcerpcrequests_dcerpcrequest_seq'::regclass);


--
-- TOC entry 1817 (class 2604 OID 16517)
-- Dependencies: 1527 1528 1528
-- Name: download; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE downloads ALTER COLUMN download SET DEFAULT nextval('downloads_download_seq'::regclass);


--
-- TOC entry 1818 (class 2604 OID 16525)
-- Dependencies: 1529 1530 1530
-- Name: emu_profile; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE emu_profiles ALTER COLUMN emu_profile SET DEFAULT nextval('emu_profiles_emu_profile_seq'::regclass);


--
-- TOC entry 1821 (class 2604 OID 16636)
-- Dependencies: 1535 1536 1536
-- Name: emu_service; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE emu_services ALTER COLUMN emu_service SET DEFAULT nextval('emu_services_emu_service_seq'::regclass);


--
-- TOC entry 1819 (class 2604 OID 16536)
-- Dependencies: 1532 1531 1532
-- Name: offer; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE offers ALTER COLUMN offer SET DEFAULT nextval('offers_offer_seq'::regclass);


--
-- TOC entry 1820 (class 2604 OID 16570)
-- Dependencies: 1534 1533 1534
-- Name: p0f; Type: DEFAULT; Schema: dionaea; Owner: -
--

ALTER TABLE p0fs ALTER COLUMN p0f SET DEFAULT nextval('p0fs_p0f_seq'::regclass);


--
-- TOC entry 1823 (class 2606 OID 16500)
-- Dependencies: 1522 1522
-- Name: connections_connection_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY connections
    ADD CONSTRAINT connections_connection_pkey PRIMARY KEY (connection);


--
-- TOC entry 1833 (class 2606 OID 16502)
-- Dependencies: 1524 1524
-- Name: dcerpcbinds_dcerpcbind_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcbinds
    ADD CONSTRAINT dcerpcbinds_dcerpcbind_pkey PRIMARY KEY (dcerpcbind);


--
-- TOC entry 1839 (class 2606 OID 16511)
-- Dependencies: 1526 1526
-- Name: dcerpcrequests_dcerpcrequest_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY dcerpcrequests
    ADD CONSTRAINT dcerpcrequests_dcerpcrequest_pkey PRIMARY KEY (dcerpcrequest);


--
-- TOC entry 1845 (class 2606 OID 16519)
-- Dependencies: 1528 1528
-- Name: downloads_download_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY downloads
    ADD CONSTRAINT downloads_download_pkey PRIMARY KEY (download);


--
-- TOC entry 1850 (class 2606 OID 16530)
-- Dependencies: 1530 1530
-- Name: emu_profiles_emu_profile_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY emu_profiles
    ADD CONSTRAINT emu_profiles_emu_profile_pkey PRIMARY KEY (emu_profile);


--
-- TOC entry 1865 (class 2606 OID 16638)
-- Dependencies: 1536 1536
-- Name: emu_services_emu_service_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY emu_services
    ADD CONSTRAINT emu_services_emu_service_pkey PRIMARY KEY (emu_service);


--
-- TOC entry 1855 (class 2606 OID 16538)
-- Dependencies: 1532 1532
-- Name: offers_offer_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY offers
    ADD CONSTRAINT offers_offer_pkey PRIMARY KEY (offer);


--
-- TOC entry 1862 (class 2606 OID 16575)
-- Dependencies: 1534 1534
-- Name: p0fs_p0f_pkey; Type: CONSTRAINT; Schema: dionaea; Owner: -; Tablespace: 
--

ALTER TABLE ONLY p0fs
    ADD CONSTRAINT p0fs_p0f_pkey PRIMARY KEY (p0f);


--
-- TOC entry 1824 (class 1259 OID 16539)
-- Dependencies: 1522
-- Name: connections_local_host_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_local_host_idx ON connections USING btree (local_host);


--
-- TOC entry 1825 (class 1259 OID 16540)
-- Dependencies: 1522
-- Name: connections_local_port_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_local_port_idx ON connections USING btree (local_port);


--
-- TOC entry 1826 (class 1259 OID 16541)
-- Dependencies: 1522
-- Name: connections_parent_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_parent_idx ON connections USING btree (connection_parent);


--
-- TOC entry 1827 (class 1259 OID 16542)
-- Dependencies: 1522
-- Name: connections_remote_host_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_remote_host_idx ON connections USING btree (remote_host);


--
-- TOC entry 1828 (class 1259 OID 16543)
-- Dependencies: 1522
-- Name: connections_root_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_root_idx ON connections USING btree (connection_root);


--
-- TOC entry 1829 (class 1259 OID 16544)
-- Dependencies: 1522
-- Name: connections_timestamp_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_timestamp_idx ON connections USING btree (connection_timestamp);


--
-- TOC entry 1830 (class 1259 OID 16553)
-- Dependencies: 1522
-- Name: connections_type_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX connections_type_idx ON connections USING btree (connection_type);


--
-- TOC entry 1831 (class 1259 OID 16554)
-- Dependencies: 1524
-- Name: dcerpcbinds_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_connection_idx ON dcerpcbinds USING btree (connection);


--
-- TOC entry 1834 (class 1259 OID 16555)
-- Dependencies: 1524
-- Name: dcerpcbinds_transfersyntax_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_transfersyntax_idx ON dcerpcbinds USING btree (dcerpcbind_transfersyntax);


--
-- TOC entry 1835 (class 1259 OID 16556)
-- Dependencies: 1524
-- Name: dcerpcbinds_uuid_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcbinds_uuid_idx ON dcerpcbinds USING btree (dcerpcbind_uuid);


--
-- TOC entry 1837 (class 1259 OID 16557)
-- Dependencies: 1526
-- Name: dcerpcrequests_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_connection_idx ON dcerpcrequests USING btree (connection);


--
-- TOC entry 1840 (class 1259 OID 16558)
-- Dependencies: 1526
-- Name: dcerpcrequests_opnum_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_opnum_idx ON dcerpcrequests USING btree (dcerpcrequest_opnum);


--
-- TOC entry 1841 (class 1259 OID 16559)
-- Dependencies: 1526
-- Name: dcerpcrequests_uuid_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX dcerpcrequests_uuid_idx ON dcerpcrequests USING btree (dcerpcrequest_uuid);


--
-- TOC entry 1843 (class 1259 OID 16560)
-- Dependencies: 1528
-- Name: downloads_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_connection_idx ON downloads USING btree (connection);


--
-- TOC entry 1846 (class 1259 OID 16561)
-- Dependencies: 1528
-- Name: downloads_md5_hash_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_md5_hash_idx ON downloads USING btree (download_md5_hash);


--
-- TOC entry 1847 (class 1259 OID 16562)
-- Dependencies: 1528
-- Name: downloads_url_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX downloads_url_idx ON downloads USING btree (download_url);


--
-- TOC entry 1836 (class 1259 OID 16666)
-- Dependencies: 1524
-- Name: fki_dcerpcbinds_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_dcerpcbinds_connection_fkey ON dcerpcbinds USING btree (connection);


--
-- TOC entry 1842 (class 1259 OID 16672)
-- Dependencies: 1526
-- Name: fki_dcerpcrequests_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_dcerpcrequests_connection_fkey ON dcerpcrequests USING btree (connection);


--
-- TOC entry 1848 (class 1259 OID 16678)
-- Dependencies: 1528
-- Name: fki_downloads_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_downloads_connection_fkey ON downloads USING btree (connection);


--
-- TOC entry 1851 (class 1259 OID 16684)
-- Dependencies: 1530
-- Name: fki_emu_profiles_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_emu_profiles_connection_fkey ON emu_profiles USING btree (connection);


--
-- TOC entry 1866 (class 1259 OID 16690)
-- Dependencies: 1536
-- Name: fki_emu_services_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_emu_services_connection_fkey ON emu_services USING btree (connection);


--
-- TOC entry 1852 (class 1259 OID 16707)
-- Dependencies: 1532
-- Name: fki_offers_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_offers_connection_fkey ON offers USING btree (connection);


--
-- TOC entry 1857 (class 1259 OID 16713)
-- Dependencies: 1534
-- Name: fki_p0fs_connection_fkey; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX fki_p0fs_connection_fkey ON p0fs USING btree (connection);


--
-- TOC entry 1853 (class 1259 OID 16563)
-- Dependencies: 1532
-- Name: offers_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX offers_connection_idx ON offers USING btree (connection);


--
-- TOC entry 1856 (class 1259 OID 16564)
-- Dependencies: 1532
-- Name: offers_url_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX offers_url_idx ON offers USING btree (offer_url);


--
-- TOC entry 1858 (class 1259 OID 16576)
-- Dependencies: 1534
-- Name: p0fs_connection_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_connection_idx ON p0fs USING btree (connection);


--
-- TOC entry 1859 (class 1259 OID 16612)
-- Dependencies: 1534
-- Name: p0fs_detail_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_detail_idx ON p0fs USING btree (p0f_detail);


--
-- TOC entry 1860 (class 1259 OID 16589)
-- Dependencies: 1534
-- Name: p0fs_genre_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_genre_idx ON p0fs USING btree (p0f_genre);


--
-- TOC entry 1863 (class 1259 OID 16579)
-- Dependencies: 1534
-- Name: p0fs_uptime_idx; Type: INDEX; Schema: dionaea; Owner: -; Tablespace: 
--

CREATE INDEX p0fs_uptime_idx ON p0fs USING btree (p0f_uptime);


--
-- TOC entry 1867 (class 2606 OID 16661)
-- Dependencies: 1524 1822 1522
-- Name: dcerpcbinds_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY dcerpcbinds
    ADD CONSTRAINT dcerpcbinds_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1868 (class 2606 OID 16667)
-- Dependencies: 1822 1526 1522
-- Name: dcerpcrequests_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY dcerpcrequests
    ADD CONSTRAINT dcerpcrequests_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1869 (class 2606 OID 16673)
-- Dependencies: 1822 1522 1528
-- Name: downloads_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY downloads
    ADD CONSTRAINT downloads_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1870 (class 2606 OID 16679)
-- Dependencies: 1822 1522 1530
-- Name: emu_profiles_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY emu_profiles
    ADD CONSTRAINT emu_profiles_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1873 (class 2606 OID 16685)
-- Dependencies: 1536 1522 1822
-- Name: emu_services_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY emu_services
    ADD CONSTRAINT emu_services_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1871 (class 2606 OID 16702)
-- Dependencies: 1532 1822 1522
-- Name: offers_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY offers
    ADD CONSTRAINT offers_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1872 (class 2606 OID 16708)
-- Dependencies: 1534 1522 1822
-- Name: p0fs_connection_fkey; Type: FK CONSTRAINT; Schema: dionaea; Owner: -
--

ALTER TABLE ONLY p0fs
    ADD CONSTRAINT p0fs_connection_fkey FOREIGN KEY (connection) REFERENCES connections(connection) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- TOC entry 1878 (class 0 OID 0)
-- Dependencies: 3
-- Name: public; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


-- Completed on 2010-02-10 22:08:44 CET

--
-- PostgreSQL database dump complete
--

