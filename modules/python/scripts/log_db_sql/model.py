import logging

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship, backref


logger = logging.getLogger('log_db_sql')
logger.setLevel(logging.DEBUG)

Base = declarative_base()


class Connection(Base):
    __tablename__ = "connection"

    id = Column(Integer, primary_key=True)
    type = Column(String(255))
    transport = Column(String(255))
    protocol = Column(String(255))
    timestamp = Column(DateTime)
    root = Column(Integer)
    parent = Column(Integer)
    local_host = Column(String(255))
    local_port = Column(Integer)
    remote_host = Column(String(255))
    remote_port = Column(Integer)
    remote_hostname = Column(String(255))


class DownloadData(Base):
    __tablename__ = "download_data"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    url = Column(String(255), index=True)
    md5_hash = Column(String(32), index=True)


class DownloadOffer(Base):
    __tablename__ = "download_offer"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    url = Column(String(255))


class EmuProfile(Base):
    __tablename__ = "emu_profile"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    json_data = Column(Text())


class EmuService(Base):
    __tablename__ = "emu_service"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    url = Column(String(255))


class MSSQLCommand(Base):
    __tablename__ = "mssql_command"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    command = Column(String(255))
    status = Column(String(255), index=True)


class MSSQLFingerprint(Base):
    __tablename__ = "mssql_fingerprint"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    hostname = Column(String(255), index=True)
    appname = Column(String(255), index=True)
    cltintname = Column(String(255), index=True)


class MSSQLLogin(Base):
    __tablename__ = "mssql_login"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    username = Column(String(255), index=True)
    password = Column(String(255), index=True)


class MQTTFingerprint(Base):
    __tablename__ = "mqtt_fingerprint"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    username = Column(String(255), index=True)
    password = Column(String(255), index=True)
    clientid = Column(String(255), index=True)
    will_topic = Column(String(255), index=True)
    will_message = Column(String(255), index=True)


class MQTTPublishCommand(Base):
    __tablename__ = "mqtt_publish_command"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    topic = Column(String(255))
    message = Column(String(255))


class MQTTSubscribeCommand(Base):
    __tablename__ = "mqtt_subscribe_command"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    messageid = Column(String(255))
    topic = Column(String(255))


class MySQLCommand(Base):
    __tablename__ = "mysql_command"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    command = Column(String(255), index=True)


class MySQLCommandArgument(Base):
    __tablename__ = "mysql_command_argument"

    id = Column(Integer, primary_key=True)
    command_id = Column(Integer, ForeignKey("mysql_command.id"), index=True)
    index = Column(Integer)
    value = Column(String(255))

    command = relationship("MySQLCommand", backref=backref("arguments"))


class MySQLCommandOption(Base):
    __tablename__ = "mysql_command_option"

    id = Column(Integer, primary_key=True)
    command_id = Column(Integer, ForeignKey("mysql_command.id"), index=True)
    command = Column(Integer)
    op_name = Column(String(255))


class MySQLLogin(Base):
    __tablename__ = "mysql_login"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    username = Column(String(255), index=True)
    password = Column(String(255), index=True)


class P0F(Base):
    __tablename__ = "p0f"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    genre = Column(String(255))
    link = Column(String(255))
    detail = Column(String(255))
    uptime = Column(Integer)
    tos = Column(String(255))
    dist = Column(Integer)
    nat = Column(Integer)
    fw = Column(Integer)

    connections = relationship("Connection", backref=backref("p0fs"))


class SipAddress(Base):
    __tablename__ = "sip_address"

    id = Column(Integer, primary_key=True)
    command_id = Column(Integer, ForeignKey('sip_command.id'), index=True)
    type = Column(String(255))
    display_name = Column(String(255))
    uri_scheme = Column(String(255))
    uri_username = Column(String(255))
    uri_password = Column(String(255))
    uri_host = Column(String(255))
    uri_port = Column(String(255))

    command = relationship("SipCommand", backref=backref("addresses"))


class SipCommand(Base):
    __tablename__ = "sip_command"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    method = Column(String(255))
    call_id = Column(String(255))
    user_agent = Column(String(255))
    allow = Column(String(255))

    connections = relationship("Connection", backref=backref("sip_commands"))


class SipSdpConnection(Base):
    __tablename__ = "sip_sdp_connection"

    id = Column(Integer, primary_key=True)

    sip_command_id = Column(Integer, ForeignKey('sip_command.id'), index=True)
    network_type = Column(String(255))
    address_type = Column(String(255))
    connection_address = Column(String(255))
    ttl = Column(Integer)
    number_of_addresses = Column(Integer)

    sip_command = relationship("SipCommand", backref=backref("sdp_connections"))


class SipSdpMedia(Base):
    __tablename__ = "sip_sdp_media"

    id = Column(Integer, primary_key=True)

    sip_command_id = Column(Integer, ForeignKey('sip_command.id'), index=True)
    media = Column(String(255))
    port = Column(String(255))
    number_of_ports = Column(String(255))
    protocol = Column(String(255))
    fmt = Column(String(255))
    attributes = Column(String(255))

    sip_command = relationship("SipCommand", backref=backref("sdp_medias"))


class SipSdpOrigin(Base):
    __tablename__ = "sip_sdp_origin"

    id = Column(Integer, primary_key=True)

    sip_command_id = Column(Integer, ForeignKey('sip_command.id'), index=True)
    username = Column(String(255))
    session_id = Column(String(255))
    session_version = Column(String(255))
    network_type = Column(String(255))
    address_type = Column(String(255))
    unicast_address = Column(String(255))

    sip_command = relationship("SipCommand", backref=backref("sdp_origins"))


class SipVia(Base):
    __tablename__ = "sip_via"

    id = Column(Integer, primary_key=True)
    command_id = Column(Integer, ForeignKey('sip_command.id'), index=True)
    protocol = Column(String(255))
    address = Column(String(255))
    port = Column(String(255))

    command = relationship("SipCommand", backref=backref("vias"))


class SmbDCERPCBind(Base):
    __tablename__ = "smb_dcerpc_bind"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    uuid = Column(String(255), index=True)
    transfer_syntax = Column(Text, index=True)


class SmbDCERPCRequest(Base):
    __tablename__ = "smb_dcerpc_request"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    uuid = Column(String(255), index=True)
    opnum = Column(Integer, index=True)


class SmbDCERPCService(Base):
    __tablename__ = "smb_dcerpc_service"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('connection.id'), index=True)
    uuid = Column(String(255), index=True)
    name = Column(String(255))


class VirusTotalResult(Base):
    __tablename__ = "virustotal_result"

    id = Column(Integer, primary_key=True)
    virustotal_scan_id = Column(Integer, ForeignKey('virustotal_scan.id'), index=True)
    result = Column(String(255), index=True)
    scanner = Column(String(255), index=True, nullable=False)

    scan = relationship("VirusTotalScan", backref=backref("results"))


class VirusTotalScan(Base):
    __tablename__ = "virustotal_scan"

    id = Column(Integer, primary_key=True)
    md5_hash = Column(String(255), index=True)
    permalink = Column(String(255))
    timestamp = Column(DateTime)
