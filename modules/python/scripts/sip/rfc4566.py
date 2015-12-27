"""
This package implements RFC 4566

:See: http://tools.ietf.org/html/rfc4566
"""

import logging
import re

try:
    from dionaea.sip.extras import int2bytes
except:
    from extras import int2bytes

logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)


class SdpParsingError(Exception):
    """Exception class for errors occuring during SDP message parsing"""


class Attribute(object):
    """
    "Attributes are the primary means for extending SDP."

    Format: a=<attribute>
    Format: a=<attribute>:<value>

    :See: http://tools.ietf.org/html/rfc4566#page-21

    >>> s = b"tool:foo"
    >>> a = Attribute.froms(s)
    >>> print(a.dumps())
    b'tool:foo'
    >>> print(a.value, a.attribute)
    b'foo' b'tool'
    >>> s = b"sendrecv"
    >>> a = Attribute(attribute=s)
    >>> print(a.dumps())
    b'sendrecv'
    >>> print(a.attribute)
    b'sendrecv'
    >>> print(a.value)
    None
    """
    def __init__(self, attribute=None, value=None):
        self.attribute = attribute
        self.value = value
        # we need at least a name
        if self.attribute == None or self.attribute == b"":
            raise ValueError("Attribute name is empty")

    @classmethod
    def froms(cls,data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        attribute, sep, v = data.partition(b":")
        if sep != b":":
            v = None
        return (len(data), {'value':v,'attribute':attribute})

    def dumps(self):
        if self.value is None:
            return self.attribute
        return b":".join([self.attribute, self.value])


class Attributes(object):
    """
    Handle a list of attributes
    """

    def __init__(self):
        self._attributes = []

    def __iter__(self):
        return iter(self._attributes)

    def append(self, value):
        if type(value) == bytes:
            self._attributes.append(Attribute.froms(value))
            return

        self._attributes.append(value)

    def get(self, name, default=None):
        """
        Get the first attribute with the specified name.
        """

        for a in self._attributes:
            if name == a.attribute:
                return a

    def get_list(self, name):
        """
        Get a list of all attributes with the specified name.
        """
        ret = []
        for a in self._attributes:
            if name == a.attribute:
                ret.append(a)

        return ret

    def get_value(self, name, default = None):
        """
        Get the value of a specified attribute.
        """
        attr = self.get(name, default)
        if attr == default:
            return None

        return attr.value


class Bandwidth(object):
    """
    Format: b=<bwtype>:<bandwidth>

    :See: http://tools.ietf.org/html/rfc4566#page-16

    # Example taken from RFC4566
    >>> s = b"X-YZ:128"
    >>> b = Bandwidth.froms(s)
    >>> print(b.dumps() == s)
    True
    >>> print(b.bwtype)
    b'X-YZ'
    >>> print(b.bandwidth)
    128
    """

    def __init__(self, bwtype=None, bandwidth=None):
        self.bwtype = bwtype
        self.bandwidth = bandwidth

    @classmethod
    def froms(cls,data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        bwtype, bandwidth = data.split(b":")
        bandwidth = int(bandwidth)
        return (len(data), {'bwtype':bwtype,'bandwidth':bandwidth})

    def dumps(self):
        return b":".join([self.bwtype, int2bytes(self.bandwidth)])


class ConnectionData(object):
    """
    "The "c=" field contains connection data."

    Format: c=<nettype> <addrtype> <connection-address>

    :See: http://tools.ietf.org/html/rfc4566#page-14

    Test values are taken from RFC4566

    >>> s = b"IN IP4 224.2.36.42/127"
    >>> c = ConnectionData.froms(s)
    >>> print(c.dumps())
    b'IN IP4 224.2.36.42/127'
    >>> print(str(c.ttl), c.connection_address, c.addrtype, c.nettype)
    127 b'224.2.36.42' b'IP4' b'IN'
    >>> s = b"IN IP4 224.2.1.1/127/3"
    >>> c = ConnectionData.froms(s)
    >>> print(c.dumps())
    b'IN IP4 224.2.1.1/127/3'
    >>> print(str(c.number_of_addresses), str(c.ttl), c.connection_address, c.addrtype, c.nettype)
    3 127 b'224.2.1.1' b'IP4' b'IN'
    """

    def __init__(self, nettype=None,addrtype=None,connection_address=None,ttl=None,number_of_addresses=None):
        self.nettype = nettype
        self.addrtype = addrtype
        self.connection_address = connection_address
        self.ttl = ttl
        self.number_of_addresses = number_of_addresses

    @classmethod
    def froms(cls,data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        nettype, addrtype, con_addr = re.split(b" +", data, 2)
        con_values = con_addr.split(b"/")
        connection_address = con_values[0]

        # ToDo: IP6?
        if addrtype == b"IP4":
            if len(con_values) > 1:
                ttl = int(con_values[1])
            else:
                ttl = None
            if len(con_values) > 2:
                number_of_addresses = int(con_values[2])
            else:
                number_of_addresses = None
        return (
            len(data),
            {
                'nettype': nettype,
                'addrtype': addrtype,
                'connection_address': connection_address,
                'ttl': ttl,
                'number_of_addresses': number_of_addresses
            }
        )

    def dumps(self):
        addr = self.connection_address
        if self.addrtype == b"IP4":
            if self.ttl is not None:
                addr = addr + b"/" + int2bytes(self.ttl)
            if self.ttl is not None and self.number_of_addresses is not None:
                addr = addr + b"/" + int2bytes(self.number_of_addresses)

        # ToDo: IPv6
        return b" ".join([self.nettype, self.addrtype, addr])


class Media(object):
    """
    "A session description may contain a number of media descriptions."

    Format: m=<media> <port>/<number of ports> <proto> <fmt> ...

    :See: http://tools.ietf.org/html/rfc4566#page-22

    >>> s = b"video 49170/2 RTP/AVP 31"
    >>> m = Media.froms(s)
    >>> print(m.dumps() == s)
    True
    >>> print(m.fmt, m.proto, m.number_of_ports, m.port, m.media)
    [b'31'] b'RTP/AVP' 2 49170 b'video'
    >>> s = b"audio 49170 RTP/AVP 31"
    >>> m = Media.froms(s)
    >>> print(m.dumps() == s)
    True
    >>> print(m.fmt, m.proto, m.number_of_ports, m.port, m.media)
    [b'31'] b'RTP/AVP' None 49170 b'audio'
    """

    def __init__(self, media=None, port=None, number_of_ports=None, proto=None, fmt=None, attributes=None):
        self.media = media
        self.port = port
        self.number_of_ports = number_of_ports
        self.proto = proto
        self.fmt = fmt
        if attributes == None:
            attributes = Attributes()
        self.attributes = attributes

    @classmethod
    def froms(cls,data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        media, ports, proto, rest = re.split(b" +", data, 3)

        # Media: currently defined media are "audio", "video", "text", "application", and "message"
        # check if we support the type and if not send an error?
        port, sep, ports = ports.partition(b"/")
        port = int(port)
        if ports != b"":
            number_of_ports = int(ports)
        else:
            number_of_ports = None

        # ToDo: better fmt handling
        fmt = rest.split(b" ")
        return (
            len(data),
            {
                "media": media,
                "port": port,
                "number_of_ports": number_of_ports,
                "proto": proto,
                "fmt": fmt
            }
        )

    def dumps(self):
        # ToDo: better fmt handling
        fmt = b" ".join(self.fmt)

        ports = int2bytes(self.port)

        if self.number_of_ports != None:
            ports = ports + b"/" + int2bytes(self.number_of_ports)

        return b" ".join([self.media, ports, self.proto, fmt])


class Origin(object):
    """
    "The "o=" field gives the originator of the session (her username and the address of the user's host) plus a session identifier and version number"

    :See: http://tools.ietf.org/html/rfc4566#page-11

    >>> s = b"Foo 12345 12345 IN IP4 192.168.1.1"
    >>> o = Origin.froms(s)
    >>> print(s == o.dumps())
    True
    """
    def __init__(self, username=b'-',sess_id=-1,sess_version=-1,nettype=b'IN',addrtype=b"IP4",unicast_address=b"127.0.0.1"):

        self.username = username
        self.sess_id = sess_id
        self.sess_version = sess_version
        self.nettype = nettype
        self.addrtype = addrtype
        self.unicast_address = unicast_address

    @classmethod
    def froms(cls,data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        username, sess_id, sess_version, nettype, addrtype, unicast_address = re.split(b" +", data, 5)
        sess_id = int(sess_id)
        sess_version = int(sess_version)
        return (
            len(data),
            {
                "username": username,
                "sess_id": sess_id,
                "sess_version": sess_version,
                "nettype": nettype,
                "addrtype": addrtype,
                "unicast_address": unicast_address
            }
        )

    def dumps(self):
        return b" ".join([self.username, int2bytes(self.sess_id), int2bytes(self.sess_version), self.nettype, self.addrtype, self.unicast_address])


class SDP(object):
    """
    Example taken from RFC4566 p.10 See: http://tools.ietf.org/html/rfc4566#page-10
    >>> s = b"v=0\\r\\n"
    >>> s = s + b"o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\\r\\n"
    >>> s = s + b"s=SDP Seminar\\r\\n"
    >>> s = s + b"i=A Seminar on the session description protocol\\r\\n"
    >>> s = s + b"u=http://www.example.com/seminars/sdp.pdf\\r\\n"
    >>> s = s + b"e=j.doe@example.com (Jane Doe)\\r\\n"
    >>> s = s + b"c=IN IP4 224.2.17.12/127\\r\\n"
    >>> s = s + b"t=2873397496 2873404696\\r\\n"
    >>> s = s + b"a=recvonly\\r\\n"
    >>> s = s + b"m=audio 49170 RTP/AVP 0\\r\\n"
    >>> s = s + b"m=video 51372 RTP/AVP 99\\r\\n"
    >>> s = s + b"a=rtpmap:99 h263-1998/90000\\r\\n"
    >>> sdp = SDP.froms(s)
    >>> #print(str(s, "utf-8"), "--", str(sdp.dumps(), "utf-8"))
    >>> #print(sdp.dumps(), s)
    >>> print(sdp.dumps() == s)
    True
    """

    _must = ["v", "s"]
    _once = ["u", "c"]
    _multi = []
    _attributes_allowed = [b"v", b"o", b"s", b"i", b"u", b"e", b"p", b"c", b"b", b"t", b"r", b"z", b"a", b"m"]

    def __init__(self, a=None, b=None, c=None, e=None, i=None, k=None, m=None, o=None, p=None, r=None, s=None, t=None, u=None, v=None, z=None):
        self._attributes = {
            b"a": a, # Attributes
            b"b": b, # Bandwidth
            b"c": c, # Connection Data
            b"e": e, # Email Address
            b"i": i, # Session Information
            b"k": k, # Encryption Keys
            b"m": m, # Media Description
            b"o": o, # Origin
            b"p": p, # Phone Number
            b"r": r, # Repeat Times
            b"s": s, # Session Name
            b"t": t, # Timing
            b"u": u, # URI
            b"v": v, # Protocol Version
            b"z": z, # Time Zone
        }

    def __getitem__(self, name):
        return self.get(name)

    @classmethod
    def froms(cls,data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        attributes = {k:None for k in cls._attributes_allowed}
        data_length = len(data)
        data = data.replace(b"\r\n", b"\n")
        for line in data.split(b"\n"):
            try:
                k, sep, v = line.partition(b"=")
                if k == b"v":
                    attributes[k] = int(v)
                elif k == b"o":
                    attributes[k] = Origin.froms(v)
                elif k == b"c":
                    attributes[k] = ConnectionData.froms(v)
                elif k == b"b":
                    attributes[k] = Bandwidth.froms(v)
                elif k == b"t":
                    attributes[k] = Timing.froms(v)
                elif k == b"r":
                    # ToDo: parse it
                    attributes[k] = v
                elif k == b"z":
                    # ToDo: parse it
                    attributes[k] = v
                elif k == b"a":
                    if attributes[b"m"] is None:
                        # append attribute to session
                        if attributes[k] is None:
                            attributes[k] = Attributes()
                        attributes[k].append(v)
                    else:
                        # append attribute to media
                        attributes[b"m"][-1].attributes.append(v)

                elif k == b"m":
                    if attributes[k] is None:
                        attributes[k] = []
                    attributes[k].append(Media.froms(v))

                elif k in cls._attributes_allowed:
                    attributes[k] = v
            except ValueError as error_msg:
                logger.warning("Can't parse sdp data: '{}':  {!s}".format(repr(line)[:128], error_msg))
                raise SdpParsingError()

        a = {}
        for k,v in attributes.items():
            a[k.decode('ascii')] = v
        return (data_length, a)

    def dumps(self):
        ret = []
        for k in self._attributes_allowed:
            v = self._attributes[k]
            if v == None:
                continue

            if type(v) != list and type(v) != Attributes:
                v = [v]

            for v2 in v:
                if type(v2) == int:
                    d = int2bytes(v2)
                elif type(v2) == bytes:
                    d = v2
                else:
                    d = v2.dumps()

                ret.append(b"=".join([k, d]))
                if k != b"m":
                    # continue with next value if it isn't a media
                    continue

                for attr in v2.attributes:
                    ret.append(b"=".join([b"a", attr.dumps()]))

        ret.append(b"")

        return b"\r\n".join(ret)

    def get(self, name):
        return self._attributes.get(name, None)


class Timing(object):
    """

    Format: t=<start-time> <stop-time>

    :See: http://tools.ietf.org/html/rfc4566#page-17
    """

    def __init__(self, start_time=None,stop_time=None):
        self.start_time = start_time
        self.stop_time = stop_time

    @classmethod
    def froms(cls,data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        start_time, stop_time = re.split(b" +", data, 1)
        start_time = int(start_time)
        stop_time = int(stop_time)
        return (len(data), {'start_time':start_time,'stop_time':stop_time})

    def dumps(self):
        return b" ".join([int2bytes(self.start_time), int2bytes(self.stop_time)])

if __name__ == '__main__':
    import doctest
    doctest.testmod()
