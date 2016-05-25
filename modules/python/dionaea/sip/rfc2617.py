"""
RFC2617

:See: http://tools.ietf.org/html/rfc2617

"""

import hashlib
import re


def quote(data):
    """
    Quote a string
    >>> print(quote(b'test'), quote(b'"test'), quote(b'test"'), quote(b'"test"'))
    b'"test"' b'"test"' b'"test"' b'"test"'
    """
    if type(data) == str:
        data = bytes(data, "utf-8")

    data = data.strip()
    if data[0] != 34: # ASCII Code 34 = "
        data = b'"' + data

    if data[-1] != 34:
        data = data + b'"'

    return data


def unquote(data):
    """
    Unquote a string
    >>> print(unquote(b'test'), unquote(b'"test'), unquote(b'test"'), unquote(b'"test"'))
    b'test' b'test' b'test' b'test'
    """
    if type(data) == str:
        data = bytes(data, "utf-8")

    data = data.strip()
    if data[0] == 34: # ASCII Code 34 = "
        data = data[1:]

    if data[-1] == 34:
        data = data[:-1]

    return data


class Authentication(object):
    """
    >>> a = Authentication(method = "basic", realm = "test")
    >>> print(a.dumps())
    b'Basic realm="test"'
    >>> a = Authentication(method = "digest", realm = "test", domain = "example.org", algorithm = "md5", nonce = "abcd")
    >>> print(a.dumps())
    b'Digest realm="test", domain="example.org", algorithm=MD5, nonce="abcd"'
    >>> a = Authentication.froms(b'Digest realm="test", algorithm="MD5", nonce="efgh", domain="example.org"')
    >>> print(a.method, a.algorithm, a.domain, a.nonce, a.realm)
    b'digest' b'MD5' b'example.org' b'efgh' b'test'
    """
    _quote = ["realm", "domain", "nonce", "response", "uri"]
    _noquote = ["algorithm"]

    def __init__(self, method = "basic", realm = None, domain = None, algorithm = None, nonce = None, response = None, uri = None):
        self.method = method
        self.realm = realm
        self.domain = domain
        self.algorithm = algorithm
        self.nonce = nonce
        self.response = response
        self.uri = uri

    def check(self, username, password, method, auth):
        digest = create_digest(
            algorithm="md5",
            method=method,
            nonce=self.nonce,
            password=password,
            realm=self.realm,
            uri=auth.uri,
            username=username
        )

        if digest == auth.response:
            return True

        return False

    def dumps(self):
        if self.method == "digest":
            ret = []
            for n in ["realm", "domain", "uri", "algorithm", "nonce", "response"]:
                v = getattr(self, n)
                if v is None:
                    continue

                if n == "algorithm":
                    v = v.upper()

                if n in self._quote:
                    v = quote(v)

                if n in self._noquote:
                    v = unquote(v)

                ret.append(bytes(n, "utf-8") + b"=" + v)

            return b"Digest " + b", ".join(ret)

        return b"Basic realm=" + quote(self.realm)

    @classmethod
    def froms(cls, data):
        return cls(**cls.loads(data)[1])

    @classmethod
    def loads(cls, data):
        l = len(data)
        if type(data) == str:
            data = bytes(data, "utf-8")

        method, data = re.split(b" *", data, 1)
        ret = {
            "method": method.lower()
        }

        for part in re.split(b" *, *", data):
            n, s, v = part.partition(b"=")
            n = n.decode("utf-8")
            if n in cls._quote:
                ret[n] = unquote(v)
            if n in cls._noquote:
                # this values shouldn't be quoted, but nevertheless some clients do it
                ret[n] = unquote(v)

        return (l, ret)

# :See: http://tools.ietf.org/html/rfc2617#page-10
H = lambda d: bytes(hashlib.md5(d).hexdigest(), "utf-8")
KD = lambda secret, data: H(secret + b":" + data)


def create_digest(algorithm = None, cnonce = None, method = None, nonce = None, password = None, realm = None, uri = None, username = None):
    """
    >>> print(create_digest(algorithm = "md5", method = "REGISTER", nonce = "foobar", password = "secret", realm = "sip-server", uri = "sip:sip-server", username = "alice"))
    b'8b30552864468e5e6ab1eb2b87d1b92f'
    """
    if type(algorithm) == str:
        algorithm = bytes(algorithm, "utf-8")
    if type(cnonce) == str:
        cnonce = bytes(cnonce, "utf-8")
    if type(method) == str:
        method = bytes(method, "utf-8")
    if type(nonce) == str:
        nonce = bytes(nonce, "utf-8")
    if type(password) == str:
        password = bytes(password, "utf-8")
    if type(realm) == str:
        realm = bytes(realm, "utf-8")
    if type(uri) == str:
        uri = bytes(uri, "utf-8")
    if type(username) == str:
        username = bytes(username, "utf-8")

    # :See: http://tools.ietf.org/html/rfc2617#page-13
    if algorithm and algorithm.lower() == 'md5-sess':
        A1 = H(username + b":" + realm + b":" + password) + b":" + nonce + b":" + cnonce
    else:
        A1 = username + b":" + realm + b":" + password

    A2 = method + b":" + uri

    return KD(H(A1), nonce + b":" + H(A2))

if __name__ == '__main__':
    import doctest
    doctest.testmod()
