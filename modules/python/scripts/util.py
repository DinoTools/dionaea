import sys
import hashlib

def md5file(filename):
	return hashfile(filename, hashlib.md5())

def sha512file(filename):
	return hashfile(filename, hashlib.sha512())

def hashfile(filename, digest):
    fh = open(filename, mode="rb")
    while 1:
        buf = fh.read(4096)
        if len(buf) == 0:
            break
        digest.update(buf)
    fh.close()
    return digest.hexdigest()

