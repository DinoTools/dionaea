import sys
import hashlib

def md5file(filename):
    fh = open(filename, mode="rb")
    digest = hashlib.md5()
    while 1:
        buf = fh.read(4096)
        if len(buf) == 0:
            break
        digest.update(buf)
    fh.close()
    return digest.hexdigest()

