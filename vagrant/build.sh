#!/bin/sh
autoreconf -vi
./configure \
	--disable-werror \
	--prefix=/usr \
	--with-python=/usr/bin/python3 \
	--with-cython-dir=/usr/bin \
	--with-lcfg-include=/usr/include \
	--with-lcfg-lib=/usr/lib/liblcfg \
	--with-ev-include=/usr/include \
	--with-ev-lib=/usr/lib \
	--with-emu-lib=/usr/lib/libemu \
	--with-emu-include=/usr/include \
	--with-gc-include=/usr/include/gc \
	--with-nl-include=/usr/include \
	--with-nl-lib=/usr/lib
make
sudo make install

