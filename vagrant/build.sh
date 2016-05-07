#!/bin/sh
autoreconf -vi
./configure \
	--disable-werror \
	--prefix=/opt/dionaea \
	--with-python=/usr/bin/python3 \
	--with-cython-dir=/usr/bin \
	--with-ev-include=/usr/include \
	--with-ev-lib=/usr/lib \
	--with-emu-lib=/usr/lib/libemu \
	--with-emu-include=/usr/include \
	--with-gc-include=/usr/include/gc \
	--enable-nl \
	--with-nl-include=/usr/include/libnl3 \
	--with-nl-lib=/usr/lib
make
sudo make install
