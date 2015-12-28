Development
===========

dionaea initial development was funded by the Honeynet Project
<http://honeynet.org/> as part of the Honeynets Summer of Code during
2009. The development process is as open as possible; you can browse
<http://src.carnivore.it/dionaea> the source online and subscribe to RSS
updates <http://src.carnivore.it/dionaea/atom> and submit bugs or
patches <mailto:nepenthes-devel@lists.sourceforge.net>.


Compiling & Installation
------------------------


Requirements

  * libev <#install_libev> >=4.04, schmorp.de
    <http://software.schmorp.de/pkg/libev.html>
  * libglib <#install_glib> >=2.20
  * libssl <#install_openssl>, openssl.org <http://www.openssl.org>
  * liblcfg <#install_liblcfg>, liblcfg.carnivore.it
    <http://liblcfg.carnivore.it>
  * libemu <#install_libemu>, libemu.carnivore.it
    <http://libemu.carnivore.it>
  * python <#install_python> >=3.2, python.org <http://www.python.org>
  *
      o sqlite <#install_sqlite> >=3.3.6 sqlite.org <http://www.sqlite.org>
      o readline <#install_readline> >=3 cnswww.cns.cwru.edu
        <http://cnswww.cns.cwru.edu/php/chet/readline/rltop.html>
  * cython <#install_cython> >0.14.1, cython.org <http://www.cython.org>
  * libudns <#install_udns>, corpit.ru <http://www.corpit.ru/mjt/udns.html>
  * libcurl <#install_curl> >=7.18, curl.haxx.se <http://curl.haxx.se>
  * libpcap <#install_pcap> >=1.1.1, tcpdump.org <http://www.tcpdump.org>
  * libnl <#install_nl> from git, infradead.org
    <http://www.infradead.org/~tgr/libnl/> (optional)
  * libgc >=6.8, hp.com <http://linux.maruhn.com/sec/libgc.html> (optional)


Ubuntu
------

Some packages are provided by the apt-tree, so you don't have to install
everything from source

.. code-block:: console

    aptitude install libudns-dev libglib2.0-dev libssl-dev libcurl4-openssl-dev \
    libreadline-dev libsqlite3-dev python-dev \
    libtool automake autoconf build-essential \
    subversion git-core \
    flex bison \
    pkg-config


tar xfz ...
-----------

The remaining dependencies have to be installed from source, we will
install all dependencies to /opt/dionaea here, so make sure the
directory exists, and you are allowed to write it.


        libglib (debian <= etch)

If your lack a recent glib, better update your operating system.


        liblcfg (all)

git clone git://git.carnivore.it/liblcfg.git liblcfg
cd liblcfg/code
autoreconf -vi
./configure --prefix=/opt/dionaea
make install
cd ..
cd ..


        libemu (all)

git clone git://git.carnivore.it/libemu.git libemu
cd libemu
autoreconf -vi
./configure --prefix=/opt/dionaea
make install
cd ..


        libnl (linux && optional)

In case you use Ubuntu, libnl3 may be available in apt,

apt-get install libnl-3-dev libnl-genl-3-dev libnl-nf-3-dev libnl-route-3-dev


else install it from git.

git clone git://git.infradead.org/users/tgr/libnl.git
cd libnl
autoreconf -vi
export LDFLAGS=-Wl,-rpath,/opt/dionaea/lib
./configure --prefix=/opt/dionaea
make
make install
cd ..


        libev (all)

wget http://dist.schmorp.de/libev/Attic/libev-4.04.tar.gz
tar xfz libev-4.04.tar.gz
cd libev-4.04
./configure --prefix=/opt/dionaea
make install
cd ..


        Python 3.2

Before installing Python, we will install required dependencies


          readline

Should be available for every distribution.


          sqlite > 3.3

Should be available for every distribution. If your distributions sqlite
version is < 3.3 and does not support triggers, you are doomed, please
let me know, I'll write about how broken pythons build scripts are, and
document how to to compile it with a user- provided - more recent -
sqlite version.


          Python

wget http://www.python.org/ftp/python/3.2.2/Python-3.2.2.tgz
tar xfz Python-3.2.2.tgz
cd Python-3.2.2/
./configure --enable-shared --prefix=/opt/dionaea --with-computed-gotos \
      --enable-ipv6 LDFLAGS="-Wl,-rpath=/opt/dionaea/lib/ -L/usr/lib/x86_64-linux-gnu/"

make
make install


        Cython (all)

We have to use cython >= 0.15 as previous releases do not support
Python3.2 __hash__'s Py_Hash_type for x86.

wget http://cython.org/release/Cython-0.15.tar.gz
tar xfz Cython-0.15.tar.gz
cd Cython-0.15
/opt/dionaea/bin/python3 setup.py install
cd ..


        udns (!ubuntu)

udns does not use autotools to build.

wget http://www.corpit.ru/mjt/udns/old/udns_0.0.9.tar.gz
tar xfz udns_0.0.9.tar.gz
cd udns-0.0.9/
./configure
make shared

There is no make install, so we copy the header to our include directory.

 cp udns.h /opt/dionaea/include/

and the lib to our library directory.

 cp *.so* /opt/dionaea/lib/
cd /opt/dionaea/lib
ln -s libudns.so.0 libudns.so
cd -
cd ..


        libcurl (all)

Grabbing curl from your distributions maintainer should work, if you run
a decent distribution. If not consider upgrading your operating system.


        libpcap (most)

To honor the effort, we rely on libpcap 1.1.1. Most distros ship older
versions, therefore it is likely you have to install it from source.

wget http://www.tcpdump.org/release/libpcap-1.1.1.tar.gz
tar xfz libpcap-1.1.1.tar.gz
cd libpcap-1.1.1
./configure --prefix=/opt/dionaea
make
make install
cd ..


        OpenSSL (optional)

*WARNING:* doing this, requires *all* dependencies to be compiled using
the same ssl version, so you have to link curl and python to your own
openssl build too
If you experience problems with tls connections, install your OpenSSL >=
0.9.8l/1.0.0-beta2, or fall back to cvs for now.

cvs -d anonymous@cvs.openssl.org:/openssl-cvs co openssl
cd openssl
./Configure shared --prefix=/opt/dionaea linux-x86_64
make SHARED_LDFLAGS=-Wl,-rpath,/opt/dionaea/lib
make install


      Compiling dionaea

git clone git://git.carnivore.it/dionaea.git dionaea

then ..

cd dionaea
autoreconf -vi
./configure --with-lcfg-include=/opt/dionaea/include/ \
      --with-lcfg-lib=/opt/dionaea/lib/ \
      --with-python=/opt/dionaea/bin/python3.2 \
      --with-cython-dir=/opt/dionaea/bin \
      --with-udns-include=/opt/dionaea/include/ \
      --with-udns-lib=/opt/dionaea/lib/ \
      --with-emu-include=/opt/dionaea/include/ \
      --with-emu-lib=/opt/dionaea/lib/ \
      --with-gc-include=/usr/include/gc \
      --with-ev-include=/opt/dionaea/include \
      --with-ev-lib=/opt/dionaea/lib \
      --with-nl-include=/opt/dionaea/include \
      --with-nl-lib=/opt/dionaea/lib/ \
      --with-curl-config=/usr/bin/ \
      --with-pcap-include=/opt/dionaea/include \
      --with-pcap-lib=/opt/dionaea/lib/
make
make install

    Update dionaea

Most updates boil down to a

git pull;
make clean install

But, you always want to make sure your config file is up to date, you
can use

/opt/dionaea/etc/dionaea# diff dionaea.conf dionaea.conf.dist
