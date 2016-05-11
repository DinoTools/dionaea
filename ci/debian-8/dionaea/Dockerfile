FROM debian:8
ENV DEBIAN_FRONTEND noninteractive

# Speedup
RUN echo 'force-unsafe-io' | tee /etc/dpkg/dpkg.cfg.d/02apt-speedup && \
    echo 'DPkg::Post-Invoke {"/bin/rm -f /var/cache/apt/archives/*.deb || true";};' | tee /etc/apt/apt.conf.d/no-cache && \
    echo 'Acquire::http {No-Cache=True;};' | tee /etc/apt/apt.conf.d/no-http-cache

RUN apt-get update && \
    apt-get install -y \
        autoconf \
        automake \
        build-essential \
        check \
        cython3 \
        libcurl4-openssl-dev \
        libemu-dev \
        libev-dev \
        libgc-dev \
        libglib2.0-dev \
        libloudmouth1-dev \
        libnetfilter-queue-dev \
        libnl-3-dev \
        libpcap-dev \
        libssl-dev \
        libtool \
        libudns-dev \
        python3 \
        python3-dev \
        python3-yaml \
        && \
    apt-get clean

COPY . /code
RUN cd /code && \
    autoreconf -vi && \
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
        --with-nl-lib=/usr/lib && \
     make && \
     make install
