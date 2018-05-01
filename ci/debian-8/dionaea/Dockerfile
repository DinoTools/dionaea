FROM debian:8
ENV DEBIAN_FRONTEND noninteractive

# Speedup
RUN echo 'force-unsafe-io' | tee /etc/dpkg/dpkg.cfg.d/02apt-speedup && \
    echo 'DPkg::Post-Invoke {"/bin/rm -f /var/cache/apt/archives/*.deb || true";};' | tee /etc/apt/apt.conf.d/no-cache && \
    echo 'Acquire::http {No-Cache=True;};' | tee /etc/apt/apt.conf.d/no-http-cache

# We need backport repo to get recent cmake version
RUN echo "deb http://httpredir.debian.org/debian jessie-backports main non-free" > /etc/apt/sources.list.d/backports.list && \
    echo "deb-src http://httpredir.debian.org/debian jessie-backports main non-free" >> /etc/apt/sources.list.d/backports.list && \
    apt-get update && \
    apt-get install -y \
        build-essential \
        check \
        cython3 \
        libcurl4-openssl-dev \
        libemu-dev \
        libev-dev \
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
    apt-get -t jessie-backports install -y cmake && \
    apt-get clean

COPY . /code
RUN cd /code && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea .. && \
    make && \
    make install
