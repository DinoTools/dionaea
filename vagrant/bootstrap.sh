#!/bin/sh

export DEBIAN_FRONTEND noninteractive
sudo apt-get update
sudo apt-get install -y \
    autoconf \
    automake \
    check \
    cython3 \
    libcurl4-openssl-dev \
    libemu-dev \
    libev-dev \
    libglib2.0-dev \
    libloudmouth1-dev \
    libnetfilter-queue-dev \
    libnl-dev \
    libpcap-dev \
    libreadline-dev \
    libsqlite3-dev \
    libssl-dev \
    libtool \
    libudns-dev \
    libxml2-dev \
    libxslt1-dev \
    python3 \
    python3-dev \
    python3-yaml

# Prepare and install dionaea
cd /vagrant && bash /vagrant/vagrant/build.sh
