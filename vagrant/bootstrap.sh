#!/bin/sh
DATADIR=/var/lib/dionaea
LOGDIR=/var/log/dionaea

export DEBIAN_FRONTEND noninteractive
sudo apt-get install software-properties-common
#sudo add-apt-repository ppa:honeynet/nightly
sudo apt-get update
sudo apt-get install -y autoconf automake libtool check libglib2.0-dev libssl-dev libcurl4-openssl-dev libudns-dev libreadline-dev libsqlite3-dev libemu-dev cython3 libxml2-dev libxslt1-dev libpcap-dev libev-dev python3 python3-dev libnl-dev libnetfilter-queue-dev libgc-dev libloudmouth1-dev

sudo mkdir -p $DATADIR/binaries
sudo mkdir -p $DATADIR/bistreams
sudo mkdir -p $DATADIR/rtp
sudo mkdir -p $DATADIR/wwwroot

sudo mkdir -p $LOGDIR

# create user and group
sudo adduser --system --group --home $DATADIR --no-create-home --quiet dionaea || true

# ensure that dionaea can create files after dropping privileges
sudo chown -R dionaea:dionaea $DATADIR
sudo chown -R dionaea:dionaea $LOGDIR

# Install config
sudo mkdir -p /etc/dionaea/
sudo cp /vagrant/conf/dionaea.conf.dist /etc/dionaea/dionaea.conf

# Fix config
sudo sed -i 's:"var/dionaea/:"/var/lib/dionaea/:g' /etc/dionaea/dionaea.conf
sudo sed -i 's:"log/:"/var/log/dionaea/:g' /etc/dionaea/dionaea.conf


# Prepare and install dionaea
cd /vagrant && bash /vagrant/vagrant/build.sh

# Copy init script
sudo cp /vagrant/vagrant/dionaea.init /etc/init.d/dionaea

# Enable service
sudo update-rc.d dionaea defaults

# Start dionaea service
sudo service dionaea start

