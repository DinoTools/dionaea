# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

FROM ubuntu:18.04

ARG DEBIAN_FRONTEND=noninteractive

COPY . /code

RUN apt-get update && \
      # Install build deps
      apt-get install -y --no-install-recommends \
            build-essential \
            cmake \
            check \
            cython3 \
            libcurl4-openssl-dev \
            libemu-dev \
            libev-dev \
            libglib2.0-dev \
            libloudmouth1-dev \
            libnetfilter-queue-dev \
            libpcap-dev \
            libssl-dev \
            libtool \
            libudns-dev \
            python3 \
            python3-dev \
            python3-bson \
            python3-yaml \
            python3-boto3 \
            fonts-liberation && \
      # Build
      mkdir -p /code/build && \
      cd /code/build && \
      cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea /code && \
      make && \
      make install && \
      # Create user and group
      addgroup --gid 1000 dionaea && \
      adduser --system --no-create-home --shell /bin/bash --uid 1000 --disabled-password --disabled-login --gid 1000 dionaea && \
      # Set permissions
      chown -R dionaea:dionaea /opt/dionaea/var && \
      # Prepare additional stuff
      cp /code/docker/entrypoint.sh /usr/local/sbin/entrypoint.sh && \
      mkdir -p /opt/dionaea/template && \
      (cd /opt/dionaea && mv var/lib template/ && mv var/log template/ && mv etc template/) && \
      # Remove dev packages
      apt-get purge -y \
            build-essential \
            cmake \
            check \
            cython3 \
            libcurl4-openssl-dev \
            libemu-dev \
            libev-dev \
            libglib2.0-dev \
            libloudmouth1-dev \
            libnetfilter-queue-dev \
            libpcap-dev \
            libssl-dev \
            libtool \
            libudns-dev \
            python3-dev  && \
      # Install required packages
      apt-get install -y --no-install-recommends \
            ca-certificates \
            libcurl4 \
            libemu2 \
            libev4 \
            libglib2.0-0 \
            libnetfilter-queue1 \
            libpcap0.8 \
            libpython3.6 \
            libudns0 && \
      # Clean up
      apt-get autoremove --purge -y && \
      apt-get clean && \
      rm -rf /code/ /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]
