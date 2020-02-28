FROM ubuntu:18.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y --no-install-recommends \
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
      libnl-3-dev \
      libpcap-dev \
      libssl-dev \
      libtool \
      libudns-dev \
      python3 \
      python3-dev \
      python3-bson \
      python3-yaml \
      python3-boto3 \
      fonts-liberation

RUN apt-get install -y --no-install-recommends \
      gdbserver \
      inotify-tools \
      supervisor

CMD bash -c '/code/dev/docker/dionaea/init.sh && /usr/bin/supervisord -n'
