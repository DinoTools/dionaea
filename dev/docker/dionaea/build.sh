#!/bin/sh
mkdir -p /build && \
cd /build && \
cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea /code && \
make && \
make install
exit $?
