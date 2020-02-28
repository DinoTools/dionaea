#!/bin/sh
SRC_DIR=$(dirname $0)
test ! -d /opt/dionaea && (${SRC_DIR}/build.sh || exit 1)
find /etc/supervisor/conf.d/ -type f -name '*.conf' -exec rm {} \;
cp ${SRC_DIR}/supervisor/*.conf /etc/supervisor/conf.d/
if [ "$DIONAEA_BUILD_ENV" != "" ]; then
  cp ${SRC_DIR}/supervisor.${DIONAEA_BUILD_ENV}/*.conf /etc/supervisor/conf.d/
fi
