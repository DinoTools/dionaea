#!/bin/bash

OS_NAME=$1
OS_VERSION=$2

if [ $# -ne 2 ]; then
    echo "$0 <OS_NAME> <OS_VERSION>"
    exit 1
fi

BASE_PATH="`dirname \"$0\"`"
BASE_PATH="`( cd \"$BASE_PATH\" && pwd )`"
if [ -z "$BASE_PATH" ] ; then
  exit 1
fi
echo "Base path: $BASE_PATH"

CFG_PATH="$BASE_PATH/$OS_NAME-$OS_VERSION"
if [ ! -d "$CFG_PATH" ]; then
    echo "Path '$CFG_PATH' not found"
    exit 1
fi

cd $CFG_PATH

docker-compose up --force-recreate
RET=$?
docker-compose kill
docker-compose down --rmi local
exit $RET
