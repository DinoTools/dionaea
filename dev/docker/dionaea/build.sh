#!/bin/sh
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2020 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

mkdir -p /build && \
cd /build && \
cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea /code && \
make && \
make install
exit $?
