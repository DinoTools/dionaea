#!/bin/bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2011 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Set some environment vars for backtrack 4

export TOOL_SMAP=/pentest/voip/smap/smap
export TOOL_SMAP_BASE=/pentest/voip/smap

./run-tests.sh $@
