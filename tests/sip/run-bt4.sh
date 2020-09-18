#!/bin/bash
# Set some environment vars for backtrack 4

export TOOL_SMAP=/pentest/voip/smap/smap
export TOOL_SMAP_BASE=/pentest/voip/smap

./run-tests.sh $@
