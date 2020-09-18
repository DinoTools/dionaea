#!/bin/bash
# Set some environment vars for backtrack 5

export TOOL_SMAP=/pentest/voip/smap/smap
export TOOL_SMAP_BASE=/pentest/voip/smap
export TOOL_SIPP=/pentest/voip/sipp/sipp

./run-tests.sh $@
