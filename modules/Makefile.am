# $Id: Makefile.am 2463 2008-10-13 10:32:47Z common $

AUTOMAKE_OPTIONS = foreign

if BUILD_PYTHON_MODULE
python_dir = python 
endif

if BUILD_EMU_MODULE
emu_dir = emu
endif

if BUILD_CURL_MODULE
curl_dir = curl
endif

if BUILD_NL_MODULE
nl_dir = nl
endif

if BUILD_PCAP_MODULE
pcap_dir = pcap
endif

if BUILD_NFQ_MODULE
nfq_dir = nfq
endif


SUBDIRS = nc $(python_dir) $(emu_dir) $(curl_dir) $(nl_dir) $(pcap_dir) $(nfq_dir)
DIST_SUBDIRS = nc python emu curl nl pcap nfq
