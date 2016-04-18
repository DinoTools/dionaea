Modules
=======

The subsections name is the name of the module dionaea will try to load,
most modules got rather simplistic names, the pcap module will use
libpcap, the curl module libcurl, the emu module libemu ...
The python module is special, as the python module can load python
scripts, which offer services, and each services can have its own options.

List of available modules

.. toctree::
    :maxdepth: 2

    curl
    emu
    pcap
    python
