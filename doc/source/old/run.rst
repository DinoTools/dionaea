Running dionaea
===============

The software has some flags you can provide at startup, the -h flags
shows the help, the -H includes the default values.

  -c, --config=FILE               use FILE as configuration file
                                    Default value/behaviour: /opt/dionaea/etc/dionaea.conf
  -D, --daemonize                 run as daemon
  -g, --group=GROUP               switch to GROUP after startup (use with -u)
                                    Default value/behaviour: keep current group
  -G, --garbage=[collect|debug]   garbage collect,  usefull to debug memory leaks,
                                  does NOT work with valgrind
  -h, --help                      display help
  -H, --large-help                display help with default values
  -l, --log-levels=WHAT           which levels to log, valid values
                                  all, debug, info, message, warning, critical, error
                                  combine using ',', exclude with - prefix
  -L, --log-domains=WHAT          which domains use * and ? wildcards, combine using ',',
                                  exclude using -
  -u, --user=USER                 switch to USER after startup
                                    Default value/behaviour: keep current user
  -p, --pid-file=FILE             write pid to file
  -r, --chroot=DIR                chroot to DIR after startup
                                    Default value/behaviour: don't chroot
  -V, --version                   show version
  -w, --workingdir=DIR            set the process' working dir to DIR
                                    Default value/behaviour: /opt/dionaea

examples:

.. code-block:: console

    # dionaea -l all,-debug -L '*'
    # dionaea -l all,-debug -L 'con*,py*'
    # dionaea -u nobody -g nogroup -r /opt/dionaea/ -w /opt/dionaea -p /opt/dionaea/var/dionaea.pid
