AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -I../include -I .. -fno-strict-aliasing -Wall -Werror -g
AM_LDFLAGS = 


bin_PROGRAMS = dionaea


dionaea_CFLAGS  = ${LIB_EV_CFLAGS} ${LIB_GLIB_CFLAGS} ${LIB_LCFG_CFLAGS}   
dionaea_LDFLAGS = ${LIB_EV_LIBS}   ${LIB_GLIB_LIBS}   ${LIB_LCFG_LIBS}     

dionaea_CFLAGS  += ${LIB_SSL_CFLAGS} ${LIB_UDNS_CFLAGS} ${LIB_GC_CFLAGS}
dionaea_LDFLAGS += ${LIB_SSL_LIBS}   ${LIB_UDNS_LIBS}   ${LIB_GC_LIBS}  

dionaea_CFLAGS  += ${AM_CFLAGS} 
dionaea_LDFLAGS += ${AM_LDFLAGS}


dionaea_SOURCES = dionaea.c
dionaea_SOURCES += dns.c
dionaea_SOURCES += refcount.c
dionaea_SOURCES += node_info.c
dionaea_SOURCES += util.c
dionaea_SOURCES += connection.c
dionaea_SOURCES += modules.c
dionaea_SOURCES += pchild.c
dionaea_SOURCES += log.c
dionaea_SOURCES += signals.c
dionaea_SOURCES += incident.c
