AUTOMAKE_OPTIONS = foreign

AM_CFLAGS = -I../include -I .. -fno-strict-aliasing -Wall -Werror -g
AM_LDFLAGS = 


bin_PROGRAMS = dionaea


dionaea_CFLAGS  = ${LIB_EV_CFLAGS} ${LIB_GLIB_CFLAGS} ${LIB_LCFG_CFLAGS}   
dionaea_LDFLAGS = ${LIB_EV_LIBS}   ${LIB_GLIB_LIBS}   ${LIB_LCFG_LIBS}     

dionaea_CFLAGS  += ${LIB_SSL_CFLAGS} ${LIB_EMU_CFLAGS} ${LIB_UDNS_CFLAGS}
dionaea_LDFLAGS += ${LIB_SSL_LIBS}   ${LIB_EMU_LIBS}   ${LIB_UDNS_LIBS}  

dionaea_CFLAGS  += ${AM_CFLAGS} 
dionaea_LDFLAGS += ${AM_LDFLAGS}


dionaea_SOURCES = dionaea.c

