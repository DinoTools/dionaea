# -*- mode: m4; -*-
# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# $Id$

sinclude(m4/az_python.m4)
sinclude(m4/az_bind_ipv4_mapped_localhost.m4)

AC_PREREQ(2.59)
AC_INIT([dionaea], [0.1.0], [nepenthesdev@gmail.com])
AM_INIT_AUTOMAKE([dionaea], [0.1.0])
AC_REVISION([$Id$])

AC_PREFIX_DEFAULT(/opt/dionaea)
AC_CONFIG_SRCDIR([include/dionaea.h])
AC_CONFIG_HEADERS([config.h])
# AM_MAINTAINER_MODE

CFLAGS="${CFLAGS} -std=c99 -D_GNU_SOURCE"

AC_CANONICAL_HOST
AC_C_CONST
AC_C_BIGENDIAN

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

AC_CHECK_HEADERS([stdint.h stdlib.h string.h strings.h unistd.h netpacket/packet.h execinfo.h linux/sockios.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_UID_T
AC_STRUCT_TM
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([strndup inet_ntoa  memmove memset strdup strerror])

# Check for pkg-config program
m4_define_default([PKG_PROG_PKG_CONFIG], [AC_MSG_CHECKING([pkg-config]) AC_MSG_RESULT([no])])

PKG_PROG_PKG_CONFIG

# If the pkg-config autoconf support isn't installed, just ignore all packages
m4_define_default([PKG_CHECK_MODULES], [AC_MSG_CHECKING([$1]) AC_MSG_RESULT([no]) $4])

dnl **************************************************
dnl * bind() ipv4 mapped address?                    *
dnl **************************************************

AC_ARG_ENABLE(ev, [  --enable-ipv4-mapped      map ipv4 addresses to ipv6 f.e. ::fff:0.0.0.0],
			[enable_ipv4_mapped="$enableval"],[enable_ipv4_mapped="no"])

AZ_FUNC_BIND_MAPPED_IPV4_LOCALHOST()

if test x$enable_ipv4_mapped == "xyes"; then
	if test x$ac_cv_have_bind_ipv4_mapped_localhost == "xyes"; then
	  AC_DEFINE(BIND_IPV4_MAPPED_LOCALHOST, 1, "your bind can bind mapped ipv4 localhost to an ipv6 socket")
	fi
fi

dnl **************************************************
dnl * libev                                          *
dnl **************************************************

AC_SUBST([LIB_EV_CFLAGS])
AC_SUBST([LIB_EV_LIBS])


enable_ev="yes"

AC_ARG_ENABLE(ev, [  --enable-ev      enable support for libev],
			[enable_ev="$enableval"],[enable_ev="yes"])

AC_ARG_WITH(ev-include,
			[  --with-ev-include=DIR  libev include dir],
				      [ev_inc="$withval"],[ev_inc=no])
AC_ARG_WITH(ev-lib,
			[  --with-ev-lib=DIR  libev library dir],
			[ev_lib="$withval"],[ev_lib=no])


if test x$enable_ev = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$ev_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${ev_inc}"
	fi
	
	AC_CHECK_HEADER(ev.h,[enable_ev=yes],[enable_ev=no])
	
	if test x$enable_ev = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$ev_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${ev_lib}"
		fi
	
		AC_CHECK_LIB([ev],[ev_run],enable_ev="yes", enable_ev="no")
	
		if test x$enable_ev = "xyes" ; then
			if test x$ev_lib != "xno"; then
				LIB_EV_LIBS="-L$ev_lib -lev"
			else
				LIB_EV_LIBS="-lev"
			fi
			if test x$ev_inc != "xno"; then
				LIB_EV_CFLAGS="-I$ev_inc"
			else
				LIB_EV_CFLAGS=""
			fi
			LIB_EV_CFLAGS="${LIB_EV_CFLAGS} -DEV_COMPAT3=0"
			AC_DEFINE([HAVE_LIBEV], [1], [Define to 1 to compile with ev support])
		fi
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi


dnl **************************************************
dnl * libemu                                         *
dnl **************************************************

AC_SUBST([LIB_EMU_CFLAGS])
AC_SUBST([LIB_EMU_LIBS])


enable_emu="yes"

AC_ARG_ENABLE(emu, [  --enable-emu      enable support for libemu],
			[enable_emu="$enableval"],[enable_emu="yes"])

AC_ARG_WITH(emu-include,
			[  --with-emu-include=DIR  libemu include dir],
				      [emu_inc="$withval"],[emu_inc=no])
AC_ARG_WITH(emu-lib,
			[  --with-emu-lib=DIR  libemu library dir],
			[emu_lib="$withval"],[emu_lib=no])


if test x$enable_emu = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$emu_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${emu_inc}"
	fi
	
	AC_CHECK_HEADER(emu/emu.h,[enable_emu=yes],[enable_emu=no])
	
	if test x$enable_emu = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$emu_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${emu_lib}"
		fi
	
		AC_CHECK_LIB([emu],[emu_new],enable_emu="yes", enable_emu="no")
	
		if test x$enable_emu = "xyes" ; then
			if test x$emu_lib != "xno"; then
				LIB_EMU_LIBS="-L$emu_lib -lemu"
			else
				LIB_EMU_LIBS="-lemu"
			fi
			if test x$emu_inc != "xno"; then
				LIB_EMU_CFLAGS="-I$emu_inc"
			else
				LIB_EMU_CFLAGS=""
			fi
			AC_DEFINE([HAVE_LIBEMU], [1], [Define to 1 to compile with emu support])
		fi
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi


dnl **************************************************
dnl * libcspm                                         *
dnl **************************************************

AC_SUBST([LIB_CSPM_CFLAGS])
AC_SUBST([LIB_CSPM_LIBS])


enable_cspm="yes"

AC_ARG_ENABLE(cspm, [  --enable-cspm      enable support for libcspm],
			[enable_cspm="$enableval"],[enable_cspm="yes"])

AC_ARG_WITH(cspm-include,
			[  --with-cspm-include=DIR  libcspm include dir],
				      [cspm_inc="$withval"],[cspm_inc=no])
AC_ARG_WITH(cspm-lib,
			[  --with-cspm-lib=DIR  libcspm library dir],
			[cspm_lib="$withval"],[cspm_lib=no])


if test x$enable_cspm = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$cspm_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${cspm_inc}"
	fi
	
	AC_CHECK_HEADER(cspm/cspm.h,[enable_cspm=yes],[enable_cspm=no])
	
	if test x$enable_cspm = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$cspm_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${cspm_lib}"
		fi
	
		AC_CHECK_LIB([cspm],[cspm_new],enable_cspm="yes", enable_cspm="no")
	
		if test x$enable_cspm = "xyes" ; then
			if test x$cspm_lib != "xno"; then
				LIB_CSPM_LIBS="-L$cspm_lib -lcspm"
			else
				LIB_CSPM_LIBS="-lcspm"
			fi
			if test x$cspm_inc != "xno"; then
				LIB_CSPM_CFLAGS="-I$cspm_inc"
			else
				LIB_CSPM_CFLAGS=""
			fi
			AC_DEFINE([HAVE_LIBCSPM], [1], [Define to 1 to compile with cspm support])
		fi
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi


dnl **************************************************
dnl * libudns                                         *
dnl **************************************************

AC_SUBST([LIB_UDNS_CFLAGS])
AC_SUBST([LIB_UDNS_LIBS])


enable_udns="yes"

AC_ARG_ENABLE(udns, [  --enable-udns      enable support for libudns],
			[enable_udns="$enableval"],[enable_udns="yes"])

AC_ARG_WITH(udns-include,
			[  --with-udns-include=DIR  libudns include dir],
				      [udns_inc="$withval"],[udns_inc=no])
AC_ARG_WITH(udns-lib,
			[  --with-udns-lib=DIR  libudns library dir],
			[udns_lib="$withval"],[udns_lib=no])


if test x$enable_udns = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$udns_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${udns_inc}"
	fi
	
	AC_CHECK_HEADER(udns.h,[enable_udns=yes],[enable_udns=no])
	
	if test x$enable_udns = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$udns_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${udns_lib}"
		fi
	
		AC_CHECK_LIB([udns],[dns_submit_p],enable_udns="yes", enable_udns="no")
	
		if test x$enable_udns = "xyes" ; then
			if test x$udns_lib != "xno"; then
				LIB_UDNS_LIBS="-L$udns_lib -ludns"
			else
				LIB_UDNS_LIBS="-ludns"
			fi
			if test x$udns_inc != "xno"; then
				LIB_UDNS_CFLAGS="-I$udns_inc"
			else
				LIB_UDNS_CFLAGS=""
			fi
			AC_DEFINE([HAVE_LIBUDNS], [1], [Define to 1 to compile with udns support])
		fi
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi

dnl **************************************************
dnl * libgc                                         *
dnl **************************************************

AC_SUBST([LIB_GC_CFLAGS])
AC_SUBST([LIB_GC_LIBS])


enable_gc="yes"

AC_ARG_ENABLE(gc, [  --enable-gc      enable support for libgc],
			[enable_gc="$enableval"],[enable_gc="yes"])

AC_ARG_WITH(gc-include,
			[  --with-gc-include=DIR  libgc include dir],
				      [gc_inc="$withval"],[gc_inc=no])
AC_ARG_WITH(gc-lib,
			[  --with-gc-lib=DIR  libgc library dir],
			[gc_lib="$withval"],[gc_lib=no])


if test x$enable_gc = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$gc_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${gc_inc}"
	fi
	
	AC_CHECK_HEADER(gc.h,[enable_gc=yes],[enable_gc=no])
	
	if test x$enable_gc = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$gc_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${gc_lib}"
		fi
	
		AC_CHECK_LIB([gc],[GC_gcollect],enable_gc="yes", enable_gc="no")
	
		if test x$enable_gc = "xyes" ; then
			if test x$gc_lib != "xno"; then
				LIB_GC_LIBS="-L$gc_lib -lgc"
			else
				LIB_GC_LIBS="-lgc"
			fi
			if test x$gc_inc != "xno"; then
				LIB_GC_CFLAGS="-I$gc_inc"
			else
				LIB_GC_CFLAGS=""
			fi
			AC_DEFINE([HAVE_LIBGC], [1], [Define to 1 to compile with gc support])
		fi
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi

dnl **************************************************
dnl * libssl                                          *
dnl **************************************************


AC_SUBST([LIB_SSL_CFLAGS])
AC_SUBST([LIB_SSL_LIBS])


enable_ssl="yes"

AC_ARG_ENABLE(ssl, [  --enable-ssl      enable support for libssl],
			[enable_ssl="$enableval"],[enable_ssl="yes"])

AC_ARG_WITH(ssl-include,
			[  --with-ssl-include=DIR  libssl include dir],
				      [ssl_inc="$withval"],[ssl_inc=no])
AC_ARG_WITH(ssl-lib,
			[  --with-ssl-lib=DIR  libssl library dir],
			[ssl_lib="$withval"],[ssl_lib=no])


if test x$enable_ssl = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$ssl_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${ssl_inc}"
	fi
	
	AC_CHECK_HEADER(openssl/ssl.h,[enable_ssl=yes],[enable_ssl=no])
	
	if test x$enable_ssl = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$ssl_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${ssl_lib}"
		fi
	
		if test x$ssl_lib != "xno"; then
			LIB_SSL_LIBS="-L$ssl_lib -lssl -lcrypto"
		else
			LIB_SSL_LIBS="-lssl -lcrypto"
		fi
		if test x$ssl_inc != "xno"; then
			LIB_SSL_CFLAGS="-I$ssl_inc"
		else
			LIB_SSL_CFLAGS=""
		fi
		AC_DEFINE([HAVE_LIBSSL], [1], [Define to 1 to compile with ssl support])
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi

dnl **************************************************
dnl * libpcap                                        *
dnl **************************************************


AC_SUBST([LIB_PCAP_CFLAGS])
AC_SUBST([LIB_PCAP_LIBS])


enable_pcap="yes"

AC_ARG_ENABLE(pcap, [  --enable-pcap      enable support for libpcap],
			[enable_pcap="$enableval"],[enable_pcap="yes"])

AC_ARG_WITH(pcap-include,
			[  --with-pcap-include=DIR  libpcap include dir],
				      [pcap_inc="$withval"],[pcap_inc=no])
AC_ARG_WITH(pcap-lib,
			[  --with-pcap-lib=DIR  libpcap library dir],
			[pcap_lib="$withval"],[pcap_lib=no])


if test x$enable_pcap = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$pcap_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${pcap_inc}"
	fi
	
	AC_CHECK_HEADER(pcap/sll.h,[enable_pcap=yes],[enable_pcap=no])
	
	if test x$enable_pcap = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$pcap_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${pcap_lib}"
		fi
	
		AC_CHECK_LIB([pcap],[pcap_open_live],enable_pcap="yes", enable_pcap="no")
	
		if test x$enable_pcap = "xyes" ; then
			if test x$pcap_lib != "xno"; then
				LIB_PCAP_LIBS="-L$pcap_lib -lpcap"
			else
				LIB_PCAP_LIBS="-lpcap"
			fi
			if test x$pcap_inc != "xno"; then
				LIB_PCAP_CFLAGS="-I$pcap_inc"
			else
				LIB_PCAP_CFLAGS=""
			fi
			AC_DEFINE([HAVE_LIBPCAP], [1], [Define to 1 to compile with pcap support])
		fi
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi

dnl **************************************************
dnl * libnetfilter_queue                                        *
dnl **************************************************


AC_SUBST([LIB_NETFILTER_QUEUE_CFLAGS])
AC_SUBST([LIB_NETFILTER_QUEUE_LIBS])


enable_netfilter_queue="yes"

AC_ARG_ENABLE(netfilter_queue, [  --enable-netfilter_queue      enable support for libnetfilter_queue],
			[enable_netfilter_queue="$enableval"],[enable_netfilter_queue="yes"])

AC_ARG_WITH(netfilter_queue-include,
			[  --with-netfilter_queue-include=DIR  libnetfilter_queue include dir],
				      [netfilter_queue_inc="$withval"],[netfilter_queue_inc=no])
AC_ARG_WITH(netfilter_queue-lib,
			[  --with-netfilter_queue-lib=DIR  libnetfilter_queue library dir],
			[netfilter_queue_lib="$withval"],[netfilter_queue_lib=no])


if test x$enable_netfilter_queue = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$netfilter_queue_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${netfilter_queue_inc}"
	fi
	
	AC_CHECK_HEADER(libnetfilter_queue/libnetfilter_queue.h,[enable_netfilter_queue=yes],[enable_netfilter_queue=no])
	
	if test x$enable_netfilter_queue = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$netfilter_queue_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${netfilter_queue_lib}"
		fi
	
		AC_CHECK_LIB([netfilter_queue],[nfq_open],enable_netfilter_queue="yes", enable_netfilter_queue="no")
	
		if test x$enable_netfilter_queue = "xyes" ; then
			if test x$netfilter_queue_lib != "xno"; then
				LIB_NETFILTER_QUEUE_LIBS="-L$netfilter_queue_lib -lnetfilter_queue"
			else
				LIB_NETFILTER_QUEUE_LIBS="-lnetfilter_queue"
			fi
			if test x$netfilter_queue_inc != "xno"; then
				LIB_NETFILTER_QUEUE_CFLAGS="-I$netfilter_queue_inc"
			else
				LIB_NETFILTER_QUEUE_CFLAGS=""
			fi
			# The netfilter lib doesn't provide any version info, so try to detect the version
			PKG_CHECK_MODULES([libnetfilter_queue], [libnetfilter_queue >= 1.0.0],, [AC_DEFINE([NF_QUEUE_PRE_1_0_0], [1], [netfilter version < 1.0.0])])
			AC_DEFINE([HAVE_LIBNETFILTER_QUEUE], [1], [Define to 1 to compile with netfilter_queue support])
		fi
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi


dnl **************************************************
dnl * libxmatch                                      *
dnl **************************************************


AC_SUBST([LIB_XMATCH_CFLAGS])
AC_SUBST([LIB_XMATCH_LIBS])


enable_xmatch="yes"

AC_ARG_ENABLE(xmatch, [  --enable-xmatch      enable the xmatch plugin],
			[enable_xmatch="$enableval"],[enable_xmatch="yes"])

AC_ARG_WITH(xmatch-include,
			[  --with-xmatch-include=DIR  libxmatch include dir],
				      [xmatch_inc="$withval"],[xmatch_inc=no])
AC_ARG_WITH(xmatch-lib,
			[  --with-xmatch-lib=DIR  libxmatch library dir],
			[xmatch_lib="$withval"],[xmatch_lib=no])


if test x$enable_xmatch = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$xmatch_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${xmatch_inc}"
	fi
	
	AC_CHECK_HEADER(xmatch.h,[enable_xmatch=yes],[enable_xmatch=no])
	
	if test x$enable_xmatch = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$xmatch_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${xmatch_lib}"
		fi
	
		AC_CHECK_LIB([xmatch],[xm_match],enable_xmatch="yes", enable_xmatch="no")
	
		if test x$enable_xmatch = "xyes" ; then
			if test x$xmatch_lib != "xno"; then
				LIB_XMATCH_LIBS="-L$xmatch_lib -lxmatch"
			else
				LIB_XMATCH_LIBS="-lxmatch"
			fi
			if test x$xmatch_inc != "xno"; then
				LIB_XMATCH_CFLAGS="-I$xmatch_inc"
			else
				LIB_XMATCH_CFLAGS=""
			fi
			AC_DEFINE([HAVE_XMATCH], [1], [Define to 1 to compile with xmatch support])
		fi
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi


dnl **************************************************
dnl * glib                                           *
dnl **************************************************


AC_ARG_WITH(glib,
    [  --with-glib=PKGPREFIX     specify path to glib pkg config],
    [glib_pkg_prefix="$withval"],
    [glib_pkg_prefix=""])

AC_SUBST([LIB_GLIB_CFLAGS])
AC_SUBST([LIB_GLIB_LIBS])

if test x$glib_pkg_prefix != x""; then
	OLD_PKG_CONFIG_PATH=$PKG_CONFIG_PATH
	export PKG_CONFIG_PATH="$glib_pkg_prefix/lib/pkgconfig"
fi
PKG_CHECK_MODULES(glib, glib-2.0)
PKG_CHECK_MODULES(gthread, gthread-2.0)
PKG_CHECK_MODULES(gmodule, gmodule-2.0)

if test x$OLD_PKG_CONFIG_PATH != x""; then
	export PKG_CONFIG_PATH="$OLD_PKG_CONFIG_PATH"
fi

LIB_GLIB_CFLAGS="${glib_CFLAGS} ${gthread_CFLAGS} ${gmodule_CFLAGS}"
LIB_GLIB_LIBS="${glib_LIBS} ${gthread_LIBS} ${gmodule_LIBS}"

enable_glib="yes"



dnl **************************************************
dnl * python                                         *
dnl **************************************************

enable_python="no"

AZ_PYTHON_DEFAULT( )
AZ_PYTHON_ENABLE( )             # Optional
AZ_PYTHON_WITH( )               # Optional
AZ_PYTHON_PATH( )               # or AZ_PYTHON_INSIST( )
# if $PYTHON is not defined, then the following do nothing.
AZ_PYTHON_VERSION_ENSURE( [3.2] )
AZ_PYTHON_CSPEC
AZ_PYTHON_LSPEC

if $PYTHON ; then
	enable_python="yes"
	AC_DEFINE_UNQUOTED([PYTHON_PATH],"$PYTHON",[path to the python interpreter])
fi



dnl **************************************************
dnl * cython                                         *
dnl **************************************************

enable_cython="yes"
AC_SUBST([CYTHON_BIN])
AC_ARG_ENABLE(cython, [  --enable-cython      enable support for cython],
			[enable_cython="$enableval"],[enable_cython="yes"])

AC_ARG_WITH(cython-dir,
			[  --with-cython-dir=DIR  basedir of cython],
				      [cython_dir="$withval"],[cython_dir=$PATH])

if test x$enable_cython = "xyes" ; then
	AC_PATH_PROGS(CYTHON_BIN, [cython3 cython], "no", $cython_dir)
	if test "x$CYTHON_BIN" == "xno" ; then
		enable_cython="no"
	fi
fi



dnl **************************************************
dnl * liblcfg                                        *
dnl **************************************************

AC_SUBST([LIB_LCFG_CFLAGS])
AC_SUBST([LIB_LCFG_LIBS])


enable_lcfg="yes"

AC_ARG_ENABLE(lcfg, [  --enable-lcfg      enable support for liblcfg],
			[enable_lcfg="$enableval"],[enable_lcfg="yes"])

AC_ARG_WITH(lcfg-include,
			[  --with-lcfg-include=DIR  liblcfg include dir],
				      [lcfg_inc="$withval"],[lcfg_inc=no])
AC_ARG_WITH(lcfg-lib,
			[  --with-lcfg-lib=DIR  liblcfg library dir],
			[lcfg_lib="$withval"],[lcfg_lib=no])


if test x$enable_lcfg = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$lcfg_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${lcfg_inc}"
	fi
	
	AC_CHECK_HEADER(lcfg/lcfg.h,[enable_lcfg=yes],[enable_lcfg=no])
	
	if test x$enable_lcfg = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$lcfg_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${lcfg_lib}"
		fi
	
		AC_CHECK_LIB([lcfg],[lcfg_new],enable_lcfg="yes", enable_lcfg="no")
		if test x$enable_lcfg = "xyes" ; then
			if test x$lcfg_lib != "xno"; then
				LIB_LCFG_LIBS="-L$lcfg_lib -llcfg"
			else
				LIB_LCFG_LIBS="-llcfg"
			fi
			if test x$lcfg_inc != "xno"; then
				LIB_LCFG_CFLAGS="-I$lcfg_inc"
			else
				LIB_LCFG_CFLAGS=""
			fi
			AC_DEFINE([HAVE_LIBLCFG], [1], [Define to 1 to compile with lcfg support])
		fi
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi

if test x$enable_lcfg = "xno" ; then
	AC_MSG_ERROR([liblcfg is missing - install it please - download from http://liblcfg.carnivore.it])
fi


dnl **************************************************
dnl * libnl                                        *
dnl **************************************************

AC_SUBST([LIB_NL_CFLAGS])
AC_SUBST([LIB_NL_LIBS])

enable_nl="yes"

AC_ARG_ENABLE(nl, [  --enable-nl      enable support for libnl],
			[enable_nl="$enableval"],[enable_nl="yes"])

AC_ARG_WITH(nl-include,
			[  --with-nl-include=DIR  libnl include dir],
				      [nl_inc="$withval"],[nl_inc=no])
AC_ARG_WITH(nl-lib,
			[  --with-nl-lib=DIR  libnl library dir],
			[nl_lib="$withval"],[nl_lib=no])


if test x$enable_nl = "xyes" ; then
	OLD_CPPFLAGS=${CPPFLAGS};
	if test x$nl_inc != "xno"; then
		CPPFLAGS="${CPPFLAGS} -I${nl_inc}"
	fi
	
	AC_CHECK_HEADER(netlink/netlink.h,[enable_nl=yes],[enable_nl=no])
	
	if test x$enable_nl = "xyes" ; then
		OLD_LDFLAGS=${LDFLAGS}
		if test x$nl_lib != "xno"; then
			LDFLAGS="${LDFLAGS}  -L${nl_lib}"
		fi
		LDFLAGS="${LDFLAGS} -lnl-3 -lnl-genl-3 -lnl-nf-3"
		AC_CHECK_LIB([nl-route-3],[rtnl_link_get_ifindex],enable_nl="yes", enable_nl="no")
		if test x$enable_nl = "xyes" ; then
			if test x$nl_lib != "xno"; then
				LIB_NL_LIBS="-L$nl_lib -lnl-3 -nl-genl-3 -lnl-route-3 -lnl-nf-3"
			else
				LIB_NL_LIBS="-lnl-3 -nl-genl-3 -lnl-route-3 -lnl-nf-3"
			fi
			if test x$nl_inc != "xno"; then
				LIB_NL_CFLAGS="-I$nl_inc"
			else
				LIB_NL_CFLAGS=""
			fi
			AC_DEFINE([HAVE_LIBNL], [1], [Define to 1 to compile with nl support])
			libnl_rtnl_link_alloc_cache_argc="unknown"
			dnl 2 args
			if test $libnl_rtnl_link_alloc_cache_argc = "unknown"; then
				AC_MSG_CHECKING([if rtnl_link_alloc_cache takes 2 args.])
				AC_COMPILE_IFELSE([
				AC_LANG_PROGRAM([[
					#include <netlink/route/link.h>
					]],[[
					if(0 != rtnl_link_alloc_cache(NULL, NULL))
						return 1;
					]])
				],[
					AC_MSG_RESULT([yes])
					libnl_rtnl_link_alloc_cache_argc=2
					AC_DEFINE([LIBNL_RTNL_LINK_ALLOC_CACHE_ARGC], 2, [Number of args for rtnl_link_alloc_cache (old version)])
				],[
					AC_MSG_RESULT([no])
				])
			fi
			if test $libnl_rtnl_link_alloc_cache_argc = "unknown"; then
				AC_MSG_CHECKING([if rtnl_link_alloc_cache takes 3 args.])
				AC_COMPILE_IFELSE([
				AC_LANG_PROGRAM([[
					#include <netlink/route/link.h>
					]],[[
					if(0 != rtnl_link_alloc_cache(NULL, 0, NULL))
						return 1;
					]])
				],[
					AC_MSG_RESULT([yes])
					AC_DEFINE([LIBNL_RTNL_LINK_ALLOC_CACHE_ARGC], 3, [Number of args for rtnl_link_alloc_cache (new version)])
					libnl_rtnl_link_alloc_cache_argc=3
				],[
					AC_MSG_RESULT([no])
				])
			fi
			
		fi
	fi
	CPPFLAGS=${OLD_CPPFLAGS}
	LDFLAGS=${OLD_LDFLAGS}
fi

dnl **************************************************
dnl * libcurl                                        *
dnl **************************************************

AC_SUBST([LIB_CURL_CFLAGS])
AC_SUBST([LIB_CURL_LIBS])


enable_curl="yes"

AC_ARG_ENABLE(curl, [  --enable-curl      enable support for libcurl],
			[enable_curl="$enableval"],[enable_curl="yes"])

AC_ARG_WITH(curl-config,
			[  --with-curl-config=BIN  curl-config binary path],
				      [curl_config_dir="$withval"], [curl_config_dir=$PATH])
if test x$enable_curl = "xyes" ; then
	AC_PATH_PROG(CURL_CONFIG_BIN, curl-config, "no", $curl_config_dir)
	if test "x$CURL_CONFIG_BIN" == "xno" ; then
		enable_curl="no"
	else
		LIB_CURL_CFLAGS=$($CURL_CONFIG_BIN --cflags)
		LIB_CURL_LIBS=$($CURL_CONFIG_BIN --libs)
	fi
fi


dnl **************************************************
dnl * libloudmouth                                        *
dnl **************************************************

AC_SUBST([LIB_LOUDMOUTH_CFLAGS])
AC_SUBST([LIB_LOUDMOUTH_LIBS])


enable_loudmouth="no"


dnl PKG_CHECK_MODULES(VARIABLE-PREFIX, MODULES, [ACTION-IF-FOUND],
dnl [ACTION-IF-NOT-FOUND])

PKG_CHECK_MODULES(loudmouth, loudmouth,[enable_loudmouth="yes"],[enable_loudmouth="no"])

if test x$enable_loudmouth = "xno"; then
	PKG_CHECK_MODULES(loudmouth, loudmouth-1.0,[enable_loudmouth="yes"],[enable_loudmouth="no"])
fi

if test x$enable_loudmouth = "xyes"; then
	LIB_LOUDMOUTH_CFLAGS=${loudmouth_CFLAGS} 
	LIB_LOUDMOUTH_LIBS=${loudmouth_LIBS} 
fi


dnl **************************************************
dnl * module building                                *
dnl **************************************************

AM_CONDITIONAL([BUILD_CSPM_MODULE], [ test x$enable_cspm = "xyes" ])
AM_CONDITIONAL([BUILD_EMU_MODULE], [ test x$enable_emu = "xyes" ])
AM_CONDITIONAL([BUILD_NFQ_MODULE], [ test x$enable_netfilter_queue = "xyes" ])
AM_CONDITIONAL([BUILD_XMATCH_MODULE], [ test x$enable_xmatch = "xyes" ])
AM_CONDITIONAL([BUILD_PCAP_MODULE], [ test x$enable_pcap = "xyes" ])
AM_CONDITIONAL([BUILD_LOUDMOUTH_MODULE], [ test x$enable_loudmouth = "xyes" ])
AM_CONDITIONAL([BUILD_PYTHON_MODULE], [ test x$enable_python = "xyes" && test x$enable_cython = "xyes" ])
AM_CONDITIONAL([BUILD_CURL_MODULE], [ test x$enable_curl = "xyes" ])
AM_CONDITIONAL([BUILD_NL_MODULE], [ test x$enable_nl = "xyes" ])
AM_CONDITIONAL([BUILD_PCAP_MODULE], [ test x$enable_pcap = "xyes" ])


dnl **************************************************
dnl * debug & performance                            *
dnl **************************************************

AC_MSG_CHECKING(whether you are looking for 'performance')
AC_ARG_ENABLE([performance],
		[AS_HELP_STRING(--enable-performance, tries to kill all logging activity to save some cycles [[default=no]])],
		[enable_performance=${enableval}], [enable_performance="no"])
if test x"$enable_performance" = "xyes"; then
	AC_DEFINE([PERFORMANCE], 1, [I'm looking for performance])
else
	AC_DEFINE([NPERFORMANCE], 1, [I'm ... capacity instead of spoiler])
fi
AC_MSG_RESULT($enable_performance)


AC_SUBST([CFLAGS_DEBUG])

AC_MSG_CHECKING(whether debug code generation should be enabled)
AC_ARG_ENABLE([debug],
		[AS_HELP_STRING(--enable-debug, enable debug code generation [[default=yes]])],
		[enable_debug=${enableval}], [enable_debug="yes"])
if test x"$enable_debug" = "xyes" && test x"$enable_performance" = "xno"; then
	AC_DEFINE([DEBUG], 1, [enable debug code generation])
	CFLAGS_DEBUG="-g"
else
	enable_debug="no"
	AC_DEFINE([NDEBUG], 1, [don't enable debug code generation])
	CFLAGS_DEBUG=""
fi
AC_MSG_RESULT($enable_debug)


dnl **************************************************
dnl * Werror                                         *
dnl **************************************************

AC_MSG_CHECKING(whether you want Werror)
AC_ARG_ENABLE([werror],
		[AS_HELP_STRING(--enable-werror, compiler warnings are errors [[default=yes]])],
		[enable_werror=${enableval}], [enable_werror="yes"])
if test x"$enable_werror" = "xyes"; then
	CFLAGS_DEFAULT="-Werror"
else
	CFLAGS_DEFAULT=""
fi
AC_MSG_RESULT($enable_werror)



dnl **************************************************
dnl * default cflags                                 *
dnl **************************************************

AC_SUBST([CFLAGS_DEFAULT])
CFLAGS_LFS=`getconf LFS_CFLAGS`

CFLAGS_DEFAULT="-Wall ${CFLAGS_DEFAULT}"

CFLAGS="${CFLAGS} -D_GNU_SOURCE ${LIB_EV_CFLAGS} ${LIB_GLIB_CFLAGS} ${LIB_LCFG_CFLAGS} ${CFLAGS_DEFAULT} -Wstrict-prototypes ${CFLAGS_DEBUG} ${CFLAGS_LFS}"


dnl **************************************************
dnl * revision                                       *
dnl **************************************************

#AC_PATH_PROG(GIT_BIN, git, "no")
#if test "x$GIT_BIN" != "xno" ; then
#	REV="\`$GIT_BIN show-ref heads/master | cut -b 1-6\`"
#	AC_DEFINE([DIONAEA_GIT_VERSION], [$REV], [this is the git revision])
#	CFLAGS="${CFLAGS} -DDIONAEA_REV=$REV..." 
#fi

dnl **************************************************
dnl * sanity                                         *
dnl * make sure everything which is required exists  *
dnl **************************************************


fail="no"

for i in emu ev curl cython python glib udns ssl; do
	AC_MSG_CHECKING(DEPENDENCY $i)
	v=enable_$i
	x=$(eval echo $`echo $v`)
	if test "x$x" != "xyes"; then
		AC_MSG_WARN(no)
		fail="yes"
	else
		AC_MSG_RESULT(yes)	
	fi
done

AC_MSG_CHECKING(if all required dependencies are installed properly)
if test "x$fail" != "xno"; then
	AC_MSG_ERROR([no - better read the documentation])
else
	AC_MSG_RESULT([yes - well done, you read the documentation])
fi






AC_DEFUN([AC_DEFINE_DIR], [
  prefix_NONE=
  exec_prefix_NONE=
  test "x$prefix" = xNONE && prefix_NONE=yes && prefix=$ac_default_prefix
  test "x$exec_prefix" = xNONE && exec_prefix_NONE=yes && exec_prefix=$prefix
dnl In Autoconf 2.60, ${datadir} refers to ${datarootdir}, which in turn
dnl refers to ${prefix}.  Thus we have to use `eval' twice.
  eval ac_define_dir="\"[$]$2\""
  eval ac_define_dir="\"$ac_define_dir\""
  AC_SUBST($1, "$ac_define_dir")
  AC_DEFINE_UNQUOTED($1, "$ac_define_dir", [$3])
  test "$prefix_NONE" && prefix=NONE
  test "$exec_prefix_NONE" && exec_prefix=NONE
])

AC_DEFINE_DIR(PREFIX, prefix, [default working directory])
AC_DEFINE_DIR(LOCALESTATEDIR, localstatedir, [where to put logs etc])
AC_DEFINE_DIR(LIBDIR, libdir, [where to look for plugins])
AC_DEFINE_DIR(SYSCONFDIR, [sysconfdir], [System configuration dir])
AC_DEFINE_DIR(DATADIR, [datadir], [The directory for installing idiosyncratic read-only architecture-independent data.])
AC_DEFINE_DIR(DATAROOTDIR, [datarootdir], [The root of the directory tree for read-only architecture-independent data files.])

AC_CONFIG_FILES([Makefile
				src/Makefile
				include/Makefile
				modules/Makefile
				modules/nc/Makefile
				modules/python/Makefile
				modules/python/setup.py
				modules/python/scripts/Makefile
				modules/python/util/Makefile
				modules/emu/Makefile
				modules/curl/Makefile
				modules/nl/Makefile
				modules/nfq/Makefile
				modules/xmatch/Makefile
				modules/pcap/Makefile])

                 
AC_OUTPUT

echo
echo "*** dionaea configuration ***"
echo ""
echo "debug                              : $enable_debug"
echo "performance                        : $enable_performance"
echo "werror                             : $enable_werror"
echo "ipv4 mapped                        : $enable_ipv4_mapped"
echo ""
echo "ev                                 : $enable_ev"
echo " - cflags                          : $LIB_EV_CFLAGS"
echo " - libs                            : $LIB_EV_LIBS"
echo ""
echo "glib                               : $enable_glib"
echo " - cflags                          : $LIB_GLIB_CFLAGS"
echo " - libs                            : $LIB_GLIB_LIBS"
echo ""
echo "python                             : $enable_python"
echo " - binary                          : $PYTHON"
echo " - cflags                          : $PYTHON_CSPEC"
echo " - libs                            : $PYTHON_LSPEC"
echo ""
echo "cython                             : $enable_cython"
echo " - binary                          : $CYTHON_BIN"
echo ""
echo "lcfg                               : $enable_lcfg"
echo " - cflags                          : $LIB_LCFG_CFLAGS"
echo " - libs                            : $LIB_LCFG_LIBS"
echo ""
echo "ssl                                : $enable_ssl"
echo " - cflags                          : $LIB_SSL_CFLAGS"
echo " - libs                            : $LIB_SSL_LIBS"
echo ""
echo "emu                                : $enable_emu"
echo " - cflags                          : $LIB_EMU_CFLAGS"
echo " - libs                            : $LIB_EMU_LIBS"
echo ""
echo "udns                               : $enable_udns"
echo " - cflags                          : $LIB_UDNS_CFLAGS"
echo " - libs                            : $LIB_UDNS_LIBS"
echo ""
echo "pcap                               : $enable_pcap"
echo " - cflags                          : $LIB_PCAP_CFLAGS"
echo " - libs                            : $LIB_PCAP_LIBS"
echo ""
echo "netfilter_queue                    : $enable_netfilter_queue"
echo " - cflags                          : $LIB_NETFILTER_QUEUE_CFLAGS"
echo " - libs                            : $LIB_NETFILTER_QUEUE_LIBS"
echo ""
echo "cspm                               : $enable_cspm"
echo " - cflags                          : $LIB_CSPM_CFLAGS"
echo " - libs                            : $LIB_CSPM_LIBS"
echo ""
echo "loudmouth                          : $enable_loudmouth"
echo " - cflags                          : $LIB_LOUDMOUTH_CFLAGS"
echo " - libs                            : $LIB_LOUDMOUTH_LIBS"
echo ""
echo "gc                                 : $enable_gc"
echo " - cflags                          : $LIB_GC_CFLAGS"
echo " - libs                            : $LIB_GC_LIBS"
echo ""
echo "curl                               : $enable_curl"
echo " - cflags                          : $LIB_CURL_CFLAGS"
echo " - libs                            : $LIB_CURL_LIBS"
echo ""
echo "nl                                 : $enable_nl"
echo " - cflags                          : $LIB_NL_CFLAGS"
echo " - libs                            : $LIB_NL_LIBS"
echo ""
echo "xmatch                             : $enable_xmatch"
echo " - cflags                          : $LIB_XMATCH_CFLAGS"
echo " - libs                            : $LIB_XMATCH_LIBS"
