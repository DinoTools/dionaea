# ===========================================================================
#               http://autoconf-archive.cryp.to/az_python.html
# ===========================================================================
#
# SYNOPSIS
#
#   AZ_PYTHON_DEFAULT
#   AZ_PYTHON_ENABLE
#   AZ_PYTHON_WITH
#   AZ_PYTHON_PATH
#   AZ_PYTHON_VERSION_ENSURE( [2.2] )
#   AZ_PYTHON_CSPEC
#   AZ_PYTHON_LSPEC
#
# DESCRIPTION
#
#   This file provides autoconf support for those applications that want to
#   embed python. It supports all pythons >= 2.2 which is the first official
#   release containing distutils. Version 2.2 of python was released
#   December 21, 2001. Since it actually executes the python, cross platform
#   configuration will probably not work. Also, most of the platforms
#   supported are consistent until you look into MacOSX. The python included
#   with it is installed as a framework which is a very different
#   environment to set up the normal tools such as gcc and libtool to deal
#   with. Therefore, once we establish which python that we are going to
#   use, we use its distutils to actually compile and link our modules or
#   applications.
#
#   At this time, it does NOT support linking with Python statically. It
#   does support dynamic linking.
#
#   This set of macros help define $PYTHON, $PYTHON_USE, $PYTHON_CSPEC and
#   $PYTHON_LSPEC. $PYTHON defines the full executable path for the Python
#   being linked to and is used within these macros to determine if that has
#   been specified or found. These macros do execute this python version so
#   it must be present on the system at configure time.
#
#   $PYTHON_USE is an automake variable that defines whether Python support
#   should be included or not in your application. $PYTHON_CSPEC is a
#   variable that supplies additional CFLAGS for the compilation of the
#   application/shared library. $PYTHON_LSPEC is a variable that supplies
#   additional LDFLAGS for linking the application/shared library.
#
#   The following is an example of how to set up for python usage within
#   your application in your configure.in:
#
#     AZ_PYTHON_DEFAULT( )
#     AZ_PYTHON_ENABLE( )             # Optional
#     AZ_PYTHON_WITH( )               # Optional
#     AZ_PYTHON_PATH( )               # or AZ_PYTHON_INSIST( )
#     # if $PYTHON is not defined, then the following do nothing.
#     AZ_PYTHON_VERSION_ENSURE( [2.2] )
#     AZ_PYTHON_CSPEC
#     AZ_PYTHON_LSPEC
#
#   The AZ_PYTHON_DEFAULT sets the $PYTHON_USE to false. Thereby, excluding
#   it if it was optional.
#
#   The AZ_PYTHON_ENABLE looks for the optional configure parameters of
#   --enable-python/--disable-python and establishes the $PYTHON and
#   $PYTHON_USE variables accordingly.
#
#   The AZ_PYTHON_WITH looks for the optional configure parameters of
#   --with-python/--without-python and establishes the $PYTHON and
#   $PYTHON_USE variables accordingly.
#
#   The AZ_PYTHON_PATH looks for python assuming that none has been
#   previously found or defined and issues an error if it does not find it.
#   If it does find it, it establishes the $PYTHON and $PYTHON_USE variables
#   accordingly. AZ_PYTHON_INSIST could be used here instead if you want to
#   insist that Python support be included using the --enable-python or
#   --with-python checks previously done.
#
#   The AZ_PYTHON_VERSION_ENSURE issues an error if the Python previously
#   found is not of version 2.2 or greater.
#
#   Once that these macros have be run, we can use PYTHON_USE within the
#   makefile.am file to conditionally add the Python support such as:
#
#   Makefile.am example showing optional inclusion of directories:
#
#    if PYTHON_USE
#    plugins = plugins
#    src = src
#    else
#    plugins =
#    src =
#    endif
#
#    SUBDIRS = . $(plugins) $(src)
#
#   Makefile.am example showing optional shared library build:
#
#    if PYTHON_USE
#    lib_LTLIBRARIES        = libElemList.la
#    libElemList_la_SOURCES = libElemList.c
#    libElemList_la_CFLAGS  = @PYTHON_CSPEC@
#    libElemList_la_LDFLAGS = @PYTHON_LSPEC@
#    endif
#
#   Makefile.am example showing optional program build:
#
#    if PYTHON_USE
#    bin_PROGRAMS    = runFunc
#    runFunc_SOURCES = runFunc.c
#    runFunc_CFLAGS  = @PYTHON_CSPEC@
#    runFunc_LDFLAGS = @PYTHON_LSPEC@
#    endif
#
#   The above compiles the modules only if PYTHON_USE was specified as true.
#   Also, the else portion of the if was optional.
#
# LAST MODIFICATION
#
#   2008-04-12
#
# COPYLEFT
#
#   Copyright (c) 2008 Robert White <kranki@mac.com>
#   Copyright (c) 2008 Dustin J. Mitchell <dustin@cs.uchicago.edu>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved.

# AZ_PYTHON_DEFAULT( )
# -----------------
# Sets the default to not include Python support.

AC_DEFUN([AZ_PYTHON_DEFAULT],
[
    az_python_use=false
    AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
])



# AZ_PYTHON_ENABLE( [path] )
# -----------------------------------------------------------------
# Handles the various --enable-python commands.
# Input:
#   $1 is the optional search path for the python executable if needed
# Ouput:
#   PYTHON_USE (AM_CONDITIONAL) is true if python executable found
#   and --enable-python was requested; otherwise false.
#   $PYTHON contains the full executable path to python if PYTHON_ENABLE_USE
#   is true.
#
# Example:
#   AZ_PYTHON_ENABLE( )
#   or
#   AZ_PYTHON_ENABLE( "/usr/bin" )

AC_DEFUN([AZ_PYTHON_ENABLE],
[
    AC_ARG_VAR([PYTHON],[Python Executable Path])

    # unless PYTHON was supplied to us (as a precious variable),
    # see if --enable-python[=PythonExecutablePath], --enable-python,
    # --disable-python or --enable-python=no was given.
    if test -z "$PYTHON"
    then
        AC_MSG_CHECKING(for --enable-python)
        AC_ARG_ENABLE(
            python,
            AC_HELP_STRING([--enable-python@<:@=PYTHON@:>@],
                [absolute path name of Python executable]
            ),
            [
                if test "$enableval" = "yes"
                then
                    # "yes" was specified, but we don't have a path
                    # for the executable.
                    # So, let's searth the PATH Environment Variable.
                    AC_MSG_RESULT(yes)
                    AC_PATH_PROG(
                        [PYTHON],
                        python,
                        [],
                        $1
                    )
                    if test -z "$PYTHON"
                    then
                        AC_MSG_ERROR(no path to python found)
                    fi
                    az_python_use=true
                    AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
                    AZ_PYTHON_PREFIX( )
                elif test "$enableval" = "no"
                then
                    AC_MSG_RESULT(no)
                    az_python_use=false
                    AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
                else
                    # $enableval must be the executable path then.
                    AC_SUBST([PYTHON], ["${enableval}"])
                    AC_MSG_RESULT($withval)
                    az_python_use=true
                    AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
                    AZ_PYTHON_PREFIX( )
                fi
            ],
            [
                # --with-python was not specified.
                AC_MSG_RESULT(no)
                az_python_use=false
                AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
            ]
        )
    fi

])



# AZ_PYTHON_CSPEC( )
# -----------------
# Set up the c compiler options to compile Python
# embedded programs/libraries in $PYTHON_CSPEC if
# $PYTHON has been defined.

AC_DEFUN([AZ_PYTHON_CSPEC],
[
    AC_ARG_VAR( [PYTHON], [Python Executable Path] )
    if test -n "$PYTHON"
    then
        az_python_prefix=`${PYTHON} -c "import sys; print(sys.prefix)"`
        if test -z "$az_python_prefix"
        then
            AC_MSG_ERROR([Python Prefix is not known])
        fi
        az_python_platinclude=`$PYTHON -c "import sysconfig; print(sysconfig.get_path('platinclude'))"`
        az_python_includespec="-I${az_python_platinclude}"
        az_python_ccshared=`${PYTHON} -c "import sysconfig; print(sysconfig.get_config_var('CFLAGSFORSHARED'))"`
        az_python_cspec="${az_python_ccshared} ${az_python_includespec}"
        AC_SUBST([PYTHON_CSPEC], [${az_python_cspec}])
        AC_MSG_NOTICE([PYTHON_CSPEC=${az_python_cspec}])
    fi
])



# AZ_PYTHON_INSIST( )
# -----------------
# Look for Python and set the output variable 'PYTHON'
# to 'python' if found, empty otherwise.

AC_DEFUN([AZ_PYTHON_PATH],
[
    AC_ARG_VAR( [PYTHON], [Python Executable Path] )
    if test -z "$PYTHON"
    then
        AC_MSG_ERROR([Python Executable not found])
    fi
])



# AZ_PYTHON_LSPEC( )
# -----------------
# Set up the linker options to link Python embedded
# programs/libraries in $PYTHON_LSPEC if $PYTHON
# has been defined.

AC_DEFUN([AZ_PYTHON_LSPEC],
[
    AC_ARG_VAR( [PYTHON], [Python Executable Path] )
    if test -n "$PYTHON"
    then
        AZ_PYTHON_RUN([
import sys
import sysconfig
dictConfig = sysconfig.get_config_vars( )
strLinkSpec =  dictConfig.get('LDFLAGS','')

for k,v in {"SYSLIBS": "","SHLIBS":"","LINKFORSHARED":""}.items():
	lib = dictConfig.get(k)
	if lib and lib != "":
		strLinkSpec += " %s%s" % (v,lib)

# Construct the Python Library Name.
strLinkSpec += " -lpython%s%s" % (sysconfig.get_python_version(), sys.abiflags)
print(strLinkSpec)
        ])
        AC_SUBST([PYTHON_LSPEC], [${az_python_output}])
        AC_MSG_NOTICE([PYTHON_LSPEC=${az_python_output}])
    fi
])



# AZ_PYTHON_PATH( )
# -----------------
# Look for Python and set the output variable 'PYTHON'
# to 'python' if found, empty otherwise.

AC_DEFUN([AZ_PYTHON_PATH],
[
    AC_ARG_VAR( [PYTHON], [Python Executable Path] )
    AC_PATH_PROG( PYTHON, python3.2, [], $1 )
    if test -z "$PYTHON"
    then
        AC_MSG_ERROR([Python Executable not found])
    else
        az_python_use=true
    fi
    AM_CONDITIONAL(PYTHON_USE, test "$az_python_use" = "true")
])



# AZ_PYTHON_PREFIX( )
# -------------------
# Use the values of $prefix and $exec_prefix for the corresponding
# values of PYTHON_PREFIX and PYTHON_EXEC_PREFIX.

AC_DEFUN([AZ_PYTHON_PREFIX],
[
    if test -z "$PYTHON"
    then
        AC_MSG_ERROR([Python Executable Path is not known])
    fi
    ax_python_prefix=`${PYTHON} -c "import sys; print(sys.prefix)"`
    ax_python_execprefix=`${PYTHON} -c "import sys; print(sys.exec_prefix)"`
    AC_SUBST([PYTHON_PREFIX], ["${ax_python_prefix}"])
    AC_SUBST([PYTHON_EXECPREFIX], ["${ax_python_execprefix}"])
])



# AZ_PYTHON_RUN( PYTHON_PROGRAM )
# -----------------
# Run a Python Test Program saving its output
# in az_python_output and its condition code
# in az_python_cc.

AC_DEFUN([AZ_PYTHON_RUN],
[
    AC_ARG_VAR( [PYTHON], [Python Executable Path] )
    if test -z "$PYTHON"
    then
        AC_MSG_ERROR([Python Executable not found])
    else
        cat >conftest.py <<_ACEOF
$1
_ACEOF
        az_python_output=`$PYTHON conftest.py`
        az_python_cc=$?
        rm conftest.py
        if test -f "conftest.pyc"
        then
            rm conftest.pyc
        fi
    fi
])



# AZ_PYTHON_VERSION_CHECK( VERSION, [ACTION-IF-TRUE], [ACTION-IF-FALSE] )
# -----------------------------------------------------------------------------
# Run ACTION-IF-TRUE if the Python interpreter has version >= VERSION.
# Run ACTION-IF-FALSE otherwise.
# This test uses sys.hexversion instead of the string equivalant (first
# word of sys.version), in order to cope with versions such as 2.2c1.
# hexversion has been introduced in Python 1.5.2; it's probably not
# worth to support older versions (1.5.1 was released on October 31, 1998).

AC_DEFUN([AZ_PYTHON_VERSION_CHECK],
 [
    AC_ARG_VAR( [PYTHON], [Python Executable Path] )
    if test -n "$PYTHON"
    then
        AC_MSG_CHECKING([whether $PYTHON version >= $1])
        AZ_PYTHON_RUN([
import sys, string
# split strings by '.' and convert to numeric.  Append some zeros
# because we need at least 4 digits for the hex conversion.
minver = list(map(int, '$1'.split('.'))) + [[0, 0, 0]]
minverhex = 0
for i in list(range(0, 4)): minverhex = (minverhex << 8) + minver[[i]]
if sys.hexversion >= minverhex:
    sys.exit( 0 )
else:
    sys.exit( 1 )
        ])
        if test $az_python_cc -eq 0
        then
            $2
        m4_ifvaln(
            [$3],
            [else $3]
        )
        fi
    fi
])



# AZ_PYTHON_VERSION_ENSURE( VERSION )
# -----------------
# Insure that the Python Interpreter Version
# is greater than or equal to the VERSION
# parameter.

AC_DEFUN([AZ_PYTHON_VERSION_ENSURE],
[
    AZ_PYTHON_VERSION_CHECK(
        [$1],
        [AC_MSG_RESULT(yes)],
        [AC_MSG_ERROR(too old)]
    )
])



# AZ_PYTHON_WITH( [path] )
# -----------------------------------------------------------------
# Handles the various --with-python commands.
# Input:
#   $1 is the optional search path for the python executable if needed
# Ouput:
#   PYTHON_USE (AM_CONDITIONAL) is true if python executable found
#   and --with-python was requested; otherwise false.
#   $PYTHON contains the full executable path to python if PYTHON_USE
#   is true.
#
# Example:
#   AZ_PYTHON_WITH( )
#   or
#   AZ_PYTHON_WITH("/usr/bin")

AC_DEFUN([AZ_PYTHON_WITH],
[
    AC_ARG_VAR([PYTHON],[Python Executable Path])

    # unless PYTHON was supplied to us (as a precious variable),
    # see if --with-python[=PythonExecutablePath], --with-python,
    # --without-python or --with-python=no was given.
    if test -z "$PYTHON"
    then
        AC_MSG_CHECKING(for --with-python)
        AC_ARG_WITH(
            python,
            AC_HELP_STRING([--with-python@<:@=PYTHON@:>@],
                [absolute path name of Python executable]
            ),
            [
                if test "$withval" = "yes"
                then
                    # "yes" was specified, but we don't have a path
                    # for the executable.
                    # So, let's searth the PATH Environment Variable.
                    AC_MSG_RESULT(yes)
                    AC_PATH_PROG(
                        [PYTHON],
                        python,
                        [],
                        $1
                    )
                    if test -z "$PYTHON"
                    then
                        AC_MSG_ERROR(no path to python found)
                    fi
                    az_python_use=true
                    AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
                    AZ_PYTHON_PREFIX( )
                elif test "$withval" = "no"
                then
                    AC_MSG_RESULT(no)
                    az_python_use=false
                    AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
                else
                    # $withval must be the executable path then.
                    AC_SUBST([PYTHON], ["${withval}"])
                    AC_MSG_RESULT($withval)
                    az_python_use=true
                    AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
                    AZ_PYTHON_PREFIX( )
                fi
            ],
            [
                # --with-python was not specified.
                AC_MSG_RESULT(no)
                az_python_use=false
                AM_CONDITIONAL(PYTHON_USE, test x"$az_python_use" = x"true")
            ]
        )
    fi

])
