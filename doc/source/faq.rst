FAQ
===

.. warning:: The documentation is work in progress.


Build/Install
-------------
I got these error while installation from source code 
"libtool: Version mismatch error.  This is libtool 2.4.6, but the
libtool: definition of this LT_INIT comes from libtool 2.4.2.
libtool: You should recreate aclocal.m4 with macros from libtool 2.4.6
libtool: and run autoconf again.".

I get gcc: command not found?

    install gcc..

How to uninstall it?

    rm -rf /opt/dionaea

I get binding.pyx:...: undeclared name not builtin: bytes during the python modules build.

    Install a recent cython version

I get Python.h not found during compiling cython

    Install appropriate headers for your python interpreter

I do not use ubuntu/debian and the instructions are useless for me therefore.

    I use debian/ubuntu, and therefore I can only provide instructions
    for debian/ubuntu, but you are free to send me a diff for your
    operating system

I use Redhat/Centos 5 and the installation is frustrating and a mess as nothing works.

    Thats right, but I did not choose your operating system.
    Here is a list of outdated or missing packages for your choosen
    distribution: *all*. Yes, you'll even have to install glib (you'll
    have 2.10 where 2.20 is required) from source.
    Getting python3 compiled with a recent sqlite3 version installed to
    /opt/dionaea requires editing the setup.py file (patch
    <http://p.carnivore.it/KDIFWt>).
    /I experienced this wonderful operating system myself ... You really
    have to love your distro to stick with it, even if it ships software
    versions your grandma saw released in her youth.
    *Centos is the best distro ... to change distros*.
    No matter what you choose, it can't get worse./

Unable to build.

    .. code-block:: console

        ==> default: cp build/*/dionaea/*.so /opt/dionaea/lib/dionaea/python.so
        ==> default: cp:
        ==> default: target ‘/opt/dionaea/lib/dionaea/python.so’ is not a directory

    .. code-block:: console

        ==> default: libtool: Version mismatch error.  This is libtool 2.4.6 Debian-2.4.6-2, but the
        ==> default: libtool: definition of this LT_INIT comes from libtool 2.4.2.
        ==> default: libtool: You should recreate aclocal.m4 with macros from libtool 2.4.6 Debian-2.4.6-2
        ==> default: libtool: and run autoconf again.

    Try to clean your build environment.

    .. warning::

        This will remove all ignored and untracked files from the directory.
        Use `--dry-run`

    .. code-block:: console

        git clean -xdf

Run
---

I get OperationalError at unable to open database file when using logsqlite and it does not work at all

    Read the logsql instructions <#logsql>

I get a Segmentation Fault

    Read the segfault instructions <#segfault>

I logrotate, and after logrotate dionaea does not log anymore.

    Read the logrotate instructions <#logging>

p0f does not work.

    Make sure your have p0f 2.0.8 and dionaea does not listen on ::, p0f
    can't deal with IPv6.

I'm facing a bug, it fails, and I can't figure out why.

    Explain the problem, if I'm interested in the nature of the problem,
    as it does not sound like pebcak, I may ask for a shell/screen and
    have a look myself, and if it is worth it, you'll even get a FAQ
    entry for some specialties of your OS.

Unable to bind to port after dropping privileges

    Dropping privileges and binding to ports lower than 1024 is only support on Linux systems.
    If some of the optional build dependencies are missing dionaea might not be able to bind to these ports too.
    After enabling all log levels it should display some log messages like in the example below.

    .. code-block:: console

        [10052017 15:58:17] connection connection.c:200: bind_local con 0x55f21b1ec720
        [10052017 15:58:17] connection connection.c:216: bind_local socket 10 1.2.3.4:21
        [10052017 15:58:17] connection connection.c:230: Could not bind 1.2.3.4:21 (Permission denied)

    To fix this issue you have to install the **kernel headers** for your kernel and rebuild dionaea.
    If everything works as it should you might get log messages like in the example below.
    You might have noticed that there is now a pchild section.
    This means dionaea is using a child process with extended privileges to bind to the port.

    .. code-block:: console

        [10052017 15:58:17] connection connection.c:200: bind_local con 0x55f21b1ec720
        [10052017 15:58:17] connection connection.c:216: bind_local socket 10 1.2.3.4:21
        [10052017 15::58:17] pchild pchild.c:199: sending msg to child to bind port ...
        [10052017 15::58:17] pchild pchild.c:218: child could bind the socket!
        [10052017 15::58:17] connection connection.c:316: ip '1.2.3.4' node '1.2.3.4:21'
