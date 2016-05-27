FAQ
===

.. warning:: The documentation is work in progress.


Build/Install
-------------

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
