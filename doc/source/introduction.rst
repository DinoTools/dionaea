Introduction
============

How it works
------------

dionaea intention is to trap malware exploiting vulnerabilities exposed
by services offerd to a network, the ultimate goal is gaining a copy of
the malware.


Security
--------

As Software is likely to have bugs, bugs in software offering network
services can be exploitable, and dionaea is software offering network
services, it is likely dionaea has exploitable bugs.

Of course we try to avoid it, but if nobody would fail when trying hard,
we would not need software such as dionaea.

So, in order to minimize the impact, dionaea can drop privileges, and
chroot.

To be able to run certain actions which require privileges, after
dionaea dropped them, dionaea creates a child process at startup, and
asks the child process to run actions which require elevated privileges.
This does not guarantee anything, but it should be harder to get gain
root access to the system from an unprivileged user in a chroot
environment.


Network Connectivity
--------------------

Given the softwares intented use, network io is crucial. All network io
is within the main process in a so called non-blocking manner. To
understand nonblocking, imagine you have many pipes infront of you, and
these pipes can send you something, and you can put something into the
pipe. If you want to put something into a pipe, while it is crowded,
you'd have to wait, if you want to get something from a pipe, and there
is nothing, you'd have to wait too. Doing this pipe game non-blocking
means you won't wait for the pipes to be write/readable, you'll get
something off the pipes once data arrives, and write once the pipe is
not crowded. If you want to write a large chunk to the pipe, and the
pipe is crowded after a small piece, you note the rest of the chunk you
wanted to write, and wait for the pipe to get ready.

DNS resolves are done using libudns, which is a neat non-blocking dns
resolving library with support for AAAA records and chained cnames.
So much about non-blocking.

dionaea uses libev to get notified once it can act on a socket, read or
write.

dionaea can offer services via tcp/udp and tls for IPv4 and IPv6, and
can apply rate limiting and accounting limits per connections to tcp and
tls connections - if required.
