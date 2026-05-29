..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2011-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

SIP (VoIP)
==========

This is a VoIP module for the honeypot dionaea. The VoIP protocol used
is SIP since it is the de facto standard for VoIP today. In contrast to
some other VoIP honeypots, this module doesn't connect to an external
VoIP registrar/server. It simply waits for incoming SIP messages (e.g.
OPTIONS or even INVITE), logs all data as honeypot incidents and/or
binary data dumps (RTP traffic), and reacts accordingly, for instance by
creating a SIP session including an RTP audio channel. As sophisticated
exploits within the SIP payload are not very common yet, the honeypot
module doesn't pass any code to dionaea's code emulation engine. This
will be implemented if we spot such malicious messages. The main
features of the VoIP module are:

* Support for most SIP requests (OPTIONS, INVITE, ACK, CANCEL, BYE)
* Support for multiple SIP sessions and RTP audio streams
* Record all RTP data (optional)
* Set custom SIP username and secret (password)
* Set custom useragent to mimic different phone models
* Uses dionaea's incident system to log to SQL database


Personalities
-------------

A personality defines how to handle a request. At least the 'default'
personality MUST exist. The following options are available per
personality.

serve

    A list of IP addresses to use this personality for.

handle

    List of SIP methods to handle.


SIP Users
---------

You can easily add, change or remove users by editing the SQLite file
specified by the 'users = ""' parameter in the config file. All users
are specified in the users table.

username

    Specifies the name of the user. This value is treated as regular
    expression. See Python: Regular Expressions
    <http://docs.python.org/py3k/library/re.html> for more information.

password

    The password.

personality

    The user is only available in the personality specified by this
    value. You can define a personality in the config file.

pickup_delay_min

    This is an integer value. Let the phone ring for at least this
    number of seconds.

pickup_delay_max

    This is an integer value. Maximum number of seconds to wait before
    dionaea picks up the phone.

action

    This value isn't in use, yet.

sdp

    The name of the SDP to use. See table 'sdp'.

SDP
---

All SDPs can be defined in the sdp table in the users database.

name

    Name of the SDP

sdp

    The value to use as SDP

The following values are available in the SDP definition.

{addrtype}

    Address type. (IP4 or IP6)

{unicast_address}

    RTP address

{audio_port}

    Dionaea audio port.

{video_port}

    Dionaea video port.

The following control parameters are available in the SDP definition.

[audio_port]...content...[/audio_port]

    The content is only available in the output if the audio_port value
    is set.

[video_port]...content...[/video_port]

    The content is only available in the output if the video_port value
    is set.

Example:

.. code-block:: text

    v=0
    o=- 1304279835 1 IN {addrtype} {unicast_address}
    s=SIP Session
    c=IN {addrtype} {unicast_address}
    t=0 0
    [audio_port]
    m=audio {audio_port} RTP/AVP 111 0 8 9 101 120
    a=sendrecv
    a=rtpmap:111 Speex/16000/1
    a=fmtp:111 sr=16000,mode=any
    a=rtpmap:0 PCMU/8000/1
    a=rtpmap:8 PCMA/8000/1
    a=rtpmap:9 G722/8000/1
    a=rtpmap:101 telephone-event/8000
    a=fmtp:101 0-16,32,36
    a=rtpmap:120 NSE/8000
    a=fmtp:120 192-193
    [/audio_port]
    [video_port]
    m=video {video_port} RTP/AVP 34 96 97
    c=IN {addrtype} {unicast_address}
    a=rtpmap:34 H263/90000
    a=fmtp:34 QCIF=2
    a=rtpmap:96 H263-1998/90000
    a=fmtp:96 QCIF=2
    a=rtpmap:97 H263-N800/90000
    [/video_port]

Example config
--------------

.. literalinclude:: ../../../conf/services/sip.yaml.in
    :language: yaml
    :caption: services/sip.yaml
