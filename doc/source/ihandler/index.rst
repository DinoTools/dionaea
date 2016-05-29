Logging (ihandler)
==================

Getting a copy of the malware is cool, getting an overview of the attacks run on your sensor is priceless.

dionaea can write information to a text file, but be aware, dionaeas
logging to text files is rather chatty, really chatty, and you do not
want to look at the information, if you are not debugging the software
or writing some new feature for it.

Of course, you can appy filters to the logging, to limit it to different
facilities or levels, but in general you do not want to work with text
files.

dionaea uses some internal communication system which is called incidents.
An incident has an origin, which is a string, a path, and properties, which can be integers, strings, or a pointer to a connection.
Incidents limit to the max, they pass the information required to incident handlers (ihandler).
An ihandler can register a path for incidents he wants to get informed about, the pathes are matched in a glob like fashion.
Therefore logging information using an ihandler is superior to text logging, you get the information you are looking for, and can write it to a format you choose yourself.

List of available ihandlers

.. toctree::
    :maxdepth: 2

    emuprofile
    fail2ban
    ftp
    hpfeeds
    log_json
    log_sqlite
    nfq
    p0f
    store
    submit_http
    submit_http_post
    virustotal
