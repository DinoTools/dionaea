# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Markus Koetter
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

check_c_source_runs("
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <unistd.h>
    #include <stdio.h>
    #include <errno.h>

    int main(int argc, char **argv)
    {
        int s = socket(PF_INET6, SOCK_STREAM, 0);
        int r = -1;
        struct sockaddr_in6 si6;
        memset(&si6,0,sizeof(struct sockaddr_in6));
        inet_pton(PF_INET6, \"::ffff:0.0.0.0\", &si6.sin6_addr);
        si6.sin6_family = PF_INET6;
        r = bind(s, (struct sockaddr *)&si6, sizeof(struct sockaddr_in6));
        close(s);
        return r;
    }"
    CAN_BIND_IPV4_MAPPED_IPV6
)
