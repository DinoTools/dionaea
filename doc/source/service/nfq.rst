nfq
===

The python nfq script is the counterpart to the nfq module.
While the nfq module interacts with the kernel, the nfq python script takes care of the required steps to start a new service on the ports.
nfq can intercept incoming tcp connections during the tcp handshake giving your honeypot the possibility to provide service on ports which are not served by default.

As dionaea can not predict which protocol will be spoken on unknown ports, neither implement the protocol by itself, it will connect the attacking host on the same port, and use the attackers server side protocol implementation to reply to the client requests of the attacker therefore dionaea can end up re?exploiting the attackers machine, just by sending him the exploit he sent us.

The technique is a brainchild of Tillmann Werner, who used it within his honeytrap <http://honeytrap.carnivore.it> honeypot.
Legal boundaries to such behaviour may be different in each country, as well as ethical boundaries for each individual.
From a technical point of view it works, and gives good results.
Learning from the best, I decided to adopt this technique for dionaea.
Besides the legal and ethical issues with this approach, there are some technical things which have to be mentioned

**port scanning**

    If your honeypot gets port scanned, it would open a service for each port scanned, in worst case you'd end up with offering 64k services per ip scanned.
    By default you'd run out of fds at about 870 services offerd, and experience weird behaviour.
    Therefore the impact of port scanning has to be limited.
    The kiss approach taken here is a sliding window of *throttle.window* seconds size.
    Each slot in this sliding window represents a second, and we increment this slot for each connection we accept.
    Before we accept a connection, we check if the sum of all slots is below *throttle.limits.total*, else we do not create a new service.
    If the sum is below the limit, we check if the current slot is below the slot limit too, if both are given, we create a new service.
    If one of the condition fails, we do not spawn a new service, and let nfqeueu process the packet.
    There are two ways to process packets which got throttled:

    - **NF_ACCEPT** (=1), which will let the packet pass the kernel, and as there is no service listening, the packet gets rejected.
    - **NF_DROP** (=0), which will drop the packet in the kernel, the remote does not get any answer to his SYN.

    I prefer NF_DROP, as port scanners such as nmap tend to limit their scanning speed, once they notice packets get lost.

**recursive-self-connecting**

    Assume some shellcode or download instructions makes dionaea to

    - connect itself on a unbound port
    - nfq intercepts the attempt
    - spawns a service
    - accepts the connection #1
    - creates mirror connection for connection #1 by connecting the remotehost (itself) on the same port #2
    - accepts connection #2 as connection #3
    - creates mirror connection for connection #3 by connecting the remotehost (itself) on the same port #4
    - ...

    Such recursive loop, has to be avoided for obvious reasons.
    Therefore dionaea checks if the remote host connecting a nfq mirror is a local address using 'getifaddrs' and drops local connections.

So much about the known problems and workarounds ...

If you read that far, you want to use it despite the technical/legal/ethical problems.
So ... You'll need iptables, and you'll have to tell iptables to enqueue packets which would establish a new connection.
I recommend something like this:

.. code-block:: console

    iptables -t mangle -A PREROUTING -i eth0 -p tcp -m socket -j ACCEPT
    iptables -t mangle -A PREROUTING -i eth0 -p tcp --syn -m state --state NEW -j NFQUEUE --queue-num 5

Explanation:

 1. ACCEPT all connections to existing services
 2. enqueue all other packets to the NFQUEUE


If you have dionaea running on your NAT router, I recommend something like:

.. code-block:: console

    iptables -t mangle -A PREROUTING -i ppp0 -p tcp -m socket -j ACCEPT
    iptables -t mangle -A PREROUTING -i ppp0 -p tcp --syn -m state --state NEW -j MARK --set-mark 0x1
    iptables -A INPUT -i ppp0 -m mark --mark 0x1 -j NFQUEUE

Explanation:

 1. ACCEPT all connections to existing services in mangle::PREROUTING
 2. MARK all other packets
 3. if we see these marked packets on INPUT, queue them


Using something like:

.. code-block:: console

    iptables -A INPUT -p tcp --tcp-flags SYN,RST,ACK,FIN SYN -j NFQUEUE --queue-num 5

will enqueue /all/ SYN packets to the NFQUEUE, once you stop dionaea you will not even be able to connect to your ssh daemon.

Even if you add an exemption for ssh like:

.. code-block:: console

    iptables -A INPUT -i eth0 -p tcp --syn -m state --state NEW --destination-port ! 22 -j NFQUEUE

dionaea will try to create a new service for /every/ incoming connection, even if there is a service running already.
As it is easy to avoid this, I recommend sticking with the recommendation.
Besides the already mention throttle settings, there are various timeouts for the nfq mirror service in the config.
You can control how long the service will wait for new connections (/timeouts.server.listen/), and how long the mirror connection will be idle (/timeouts.client.idle/) and sustain (/timeouts.client.sustain/).
