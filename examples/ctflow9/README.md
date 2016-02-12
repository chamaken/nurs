Publish Netflow from monitor port
---------------------------------

This directory contains nursd configuration to export Netflow v9 made from
conntrack. This is based on an Linux box is a router, forwarding packets. Apart
from the case, conntrack entry can be created from monitor port. I would like to
jot it down here for myself.

We have L3 network switch which can not publish flow data, but want to classify
traffic data by address, protocol, port and staff like that. Assume the L3
switch has one interface for each inbound and outbound. Configure a port to
monitor both the inbound and the outbound, then connect a Linux box to that
monitoring port.

There seems to be many ways to create conntrack from the monitor port and
separate from local, here I introduce two of them: use ctmark and namespace. We
can create conntrack entries from the monitor port without those, but the
entries will consists of both monitoring and Linux box local self, will be
easy to be confused.

Before divide monitoring from local self, configure to create conntrack from
monitoring interface, assume monitoring interface is eth1 in this example.

<pre>
  1:  echo 1 > /proc/sys/net/ipv4/ip_forward
  2:  ip link add null0 type dummy
      ip link set null0 up
      ip link set eth1 up
      ip link set eth1 promisc on
  3:  ip route add default dev null0 table 200
      ip rule add iif eth1 table 200
  4:  brctl addbr br0
      ip link set br0 up
  5:  brctl addif br0 eth1
  6:  ebtables -t broute -I BROUTING -i eth1 -j redirect --redirect-target DROP
  7:  modprobe nf_conntrack_ipv4
  8:  echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct
      echo 1 > /proc/sys/net/netfilter/nf_conntrack_timestamp
</pre>

1. enable ip forwarding
2. create dummy, blackhole interface
3. routing packets from monitor interface to dummy interface
4. create a bridge
5. add monitor interface to the bridge
6. DROP frame to netfilter by ebtables
7. load conntrack module
8. set /proc entries

We can see conntrack created by both local self and monitor by
using conntrack-tool, conntrack -E.

using ctmark is easy, just mark packets from eth1:

      iptables -t nat -I PREROUTING -i eth1 -j CONNMARK --set-mark 1
      (you may need to flush conntrack entries by conntrack -F)


then, only monitor conntrack can be seen by:

      conntrack -E -m 1

and local conntrack:

      conntrack -E -m 0

With this setup, nursd configuration to create monitor Netflow entry
is just add mark_filter parameter for NFCT2.

      [global]
      plugin	= "@pkglibdir@/nurs_producer_NFCT2.so"
      ...
      stack	= "nfct2:NFCT2...

      [nfct2]
      mark_filter = 1

Another way, use namespace, requires commands like below:

<pre>
  01: ip netns add monitorns
  02: ip link set eth1 netns monitorns
  03: ip netns exec monitorns bash
  1:  echo 1 > /proc/sys/net/ipv4/ip_forward
  2:  ip link add null0 type dummy
      ip link set null0 up
      ip link set eth1 up
      ip link set eth1 promisc on
  3:  ip route add default dev null0 table 200
      ip rule add iif eth1 table 200
  4:  brctl addbr br0
      ip link set br0 up
  5:  brctl addif br0 eth1
  6:  ebtables -t broute -I BROUTING -i eth1 -j redirect --redirect-target DROP
  7:  modprobe nf_conntrack_ipv4
  8:  echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct
      echo 1 > /proc/sys/net/netfilter/nf_conntrack_timestamp
   :  (logout)
</pre>

This creates new network namespace "monitorns", pass eth1 to it, create dummy
and bridge and so on in the namespace. Then monitor conntrack entries will be
created in the monitorns namespace. To see the entries in the monitorns
namespace:

      ip netns exec monitorns conntrack -E

and local conntrack entries can be seen by just:

      conntrack -E

To publish Netflowv9 from that namespace, configuration is like:

      [nfct2]
      namespace = "monitorns"

That's it for now.

Copyright (C) 2016 Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>

This documentation is licenced under the terms of the Creative Commons
Attribution-ShareAlike 4.0 license, CC BY-SA 4.0.
