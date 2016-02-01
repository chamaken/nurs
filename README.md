This is unstable multithreaded re-implementation of ulogd2,  
nfnetlink userspace receipt suite, nurs.

ulogd2 is userspace logging daemon for netfilter/iptables  
(http://www.netfilter.org/projects/ulogd/), see README.ulogd2


prerequisites
=============

* libmnl (http://www.netfilter.org/projects/libmnl/)
* libjansson (http://www.digip.org/jansson/)
* liburcu2 (http://liburcu.org/)  
  atomic operation only, can it be replaced by GCC builtins? 

optional
--------

* libnetfilter-acct (http://www.netfilter.org/projects/libnetfilter_acct/)
* libnetfilter-log (http://www.netfilter.org/projects/libnetfilter_log/)
* libnetfilter-queue (http://www.netfilter.org/projects/libnetfilter_queue/)
* libnetfilter-conntrack (http://www.netfilter.org/projects/libnetfilter_conntrack/)
* libnftnl (http://www.netfilter.org/projects/libnftnl/)
* python3 (I use debian jessie which has 3.4)
  - cpylmnl (https://github.com/chamaken/cpylmnl)
  

installation
============

```
$ ./autogen.sh
$ ./configure
$ make
# make install
```


sample
======

python required. cd examples/tick after install

```
NURS_PYSON=consumer_py.json ../../src/nursd nursd1.conf
```

head *.conf file under examples directory.


Go
==

It's my fault, lack of knowledge, I've met runtime errors.  
a few of them seems related to:

* https://groups.google.com/forum/#!msg/golang-nuts/h9GbvfYv83w/5Ly_jvOr86wJ
* https://github.com/golang/go/issues/12879
* https://gist.github.com/dwbuiten/c9865c4afb38f482702e

nurs handles signals synchronously by signalfd with blocking, but go seems  
to call sigprocmask in runtime and to establish its own signal handler.  

in addition to signal handling, I do not understand Go's GC. examples seems  
to work (not stop correctly) with GOGC=off but it's useless for real use at all.  
I should have run go plugin in another process like python one, but it seems  
to be hard for me.

To disable go extension examples, run configure without go in PATH env.


TODO
====

* docmentation, can be cite from ulogd2

* needs more tests

* put / propagate for output may cause trouble.
  add borrowing flag for duplicate calling?

* input key which has VALID flag will not check at runtime.  
  should check at propagate / interp?

* resolve plugin symbols not only from self, but also from global.

* try to implement rust binding.

* (seems to be) useful packet library for nflog and nfq.
  - https://github.com/phaethon/scapy
  - https://github.com/google/gopacket
  - https://github.com/libpnet/libpnet


memo
====

* input / output key size aligned 4

* start callback is needed only for producer?

* switch / case statements for struct nurs_plugin.type seems nasty things?

* filter / consumer which input is all optional may receive no input.

* ioset depends on producer which has stack(s).  
  owner of iosets is producer, not stack

* python nurs functions can be called in only callback,  
  can not be called from thread asynchnoursly created in python.

* signal callback must be called when all workers stop.

* struct nurs_ioset
<pre>
stack = "src, f1, f2, ...

    +------------------------------                +----
 ---+ nurs_ioset      .list -----------------------+ nurs_ioset: .list -- (for pool)
    |                 .size: byte size             |
    |                 .len:  array len
    +-----------------.base ----
 0: | src.output: .len: 4, .keys ----------------/              stack.element.0.odx = 0
    +------------------------------             /
 1: | f1.input:   .len: 3, .keys -------------------------/                   1.idx = 1
    +------------------------------           /          /
 2: | f1.output:  .len: 2,                   /          /                     1.odx = 2
    +------------------------------         /          /
    .                                      /          /
    .                                     v          /
    +-------------------------------------+--       /
    | src.output .keys[0]                          /
    +------------------------------               /
    |            .keys[1]                        /
    +------------------------------ <---+       /
    |            .keys[2]               |      /
    +------------------------------     |     /
    |            .keys[3]               |    v
    +-----------------------------------+----+--
    | f1.input   .keys[0] --------------+
    +------------------------------
    |            .keys[1]
    +------------------------------
    |            .keys[2]
    +------------------------------
    | f1.output  .keys[0]
    +------------------------------
    |            .keys[1], .len > 0, .ptr: ----------/
    +------------------------------                 /
    .                                              /
    .                                             /
    .                                            /
    +------------------------------             /
    | struct nfct_bitmask valid_output         v
    +------------------------------------------+----
    | embed data area
    |
    +------------------------------
</pre>
