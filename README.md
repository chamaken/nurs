Background
==========

I needed to collect network traffic, and, after searching, I found several  
libpcap-based softwares. With a little more research, I found that, even without  
collecting in userspace, Linux has something called conntrack that collects data  
from within the kernel. There is a software called ulogd that uses this as a  
module.  

<!--
ネットワークトラヒックの集計が必要で、調べてみたところ、いくつか libpcap ベース  
のソフトウェアがみつかりました。もう少し調べてみると linux ではユーザースペース  
で集計せずとも、カーネル内で集計している conntrack というものが存在することがわ  
かり、これを基とした ulogd というソフトウェアがありました。  
-->

Although at first I believed that I need IPFIX was necessary, in actuality is  
Netflow ver. 9, so I made several patches for ulogd and sent it out to the  
mailing list. It wasn't adopted because my technical skills and English ability  
weren't enough, but it was used privately.  

<!--
当初は IPFIX が必要と思い込んでいたものの、実際は Netflow version 9 を用いること  
になったので ulogd のパッチをいくつか作り、メーリングリストに送りました。私の技  
術と英語が拙かったため採用されませんでしたが、内々で使っていました。  
-->

Afterwards, I learned that ulogd was aiming for multithreading and that, when  
acquiring netlink information, a faster mmaped socket existed. I made my own  
implementation based on ulogd, which created this Nfnetlink Userspace Receipt  
Suite.  

<!--
その後、次期 ulogd ではマルチスレッド化を目指していることや、netlink の情報を取  
得するにあたって、より早い mmaped ソケットの存在を知りました。ふまえて ulogd に  
似たものを自分で実装してみた結果、この Nfnetlink Userspace Receipt Suite が出来  
た次第です。  
-->

As described above, personally it is plenty to be able to use conntrack  
information as Netflow ver. 9, so the methods actually being used are under  
examples/ctflow9. There is less document (I would welcome document patches too).  
Other examples outside of ctflow9 are only for the interests sake and haven't  
been tested well, but I would be pleased if you could take them into  
consideration. (Thank you to Gengo for translating the above document.)  

<!--
上記通り、個人的には conntrack の情報を Netflow version 9 として扱うことができれ
ば十分なので、実際に使っている方法は examples/ctflow9 の下にあるものだけです。こ
ちらも前述通り、ドキュメントもありません (ドキュメントのパッチも歓迎です)。
ctflow9 を除く example 以下は興味本位だけのもので、あまりテストしていませんが、  
こちらを参考にし ていただければ幸いです。
-->

ulogd2 is userspace logging daemon for netfilter/iptables  
(http://www.netfilter.org/projects/ulogd/), see README.ulogd2


Prerequisites
=============
* libmnl (http://www.netfilter.org/projects/libmnl/)  
  current git (2015-10-03) is better,  
  since go and python binding implements mnl_socket_open2()
* libjansson (http://www.digip.org/jansson/)

Optional
--------
* mmaped netlink available kernel (>= 4.5 is better see:  
  commit aa3a022094fac7f6e48050e139fa8a5a2e3265ce  
  commit 1853c949646005b5959c483becde86608f548f24)
* libnetfilter-acct (http://www.netfilter.org/projects/libnetfilter_acct/)
* libnetfilter-log (http://www.netfilter.org/projects/libnetfilter_log/)  
  require recent nflog_nlmsg_parse()
* libnetfilter-queue (http://www.netfilter.org/projects/libnetfilter_queue/)
* libnetfilter-conntrack (http://www.netfilter.org/projects/libnetfilter_conntrack/)
* libnftnl (http://www.netfilter.org/projects/libnftnl/)
* python3 (I use debian jessie which has 3.4)  
  - cpylmnl (https://github.com/chamaken/cpylmnl)


Installation
============
```
$ ./autogen.sh
$ ./configure
$ make
# make install
```


Sample
======
python required. cd examples/tick after install
```
NURS_PYSON=consumer_py.json ../../src/nursd nursd1.conf
```
head *.conf file under examples directories.


Python
======
* python nurs functions can be called in only callback,  
  can not be called from thread asynchnoursly created in python.
* can not read input data which is allocated in producer or filter.  
  Python plugin forks at organize callback, can read only pre-allocated  
  mmaped area just before organize call back.


Go
==
It's my fault, lack of knowledge, I've met runtime errors.  
a few of them seems related to:  

* https://groups.google.com/forum/#!msg/golang-nuts/h9GbvfYv83w/5Ly_jvOr86wJ
* https://github.com/golang/go/issues/12879
* https://gist.github.com/dwbuiten/c9865c4afb38f482702e

nurs handles signals synchronously by signalfd with blocking, but go seems  
to call sigprocmask in runtime and to establish its own signal handler.  

... Above seems to be solved 1.6?  
https://github.com/golang/go/commit/fbdfa99246ecbb04954a042a5809c4748415574d  
Exit process is obviously differ from 1.5.  

in addition to signal handling, I do not understand Go's GC. examples seems  
to work (not stop correctly) with GOGC=off but it's useless for real use at all.  
I should have run go plugin in another process like python one, but it seems  
to be hard for me.

This GC problem still exists at 1.6.
<pre>
runtime: free list of span 0x7f4fef181438:
0x1c820018140 -> 0x1c9200181de (BAD)
fatal error: free list corrupted

runtime stack:
runtime.throw(0x7f4fea5d7510, 0x13)
        /usr/local/go/src/runtime/panic.go:530 +0x92
runtime.(*mspan).sweep(0x7f4fef181438, 0x300000000, 0x1c800000001)
        /usr/local/go/src/runtime/mgcsweep.go:201 +0x856
runtime.sweepone(0x0)
        /usr/local/go/src/runtime/mgcsweep.go:112 +0x242
runtime.gosweepone.func1()
        /usr/local/go/src/runtime/mgcsweep.go:124 +0x23
runtime.systemstack(0x7f4fea0e2e20)
        /usr/local/go/src/runtime/asm_amd64.s:307 +0xa1
runtime.gosweepone(0x7f4fea68e1e8)
        /usr/local/go/src/runtime/mgcsweep.go:125 +0x3f
runtime.deductSweepCredit(0x2000, 0x0)
        /usr/local/go/src/runtime/mgcsweep.go:384 +0xc8
...
</pre>

To disable go extension examples, run configure without go in PATH env.


TODO
====

* docmentation, can be cite from ulogd2
* needs more tests
* resolve plugin symbols not only from self, but also from global.
* try to implement rust binding.

* put / propagate for output may cause trouble.  
  add borrowing flag for duplicate calling?
* input key which has VALID flag will not check at runtime.  
  should check at propagate / interp?


memo
====

* input / output key size aligned 4
* switch / case statements for struct nurs_plugin.type seems nasty things.
* filter / consumer which input is all optional may receive no input.
* ioset depends on producer which has stack(s).  
  owner of iosets is producer, not stack
* signal callback must be called when all workers stop.
* (seems to be) useful packet library for nflog and nfq packet payload.
  - https://github.com/phaethon/scapy
  - https://github.com/google/gopacket
  - https://github.com/libpnet/libpnet

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
