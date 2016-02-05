I needed to account network traffic and looked for, I found some libpcap base  
accounting software. I kept searching, understood linux has kernel  
space accounting system conntrack, not need to account in userspace, and  
found software named ulogd which use it.

<!--
ネットワークトラヒックの集計が必要で、調べてみたところ、いくつか libpcap ベース  
のソフトウェアがみつかりました。もう少し調べてみると linux ではユーザースペース  
で集計せずとも、カーネル内で集計している conntrack というものが存在することがわ  
かり、これを基とした ulogd というソフトウェアがありました。  
-->

I had thought I needed IPFIX but it was Netflow version9 actually. Then I tried to  
create ulogd patches and post it. I'm not good at English and my lack of  
knowledge, those patches were not accepted but used it in personal.  

<!--
当初は IPFIX が必要と思い込んでいたものの、実際は Netflow version 9 を用いること  
になったので ulogd のパッチをいくつか作り、メーリングリストに送りました。私の技  
術と英語が拙かったため採用されませんでしたが、内々で使っていました。  
-->

After that, I found next-generation ulogd trying to be a multithreaded and (rx  
side) mmaped netlink socket has been implemented in kernel. I tried to use those  
tech and implement similar to ulogd, that's why this Nfnetlink Userspace Receipt  
Suite has been made.  

<!--
その後、次期 ulogd ではマルチスレッド化を目指していることや、netlink の情報を取  
得するにあたって、より早い mmaped ソケットの存在を知りました。ふまえて ulogd に  
似たものを自分で実装してみた結果、この Nfnetlink Userspace Receipt Suite が出来  
た次第です。  
-->

As described above, I am only using examples/ctflow9 now since I am satisfied  
with converting conntrack information to Netflow version9 format. There is less  
document (patches for doc are welcome too!) and other samples under examples/  
were just for my interest, has not tested well. But I'm glad if you refer those  
samples to use this software. Thanks,  

<!--
上記通り、個人的には conntrack の情報を Netflow version 9 として扱うことができれ
ば十分なので、実際に使っている方法は examples/ctflow9 の下にあるものだけです。こ
ちらも前述通り、ドキュメントもありません (ドキュメントのパッチも歓迎です)。
ctflow9 を除く example 以下は興味本位だけのもので、あまりテストしていませんが、  
こちらを参考にし ていただければ幸いです。
-->

ulogd2 is userspace logging daemon for netfilter/iptables  
(http://www.netfilter.org/projects/ulogd/), see README.ulogd2


prerequisites
=============
* libmnl (http://www.netfilter.org/projects/libmnl/)  
  current git (2015-10-03) is better,  
  since go and python binding implements mnl_socket_open2()
* libjansson (http://www.digip.org/jansson/)
* liburcu2 (http://liburcu.org/)  
  (atomic operation only, it can be replaced by GCC builtins.)

optional
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
