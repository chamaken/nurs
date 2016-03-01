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
* Go 1.6
  - cgolmnl (https://github.com/chamaken/cgolmnl)


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
NURS_PYSON=consumer_py.json ../../src/nursd py.conf
```
Or with go,
```
../../src/nursd go.conf
```

see *.conf files under examples directories.


Python
======
* python nurs functions can be called in only callback,  
  can not be called from thread asynchnoursly created in python.
* can not read input data which is allocated in producer or filter.  
  Python plugin forks at organize callback, can read only pre-allocated  
  mmaped area just before organize call back.



TODO
====

* docmentation, can be cite from ulogd2
* needs more tests
* resolve plugin symbols not only from self, but also from global.
* try to implement rust binding.

* put / propagate for output may cause trouble.  
  add borrowing flag for duplicate calling?


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

    +------------------------------              +--------
 ---+ nurs_ioset      .list ---------------------+ nurs_ioset: .list -- (for pool)
    |                 .size: byte size           |
    |                 .len:  array len
    +-----------------.base ----
 0: | src.output: .len: 4, .keys ----------------/          stack.element.0.odx = 0
    +------------------------------             /
 1: | f1.input:   .len: 3, .keys -------------------------/               1.idx = 1
    +------------------------------           /          /
 2: | f1.output:  .len: 2,                   /          /                 1.odx = 2
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
