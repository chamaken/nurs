# requires:
# scapy-python3	https://github.com/phaethon/scapy
# cpylm*	https://github.com/chamaken/

import logging
import ctypes, socket

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_logh as nflog
import cpylmnl.linux.netfilterh as nf
import cpylmnl as mnl
import cpylmnfct as nfct

from scapy.layers.inet import IP


log = logging.getLogger(__name__)


def organize(plugin):
    try:
        global log
        logging.basicConfig(level=logging.INFO,
                            filename=plugin.config['logfile'],
                            filemode='a',
                            format='%(asctime)s %(levelname)s %(module)s %(message)s')
        log = logging.getLogger(__name__)
    except Exception as e:
        nurs.Log.error("failed to prepare log: %s" % e)
        return nurs.NURS_RET_ERROR

    return nurs.NURS_RET_OK


# key index
#	0: "oob.hook"
#	1: "oob.family"
#	2: "oob.protocol"
#	3: "nflog.attrs"
#	4: "oob.seq.global"	optional
#	5: "oob.seq.local"	optional
#	6: "oob.prefix"		optional
def interp(plugin, nuin):
    hook = nuin.value(0)
    family = nuin.value(1)
    protocol = nuin.value(2)
    pattrs = (ctypes.POINTER(mnl.Attr) * (nflog.NFULA_MAX + 1)).from_buffer(nuin.value(3))
    # pattrs = (ctypes.POINTER(mnl.Attr) * (nflog.NFULA_MAX + 1)).from_address(nuin.value(3))
    seq_global = 0
    if nuin.is_valid(4):
        seq_global = nuin.value(4)
    seq_local = 0
    if nuin.is_valid(5):
        seq_local = nuin.value(5)
    prefix = ""
    if nuin.is_valid(6):
        prefix = nuin.value(6)

    log.info("hook: %d, family: %d, protocol: %d, prefix: %s, seq - global: %d, local: %d",
             hook, family, protocol, prefix, seq_global, seq_local)

    if pattrs[nflog.NFULA_PAYLOAD] is not None:
        ip = IP(bytes(pattrs[nflog.NFULA_PAYLOAD].contents.get_payload_v()))
        log.info(ip.summary())

    if pattrs[nflog.NFULA_CT]:
        ct = nfct.Conntrack()
        ct.payload_parse(pattrs[nflog.NFULA_CT].contents.get_payload_v(), family)
        b = ct.snprintf(4096, nfct.NFCT_T_UNKNOWN, nfct.NFCT_O_DEFAULT, 0)
        log.info("conntrack: %s", str(b))

    return nurs.NURS_RET_OK
