# requires:
# scapy-python3	https://github.com/phaethon/scapy
# cpylm*	https://github.com/chamaken/

import logging
import ctypes, socket

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_queueh as nfqnl
import cpylmnl.linux.netfilterh as nf
import cpylmnl as mnl
import cpylmnfq as nfq
import cpylmnfct as nfct

from scapy.layers.inet import IP


log = logging.getLogger(__name__)
nl = None # mnl.Socket


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

    try:
        global nl
        nl = mnl.Socket(netlink.NETLINK_NETFILTER)
    except Exception as e:
        nurs.Log.error("failed to open socket: %s" % e)
        return nurs.NURS_RET_ERROR

    return nurs.NURS_RET_OK


def disorganize(plugin):
    global nl
    try:
        nl.close()
    except Exception as e:
        return nurs.NURS_RET_ERROR

    return nurs.NURS_RET_OK


def nfq_hdr_put(buf, nltype, queue_num):
    nlh = mnl.Nlmsg(buf)
    nlh.put_header()
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_QUEUE << 8) | nltype
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.nfgen_family = socket.AF_UNSPEC
    nfg.version = nfnl.NFNETLINK_V0
    nfg.res_id = socket.htons(queue_num)

    return nlh


def nfq_send_accept(queue_num, qid):
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_VERDICT, queue_num)
    nfq.nlmsg_verdict_put(nlh, qid, nf.NF_ACCEPT)

    nl.send_nlmsg(nlh)


# 0: "oob.family"
# 1: "oob.res_id"
# 2: "nflog.attrs"
def interp(plugin, nuin):
    family = nuin.value(0)
    res_id = nuin.value(1);
    pattrs = (ctypes.POINTER(mnl.Attr) * (nfqnl.NFQA_MAX + 1)).from_buffer(nuin.value(2))

    ph = pattrs[nfqnl.NFQA_PACKET_HDR].contents.get_payload_as(nfqnl.NfqnlMsgPacketHdr)
    packet_id = socket.ntohl(ph.packet_id)
    log.info("res_id: %d, qid: %d", res_id, packet_id)
    nfq_send_accept(res_id, packet_id)

    if pattrs[nfqnl.NFQA_PAYLOAD]:
        ip = IP(bytes(pattrs[nfqnl.NFQA_PAYLOAD].contents.get_payload_v()))
        log.info(ip.summary())

    if pattrs[nfqnl.NFQA_IFINDEX_INDEV]:
        ifin = pattrs[nfqnl.NFQA_IFINDEX_INDEV].contents.get_u32()
        log.info("indev: %d", socket.ntohl(ifin));
    if pattrs[nfqnl.NFQA_IFINDEX_OUTDEV]:
        ifout = pattrs[nfqnl.NFQA_IFINDEX_OUTDEV].contents.get_u32()
        log.info("outdev: %d", socket.ntohl(ifout));

    if pattrs[nfqnl.NFQA_CT]:
        ct = nfct.Conntrack()
        ct.payload_parse(pattrs[nfqnl.NFQA_CT].contents.get_payload_v(), family)
        s = ct.snprintf(4096, nfct.NFCT_T_UNKNOWN, nfct.NFCT_O_DEFAULT, 0)
        log.info("conntrack: %s", s)

    return nurs.NURS_RET_OK
