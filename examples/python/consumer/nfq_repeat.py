# requires:
# scapy-python3	https://github.com/phaethon/scapy
# cpylm*	https://github.com/chamaken/

import logging
import ctypes, socket, struct

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_queueh as nfqnl
import cpylmnl.linux.netfilterh as nf
import cpylmnl as mnl
import cpylmnfq as nfq

from scapy.layers.inet import IP, ICMP
from scapy import utils


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

def start(ikset):
    global nl
    nl = mnl.Socket(netlink.NETLINK_NETFILTER)
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
    global nl

    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_VERDICT, queue_num)
    nlh.nlmsg_flags |= netlink.NLM_F_ACK
    nfq.nlmsg_verdict_put(nlh, qid, nf.NF_ACCEPT)

    nl.send_nlmsg(nlh)
    nrecv = nl.recv_into(buf)
    return mnl.cb_run(buf[:nrecv], 0, 0, None, None)


def nfq_send_repeat(queue_num, qid, mark, payload):
    global nl

    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE + len(payload))
    nlh = nfq_hdr_put(buf, nfqnl.NFQNL_MSG_VERDICT, queue_num)
    nlh.nlmsg_flags |= netlink.NLM_F_ACK
    nfq.nlmsg_verdict_put(nlh, qid, nf.NF_REPEAT)

    nlh.put_u32(nfqnl.NFQA_MARK, socket.htonl(mark));
    nlh.put(nfqnl.NFQA_PAYLOAD, payload)
    nl.send_nlmsg(nlh)
    nrecv = nl.recv_into(buf)
    return mnl.cb_run(buf[:nrecv], 0, 0, None, None)


def interp(plugin, nuin):
    family = nuin.value(0)
    res_id = nuin.value(1);
    pattrs = (ctypes.POINTER(mnl.Attr) * (nfqnl.NFQA_MAX + 1)).from_buffer(nuin.value(2))
    ph = pattrs[nfqnl.NFQA_PACKET_HDR].contents.get_payload_as(nfqnl.NfqnlMsgPacketHdr)
    packet_id = socket.ntohl(ph.packet_id)
    log.info("res_id: %d, qid: %d", res_id, packet_id)

    if pattrs[nfqnl.NFQA_PAYLOAD]:
        nfq_payload = pattrs[nfqnl.NFQA_PAYLOAD].contents
        ip = IP(bytes(nfq_payload.get_payload_v()))

        if ip[ICMP].seq % 2 == 0:
            # wrong data byte ...
            ip[ICMP].payload = bytes(ip[ICMP].payload).replace(b'!', b'@')

            # (truncated)
            # ip[ICMP].payload = bytes(ip[ICMP].payload)[:4]

            # no error but ``bytes from'' is differ a little?
            # ip[ICMP].payload = bytes(ip[ICMP].payload) + (b'0' * 8192)

            ip[ICMP].chksum = 0 # NEED THIS
            ip[ICMP].chksum = utils.checksum(bytes(ip[ICMP]))

        nfq_send_repeat(res_id, packet_id, 10, (ctypes.c_ubyte * len(ip)).from_buffer(bytearray(bytes(ip))))
    else:
        nfq_send_accept(res_id, packet_id)

    return nurs.NURS_RET_OK
