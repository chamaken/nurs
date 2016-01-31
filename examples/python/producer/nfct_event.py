import socket, logging, sys

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_compath as nfnl_compat
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct
import cpylmnl as mnl
import cpylmnfct as nfct


log = None
nlsk = None # mnl.Socket
nlfd = None # nurs.Fd


@mnl.nlmsg_cb
def data_cb(nlh, producer):
    htype = nlh.nlmsg_type & 0xFF
    if htype == nfnlct.IPCTNL_MSG_CT_NEW:
        if nlh.nlmsg_flags & (netlink.NLM_F_CREATE|netlink.NLM_F_EXCL) != 0:
            etype =  nfct.NFCT_T_NEW
            mtype = "NEW"
        else:
            etype = nfct.NFCT_T_UPDATE
            mtype = "UPDATE"
    elif htype == nfnlct.IPCTNL_MSG_CT_DELETE:
        etype = nfct.NFCT_T_DESTROY
        mtype = "DESTROY"
    else:
        etype = nfct.NFCT_T_UNKNOWN
        mtype = "UNKNOWN"

    try:
        output = producer.get_output()

        with nfct.Conntrack() as ct:
            ct.nlmsg_parse(nlh)

            l3proto = ct.get_attr_u8(nfct.ATTR_L3PROTO)
            output["ct.event"] = etype
            output["ct.event.string"] = mtype
            output["oob.family"] = l3proto
            if ct.attr_is_set(nfct.ATTR_ORIG_L4PROTO):
                output["orig.ip.protocol"] = ct.get_attr_u8(nfct.ATTR_ORIG_L4PROTO)
            else:
                output["orig.ip.protocol"] = 0

            """
            if ct.attr_is_set(nfct.ATTR_ORIG_COUNTER_BYTES):
                output["orig.raw.pktlen.delta"] = ct.get_attr_u64(nfct.ATTR_ORIG_COUNTER_BYTES)
            else:
                output["orig.raw.pktlen.delta"] = 0
            if ct.attr_is_set(nfct.ATTR_ORIG_COUNTER_PACKETS):
                output["orig.raw.pktcount.delta"] = ct.get_attr_u64(nfct.ATTR_ORIG_COUNTER_PACKETS)
            else:
                output["orig.raw.pktcount.delta"] = 0

            if ct.attr_is_set(nfct.ATTR_REPL_COUNTER_BYTES):
                output["reply.raw.pktlen.delta"] = ct.get_attr_u64(nfct.ATTR_REPL_COUNTER_BYTES)
            else:
                output["reply.raw.pktlen.delta"] = 0
            if ct.attr_is_set(nfct.ATTR_REPL_COUNTER_PACKETS):
                output["reply.raw.pktcount.delta"] = ct.get_attr_u64(nfct.ATTR_REPL_COUNTER_PACKETS)
            else:
                output["reply.raw.pktcount.delta"] = 0
            """

            try:
                output["orig.raw.pktlen.delta"] = ct.get_attr_u64(nfct.ATTR_ORIG_COUNTER_BYTES)
                output["orig.raw.pktcount.delta"] = ct.get_attr_u64(nfct.ATTR_ORIG_COUNTER_PACKETS)
            except Exception:
                output["orig.raw.pktlen.delta"] = 0
                output["orig.raw.pktcount.delta"] = 0
            try:
                output["reply.raw.pktlen.delta"] = ct.get_attr_u64(nfct.ATTR_REPL_COUNTER_BYTES)
                output["reply.raw.pktcount.delta"] = ct.get_attr_u64(nfct.ATTR_REPL_COUNTER_PACKETS)
            except Exception:
                output["reply.raw.pktlen.delta"] = 0
                output["reply.raw.pktcount.delta"] = 0

            if (l3proto == socket.AF_INET):
                # log.info("set orig.ip.saddr")
                output["orig.ip.saddr"] = ct.get_attr_u32(nfct.ATTR_ORIG_IPV4_SRC)
                # log.info("set orig.ip.daddr")
                output["orig.ip.daddr"] = ct.get_attr_u32(nfct.ATTR_ORIG_IPV4_DST)
            elif (l3proto == socket.AF_INET6):
                output["orig.ip6.saddr"] = ct.get_attr_as(nfct.ATTR_ORIG_IPV6_SRC, (ctypes.c_ubyte * 16))
                output["orig.ip6.daddr"] = ct.get_attr_as(nfct.ATTR_ORIG_IPV6_DST, (ctypes.c_ubyte * 16))
    except Exception as e:
        log.error("failed to set output: %s", e)
        producer.put_output(output)
        return mnl.MNL_CB_ERROR

    try:
        producer.propagate(output)
    except Exception as e:
        log.error("failed to propagate: %s", e)
        return mnl.MNL_CB_ERROR

    return mnl.MNL_CB_OK


def nursfd_cb(fd, when, producer):
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    ret = fd.recv_into(buf)
    ret = mnl.cb_run(buf[:ret], 0, 0, data_cb, producer)
    if ret == mnl.MNL_CB_OK:
        return nurs.NURS_RET_OK
    return nurs.NURS_RET_ERROR


def organize(producer):
    try:
        global log
        logging.basicConfig(level=logging.INFO,
                            filename=producer.config['logfile'],
                            filemode='a',
                            format='%(asctime)s %(levelname)s %(module)s %(message)s')
        log = logging.getLogger(__name__)
    except Exception as e:
        nurs.Log.error("failed to prepare log: %s" % e)
        return nurs.NURS_RET_ERROR

    try:
        global nlsk
        nlsk = mnl.Socket(netlink.NETLINK_NETFILTER)
        nlsk.bind(nfnl_compat.NF_NETLINK_CONNTRACK_NEW |\
                  nfnl_compat.NF_NETLINK_CONNTRACK_DESTROY,
                  mnl.MNL_SOCKET_AUTOPID)
    except Exception as e:
        log.error("failed to prepare socket: %s", e)
        return nurs.NURS_RET_ERROR

    try:
        global nlfd
        nlfd = nurs.Fd(nlsk, nurs.NURS_FD_F_READ)
    except Exception as e:
        log.error("failed to create nurs fd: %s", e)
        return nurs.NURS_RET_ERROR

    return nurs.NURS_RET_OK


def disorganize(producer):
    try:
        global nlsk
        global nlfd

        # nurs.Fd has no destroy() method
        # destroy in dealloc()
        nlfd = None
        nlsk.close()
        nlfd = None
    except Exception as e:
        log.error("failed to disorganize: %s", e)
        return nurs.NURS_RET_ERROR

    return nurs.NURS_RET_OK


def start(producer):
    try:
        nlfd.register(nursfd_cb, producer)
    except Exception as e:
        log.error("failed to register fd callback: %s", e)
        return nurs.NURS_RET_ERROR

    return nurs.NURS_RET_OK


def stop(producer):
    try:
        nlfd.unregister()
    except Exception as e:
        log.error("failed to stop: %s", e)
        return nurs.NURS_RET_ERROR

    return nurs.NURS_RET_OK
