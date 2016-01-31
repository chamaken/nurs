import logging, sys, ipaddress, socket
import cpylmnfct as nfct

log = logging.getLogger(__name__)
protos = {}

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

    global protos
    for line in open('/etc/protocols'):
        if len(line) == 0 or line.startswith('#'):
            continue
        f = line.split()
        if len(f) < 3:
            continue
        protos[int(f[1])] = f[0]

    return nurs.NURS_RET_OK


def interp(plugin, nuin):
    etype = nuin.value("ct.event")
    if etype == nfct.NFCT_T_NEW:
        event = "NEW"
    elif etype == nfct.NFCT_T_UPDATE:
        event = "UPDATE"
    elif etype == nfct.NFCT_T_DESTROY:
        event = "DESTROY"
    else:
        event = "UNKNOWN"

    family = nuin.value("oob.family")
    if family == socket.AF_INET:
        saddr = ipaddress.IPv4Address(socket.ntohl(nuin.value("orig.ip.saddr")))
        daddr = ipaddress.IPv4Address(socket.ntohl(nuin.value("orig.ip.daddr")))
    elif family == socket.AF_INET6:
        nid, iid = struct.unpack('!QQ', nuin.value("orig.ip6.saddr"))
        saddr = ipaddress.IPv6Address((nid << 64) | iid)
        nid, iid = struct.unpack('!QQ', nuin.value("orig.ip6.saddr"))
        daddr = ipaddress.IPv6Address((nid << 64) | iid)
    else:
        saddr = "(unknown addr)"
        daddr = "(unknown addr)"

    global protos
    msg = "%s %s >> %s %s" % \
          (event, saddr, daddr,
           protos.get(nuin.value("orig.ip.protocol"), "unknown-protocol"))
    # if etype == nfct.NFCT_T_DESTROY:
    if nuin.is_valid("orig.raw.pktcount.delta"):
        msg = "%s >>[%d / %d] <<[%d / %d]" % \
              (msg,
               nuin.value("orig.raw.pktcount.delta"),
               nuin.value("orig.raw.pktlen.delta"),
               nuin.value("reply.raw.pktcount.delta"),
               nuin.value("reply.raw.pktlen.delta"))

    log.info(msg)

    return nurs.NURS_RET_OK
