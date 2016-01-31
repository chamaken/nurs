import logging

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


"""
0: sum.name
1: sum.pkts
2: sum.bytes
3: nfacct
4: oob.time.sec		(optional)
5: oob.time.usec	(optional)
"""
def interp(plugin, nuin):
    log.info("name: %s, packets: %d, bytes: %d",
             nuin.value(0), nuin.value(1), nuin.value(2))

    return nurs.NURS_RET_OK
