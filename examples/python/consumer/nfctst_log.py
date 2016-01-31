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
 0: nfct.stats.searched
 1: nfct.stats.found
 2: nfct.stats.new
 3: nfct.stats.invalid
 4: nfct.stats.ignore
 5: nfct.stats.delete
 6: nfct.stats.delete_list
 7: nfct.stats.insert
 8: nfct.stats.insert_failed
 9: nfct.stats.drop
10: nfct.stats.early_drop
11: nfct.stats.error
12: nfct.stats.search_restart
"""
def interp(plugin, nuin):
    log.info("new: %d, invalid: %d, ignore: %d, delete: %d, insert: %d, drop: %d, error: %d",
             nuin.value(2), nuin.value(3), nuin.value(4), nuin.value(5),
             nuin.value(7), (nuin.value(9) + nuin.value(10)), nuin.value(11))

    return nurs.NURS_RET_OK
