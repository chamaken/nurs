import logging

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    filename='%s.log' % __name__,
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(module)s %(message)s')


def interp(plugin, nuin, nuout):
    if nuin.is_valid(0) and \
       nuin.is_valid(1):
        nuout[0] = nuin.value(0) << 8 | nuin.value(1)

    return nurs.NURS_RET_OK
