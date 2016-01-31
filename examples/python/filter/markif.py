import logging

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    filename='%s.log' % __name__,
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(module)s %(message)s')

in_mask = 0
in_shift = 0
out_mask = 0
out_shift = 0
flow_mask = 0


def mask_and_shift(word):
    return tuple(int(s, base=0) for s in word.split('>>'))


def organize(plugin):
    # 0: mask_ingress
    (in_mask, in_shift) = mask_and_shift(plugin.config[0])

    # 1: mask_egress
    (out_mask, out_shift) = mask_and_shift(plugin.config[1])

    # 2: mask_flow
    flow_mask = plugin.config[2]

    return nurs.NURS_RET_OK


def interp(plugin, nuin, nuout):
    global in_mask, in_shift
    global out_mask, out_shift
    global flow_mask

    ctmark = nuin.value(0)
    nuout[0] = (ctmark & in_mask) >> in_shift
    nuout[1] = (ctmark & out_mask) >> out_shift
    nuout[2] = (ctmark & flow_mask) != 0

    return nurs.NURS_RET_OK
