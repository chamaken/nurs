import logging

PROC_TIMER_LIST = "/proc/timer_list"
NSEC_PER_SEC = 1000000000

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    filename='%s.log' % __name__,
                    filemode='a',
                    format='%(asctime)s %(levelname)s %(module)s %(message)s')

rtoffset = 0
setfunc = None


def conv_ntp_us(sec, usec):
    return int((sec << 32) + ((usec << 32) / (NSEC_PER_SEC / 1000))) & ~0x7ff

def set_ntp(nuout, offset, start_sec, start_usec, end_sec, end_usec):
    nuout[0] = conv_ntp_us(start_sec, start_usec)
    nuout[1] = conv_ntp_us(end_sec, end_usec)

def conv_uptime(offset, sec, usec):
    return int((sec - offset / NSEC_PER_SEC) * 1000 \
               + usec / 1000 - (offset % NSEC_PER_SEC) / 1000000)

def set_uptime(nuout, offset, start_sec, start_usec, end_sec, end_usec):
    nuout[2] = conv_uptime(offset, start_sec, start_usec)
    nuout[3] = conv_uptime(offset, end_sec, end_usec)


def set_both(nuout, offset, start_sec, start_usec, end_sec, end_usec):
    set_ntp(nuout, offset, start_sec, start_usec, end_sec, end_usec)
    set_uptime(nuout, offset, start_sec, start_usec, end_sec, end_usec)


def organize(plugin):
    # .get_time:   ktime_get_real
    # .offset:     1444874813990832001 nsecs
    #              ^^^^^^^^^^^^^^^^^^^
    global rtoffset

    rtoffset = 0
    with open(PROC_TIMER_LIST) as fd:
        for line in fd:
            # if not fd.readline().contains('ktime_get_real'):
            if not 'ktime_get_real' in line:
                continue
            rtoffset = int(fd.readline().split()[1])
            break
    if rtoffset == 0:
        log.error("failed to get rtoffset from %s" % PROC_TIMER_LIST)
        return nurs.NURS_RET_ERROR

    # 2: usec64, 3: uptime
    global setfunc
    if plugin.config[0] and plugin.config[1]:
        setfunc = set_both
    elif plugin.config[0]:
        setfunc = set_ntp
    elif plugin.config[1]:
        setfund = set_uptime
    else:
        log.error("no flow time type specified")
        return nurs.NURS_RET_ERROR

    return nurs.NURS_RET_OK


def interp(plugin, nuin, nuout):
    try:
        if nuin.is_valid(0) and \
           nuin.is_valid(1) and \
           nuin.is_valid(2) and \
           nuin.is_valid(3):
            log.warn("0: %r, 1: %r, 2: %r, 3: %r" % (nuin.value(0), nuin.value(1), nuin.value(2), nuin.value(3)))
            setfunc(nuout, rtoffset,
                    nuin.value(0), nuin.value(1),
                    nuin.value(2), nuin.value(3))
        else:
            fmt = ("key(s) represented only -"
                   " start.sec: %r, start.usec: %r,"
                   " end.sec: %r, end.usec: %r")
            log.warn(fmt,
                     nuin.is_valid(0), nuin.is_valid(1),
                     nuin.is_valid(2), nuin.is_valid(3))

        return nurs.NURS_RET_OK
    except Exception as e:
        log.error("err on interp: %e" % e)

    return nurs.NURS_RET_ERROR


def disorganize():
    global rtoffset, setfunc
    rtoffset = 0
    setfunc = None
    return nurs.NURS_RET_OK
