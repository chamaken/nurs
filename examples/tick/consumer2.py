myname = None

def organize(plugin):
    global myname
    myname = plugin.config['myname']
    return nurs.NURS_RET_OK


def interp(plugin, nuin):
    nurs.Log.info("counter x 2: %d, %s -> %s" \
                  % ((nuin.value(0) * 2), nuin.value(1), myname))
    return nurs.NURS_RET_OK
