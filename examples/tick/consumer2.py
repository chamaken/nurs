def organize(plugin):
    nurs.Log.info("organize - config-string: %s" \
                  % plugin.config['config-string'])
    return nurs.NURS_RET_OK


def interp(plugin, nuin):
    nurs.Log.info("counter x 2: %d" % (nuin.value(0) * 2))
    return nurs.NURS_RET_OK
