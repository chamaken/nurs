import socket, logging, sys

log = None
listen_nfd = None
listen_sock = None
accept_fds = set() # hold it to prevent from GC

def accept_fd_cb(nfd, what):
    producer = nfd.data
    sock = nfd.fd

    output = producer.get_output()
    try:
        buf = output["message"]
        nbytes = sock.recv_into(buf)
        if nbytes == 0:
            sock.close()
            output.put()
            accept_fds.remove(nfd)
            return nurs.NURS_RET_OK

        if buf[nbytes - 1] != 10: # ord('\n')
            nurs.Log.error("recv too long line, exceeds: 4096")
            output.put()
            return nurs.NURS_RET_ERROR

        sock.sendall(buf[:nbytes])
        buf[nbytes - 1] = 0
        output["message"] = buf

        output.publish()
    except Exception as e:
        nurs.Log.error("failed to handle accept soket: %s" % e);
        output.put()

    return nurs.NURS_RET_OK


def listen_fd_cb(nfd, what):
    if what & nurs.NURS_FD_F_READ == 0:
        return nurs.NURS_RET_OK

    asock, addr = nfd.fd.accept()
    accept_fds.add(nurs.Fd(asock, nurs.NURS_FD_F_READ, accept_fd_cb, nfd.data))

    return nurs.NURS_RET_OK

    
def organize(plugin):
    global log
    logging.basicConfig(level=logging.INFO,
                        # filename=plugin.config['logfile'],
                        # filemode='a',
                        format='%(asctime)s %(levelname)s %(module)s %(message)s')
    log = logging.getLogger(__name__)

    global listen_sock
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.bind((plugin.config["host"], plugin.config["port"]))
    listen_sock.listen(0)

    return nurs.NURS_RET_OK


def start(plugin):
    global listen_sock, listen_nfd
    listen_nfd = nurs.Fd(listen_sock, nurs.NURS_FD_F_READ, listen_fd_cb, plugin)

    return nurs.NURS_RET_OK


# def stop(plugin):
#     listen_nfd will be decrefed then GCed

