use std::net::{ TcpStream, TcpListener };
use std::io::{ Read, Write };

extern crate libc;
use libc::c_int;

#[macro_use(nurs_return)]
#[macro_use(nurs_log)]
extern crate nurs;

const LISTEN_OUTPUT_MESSAGE_MAX: usize = 4096;

fn accept_fd_cb(nfd: &mut nurs::Fd<TcpStream, &mut &mut nurs::Producer>, what: u16) -> nurs::ReturnType {
    if what & nurs::FD_F_READ == 0 {
        return nurs::ReturnType::OK;
    }

    let producer = nfd.data();
    let output = producer.get_output().unwrap();
    let mut sock = nfd.fd();
    {
        let buf = output.get_pointer::<[u8; LISTEN_OUTPUT_MESSAGE_MAX]>(0)
            .unwrap().unwrap();
        let nread = match sock.read(buf) {
            Err(errno) => {
                nurs_log!(ERROR, "failed to read from accept socket: {}", errno);
                let _ = output.put();
                return nurs::ReturnType::ERROR;
            },
            Ok(0) => {
                nurs_log!(INFO, "closing accept socket");
                let mut ret = nurs::ReturnType::OK;
                nfd.unregister()
                    .unwrap_or_else(|errno| {
                        nurs_log!(ERROR, "failed to unregister fd: {}", errno);
                        ret = nurs::ReturnType::ERROR;
                    });
                let _ = output.put();
                return ret;
            },
            Ok(n) => n,
        };

        let last = nread - 1;
        if buf[last] != '\n' as u8 {
            nurs_log!(ERROR, "recv too long line, exceeds: {}\n",
                      LISTEN_OUTPUT_MESSAGE_MAX);
            let _ = output.put();
            return nurs::ReturnType::ERROR;
        }

        let mut nwrite = nread as isize;
        while nwrite > 0 {
            match sock.write(&buf[nread - nwrite as usize ..]) {
                Err(errno) => {
                    nurs_log!(ERROR, "failed to write to client: {}", errno);
                    let _ = output.put();
                    return nurs::ReturnType::ERROR;
                },
                Ok(n) => nwrite -= n as isize,
            }
        }
        buf[last] = 0;
    }

    if let Err(errno) = output.set_valid(0) {
        nurs_log!(ERROR, "failed to be valid output: {}", errno);
        return nurs::ReturnType::ERROR;
    }
    match output.publish() {
        Ok(_) => nurs::ReturnType::OK,
        Err(errno) => {
            nurs_log!(ERROR, "failed to publish: {}", errno);
            let _ = output.put();
            nurs::ReturnType::ERROR
        },
    }
}

fn listen_fd_cb(nfd: &mut nurs::Fd<TcpListener, &mut nurs::Producer>, what: u16) -> nurs::ReturnType {
    if what & nurs::FD_F_READ == 0 {
        return nurs::ReturnType::OK;
    }

    let producer = nfd.data();
    let sock = match nfd.fd().accept() {
        Err(errno) => {
            nurs_log!(ERROR, "failed to accept: {}\n", errno);
            return nurs::ReturnType::ERROR;
        },
        Ok((s, _)) => s,
    };

    if let Err(errno) = nurs::Fd::register(sock, nurs::FD_F_READ,
                                           accept_fd_cb, producer) {
        nurs_log!(ERROR, "failed to register listen fd: {}", errno);
        return nurs::ReturnType::ERROR;
    }
    nurs::ReturnType::OK
}

#[no_mangle]
pub extern fn listen_start(producer: &mut nurs::Producer) -> c_int {
    let config = producer.config().unwrap();
    let nfd = producer.context::<&mut nurs::Fd<TcpListener, &mut nurs::Producer>>().unwrap();

    let listener = match TcpListener::bind(config.string(0).unwrap()) {
        Err(err) => {
            nurs_log!(FATAL, "failed to open bind: {}", err);
            return nurs_return!(ERROR);
        },
        Ok(s) => s
    };

    *nfd = match nurs::Fd::register(listener, nurs::FD_F_READ,
                                    listen_fd_cb, producer) {
        Ok(fd) => fd,
        Err(errno) => {
            nurs_log!(ERROR, "failed to register nfd: {}", errno);
            return nurs_return!(ERROR);
        },
    };
    nurs_return!(OK)
}

#[no_mangle]
pub extern fn listen_stop(producer: &mut nurs::Producer) -> c_int {
    let mut nfd = producer.context::<&mut nurs::Fd<TcpListener, &mut nurs::Producer>>().unwrap();
    match nfd.unregister() {
        Ok(_) => nurs_return!(OK),
        Err(errno) => {
            nurs_log!(ERROR, "failed to unregist listen fd: {}", errno);
            nurs_return!(ERROR)
        },
    }
}

static JSONRC: &'static str = r#"
{
    "version": "0.1",
    "name": "RS_LISTEN",
    "config": [
	{ "name": "source",
	  "type": "NURS_CONFIG_T_STRING",
	  "flags": ["NURS_CONFIG_F_MANDATORY"]}
    ],
    "output" : [
	{ "name": "message",
	  "type": "NURS_KEY_T_EMBED",
	  "flags": ["NURS_OKEY_F_ALWAYS"],
	  "len":  4096 }
    ],
    "start":		"listen_start",
    "stop":		"listen_stop"
}"#;

pub extern fn listen_producer_init() {
    nurs::producer_register_jsons(
        JSONRC,
        std::mem::size_of::<&mut nurs::Fd<TcpListener, &mut nurs::Producer>>() as u16)
        .unwrap();
}

#[link_section = ".ctors"]
pub static CONSTRUCTOR: extern fn() = listen_producer_init;
