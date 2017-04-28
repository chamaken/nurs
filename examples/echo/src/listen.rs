use std::net::{ TcpStream, TcpListener };
use std::io::{ Read, Write };
use std::os::unix::io::{ RawFd, FromRawFd, AsRawFd, IntoRawFd };

extern crate libc;
use libc::c_int;

#[macro_use(nurs_return)]
#[macro_use(nurs_log)]
extern crate nurs;

const LISTEN_OUTPUT_MESSAGE_MAX: usize = 4096;

struct ListenPriv <'a> {
    listener: RawFd, // TcpListener,
    nfd: &'a mut nurs::Fd,
}

fn accept_fd_cb(nfd: &mut nurs::Fd, what: u16) -> nurs::ReturnType {
    if what & nurs::FD_F_READ == 0 {
        return nurs::ReturnType::OK;
    }

    let producer = nfd.data::<&mut &mut nurs::Producer>();
    let output = producer.get_output().unwrap();
    let mut sock = unsafe { TcpStream::from_raw_fd(nfd.as_raw_fd()) };
    {
        let buf = output.get_pointer::<[u8; LISTEN_OUTPUT_MESSAGE_MAX]>(0)
            .unwrap().unwrap();
        let nread = match sock.read(buf) {
            Err(errno) => {
                nurs_log!(ERROR, "failed to read from accept socket: {}", errno);
                sock.into_raw_fd();
                let _ = output.put();
                return nurs::ReturnType::ERROR;
            },
            Ok(0) => {
                nurs_log!(INFO, "closing accept socket");
                let mut ret = nurs::ReturnType::OK;
                nfd.unregister::<TcpStream, &mut &mut nurs::Producer>()
                    .unwrap_or_else(|errno| {
                        nurs_log!(ERROR, "failed to unregister fd: {}", errno);
                        ret = nurs::ReturnType::ERROR;
                    });
                sock.into_raw_fd();
                let _ = output.put();
                return ret;
            },
            Ok(n) => n,
        };

        let last = nread - 1;
        if buf[last] != '\n' as u8 {
            nurs_log!(ERROR, "recv too long line, exceeds: {}\n",
                      LISTEN_OUTPUT_MESSAGE_MAX);
            sock.into_raw_fd();
            let _ = output.put();
            return nurs::ReturnType::ERROR;
        }

        let mut nwrite = nread as isize;
        while nwrite > 0 {
            match sock.write(&buf[nread - nwrite as usize ..]) {
                Err(errno) => {
                    nurs_log!(ERROR, "failed to write to client: {}", errno);
                    sock.into_raw_fd();
                    let _ = output.put();
                    return nurs::ReturnType::ERROR;
                },
                Ok(n) => nwrite -= n as isize,
            }
        }
        buf[last] = 0;
    }
    sock.into_raw_fd();

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

fn listen_fd_cb(nfd: &mut nurs::Fd, what: u16) -> nurs::ReturnType {
    if what & nurs::FD_F_READ == 0 {
        return nurs::ReturnType::OK;
    }

    let producer = nfd.data::<&mut nurs::Producer>();
    let lfd = unsafe { TcpListener::from_raw_fd(nfd.as_raw_fd()) };
    let sock = match lfd.accept() {
        Err(errno) => {
            nurs_log!(ERROR, "failed to accept: {}\n", errno);
            lfd.into_raw_fd();
            return nurs::ReturnType::ERROR;
        },
        Ok((s, _)) => {
            s
        },
    };
    lfd.into_raw_fd();
    
    if let Err(errno) = nurs::Fd::register(sock.into_raw_fd(), nurs::FD_F_READ,
                                           accept_fd_cb, producer) {
        nurs_log!(ERROR, "failed to register listen fd: {}", errno);
        return nurs::ReturnType::ERROR;
    }
    nurs::ReturnType::OK
}
    
#[no_mangle]
pub extern fn listen_organize(producer: &mut nurs::Producer) -> c_int {
    let config = producer.config().unwrap();
    let mut ctx = producer.context::<ListenPriv>().unwrap();
    
    let listener = match TcpListener::bind(config.string(0).unwrap()) {
        Err(err) => {
            nurs_log!(FATAL, "failed to open bind: {}", err);
            return nurs_return!(ERROR);
        },
        Ok(s) => s
    };
    ctx.listener = listener.into_raw_fd();
    nurs_return!(OK)
}

#[no_mangle]
pub extern fn listen_disorganize(_: &mut nurs::Producer) -> c_int {
    // sock was closed at stop() by unregister
    // let mut ctx = producer.context::<ListenPriv>().unwrap();
    // unsafe { TcpListener::from_raw_fd(ctx.listener) };
    nurs_return!(OK)
}

#[no_mangle]
pub extern fn listen_start(producer: &mut nurs::Producer) -> c_int {
    let mut ctx = producer.context::<ListenPriv>().unwrap();
    ctx.nfd = match nurs::Fd::register(ctx.listener, nurs::FD_F_READ,
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
    let mut ctx = producer.context::<ListenPriv>().unwrap();
    match ctx.nfd.unregister::<TcpListener, &mut nurs::Producer>() {
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
    "organize":		"listen_organize",
    "disorganize":	"listen_disorganize",
    "start":		"listen_start",
    "stop":		"listen_stop"
}"#;

pub extern fn listen_producer_init() {
    nurs::producer_register_jsons(
        JSONRC,
        std::mem::size_of::<ListenPriv>() as u16)
        .unwrap();
}

#[link_section = ".ctors"]
pub static CONSTRUCTOR: extern fn() = listen_producer_init;
