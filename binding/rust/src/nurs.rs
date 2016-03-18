#![crate_type = "lib"]
#![crate_name = "nurs"]

use std::any::Any;
use std::ffi::{CStr, CString};
use std::io::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_void};
use std::os::unix::io::AsRawFd;
use std::ptr;

extern crate libc;
use libc::{c_int, uint8_t, uint16_t, uint32_t, uint64_t, in_addr_t, in6_addr, time_t};

// enum / #![feature(associated_consts)]

/**
 * config
 */
pub const CONFIG_T_NONE:	u16 = 0;
pub const CONFIG_T_INTEGER:	u16 = 1;
pub const CONFIG_T_BOOLEAN:	u16 = 2;
pub const CONFIG_T_STRING:	u16 = 3;
pub const CONFIG_T_CALLBACK:	u16 = 4;

pub enum ConfigType {
    NONE,
    INTEGER,
    BOOLEAN,
    STRING,
    CALLBACK,
}

fn u16_config_t(t: u16) -> ConfigType {
    // https://github.com/rust-lang/rust/issues/12832
    // macro_rules! config_t { $(t:pat) => ( $t => ConfigType::$t ) }
    match t {
        CONFIG_T_INTEGER => ConfigType::INTEGER,
        CONFIG_T_BOOLEAN => ConfigType::BOOLEAN,
        CONFIG_T_STRING => ConfigType::STRING,
        CONFIG_T_CALLBACK => ConfigType::CALLBACK,
        _ => ConfigType::NONE,
    }
}

pub enum Config{}
extern {
    fn nurs_config_integer(config: *const Config, idx: uint8_t) -> c_int;
    fn nurs_config_boolean(config: *const Config, idx: uint8_t) -> bool;
    fn nurs_config_string(config: *const Config, idx: uint8_t) -> *const c_char;
    fn nurs_config_len(config: *const Config) -> uint8_t;
    fn nurs_config_type(config: *const Config, idx: uint8_t) -> uint16_t;
    fn nurs_config_index(config: *const Config, name: *const c_char) -> uint8_t;
}

type ConfigParser = fn(*const c_char)->i32;

/**
 * key
 */
pub const KEY_T_BOOL:		u16 = 1;
pub const KEY_T_INT8:		u16 = 2;
pub const KEY_T_INT16:		u16 = 3;
pub const KEY_T_INT32:		u16 = 4;
pub const KEY_T_INT64:		u16 = 5;
pub const KEY_T_UINT8:		u16 = 6;
pub const KEY_T_UINT16:		u16 = 7;
pub const KEY_T_UINT32:		u16 = 8;
pub const KEY_T_UINT64:		u16 = 9;
pub const KEY_T_INADDR:		u16 = 10;
pub const KEY_T_IN6ADDR:	u16 = 11;
pub const KEY_T_POINTER:	u16 = 12;
pub const KEY_T_STRING:		u16 = 13;
pub const KEY_T_EMBED:		u16 = 14;

pub enum KeyType {
    NONE,
    BOOL,
    INT8,
    INT16,
    INT32,
    INT64,
    UINT8,
    UINT16,
    UINT32,
    UINT64,
    INADDR,
    IN6ADDR,
    POINTER,
    STRING,
    EMBED,
}

fn u16_key_t(t: u16) -> KeyType {
    match t {
        KEY_T_BOOL	=> KeyType::BOOL,
        KEY_T_INT8	=> KeyType::INT8,
        KEY_T_INT16	=> KeyType::INT16,
        KEY_T_INT32	=> KeyType::INT32,
        KEY_T_INT64	=> KeyType::INT64,
        KEY_T_UINT8	=> KeyType::UINT8,
        KEY_T_UINT16	=> KeyType::UINT16,
        KEY_T_UINT32	=> KeyType::UINT32,
        KEY_T_UINT64	=> KeyType::UINT64,
        KEY_T_INADDR	=> KeyType::INADDR,
        KEY_T_IN6ADDR	=> KeyType::IN6ADDR,
        KEY_T_POINTER	=> KeyType::POINTER,
        KEY_T_STRING	=> KeyType::STRING,
        KEY_T_EMBED	=> KeyType::EMBED,
        _		=> KeyType::NONE,
    }
}

type KeyDestructor = fn(*mut c_void);

pub enum Input{}
extern {
    fn nurs_input_len(input: *const Input) -> uint16_t;
    fn nurs_input_size(input: *const Input, idx: uint16_t) -> uint16_t;

    fn nurs_input_name(input: *const Input, idx: uint16_t) -> *const c_char;
    fn nurs_input_type(input: *const Input, idx: uint16_t) -> uint16_t;
    fn nurs_input_index(input: *const Input, name: *const c_char) -> uint16_t;

    fn nurs_input_bool(input: *const Input, idx: uint16_t) -> bool;
    fn nurs_input_u8(input: *const Input, idx: uint16_t) -> uint8_t;
    fn nurs_input_u16(input: *const Input, idx: uint16_t) -> uint16_t;
    fn nurs_input_u32(input: *const Input, idx: uint16_t) -> uint32_t;
    fn nurs_input_u64(input: *const Input, idx: uint16_t) -> uint64_t;
    fn nurs_input_in_addr(input: *const Input, idx: uint16_t) -> in_addr_t;
    fn nurs_input_in6_addr(input: *const Input, idx: uint16_t) -> *const in6_addr;
    fn nurs_input_pointer(input: *const Input, idx: uint16_t) -> *const c_void;
    fn nurs_input_string(input: *const Input, idx: uint16_t) -> *const c_char;
    fn nurs_input_is_valid(input: *const Input, idx: uint16_t) -> bool;
    fn nurs_input_is_active(input: *const Input, idx: uint16_t) -> bool;
    fn nurs_input_ipfix_vendor(input: *const Input, idx: uint16_t) -> uint32_t;
    fn nurs_input_ipfix_field(input: *const Input, idx: uint16_t) -> uint16_t;
    fn nurs_input_cim_name(input: *const Input, idx: uint16_t) -> *const c_char;
}

pub enum Output{}
extern {
    fn nurs_output_len(output: *const Output) -> uint16_t;
    fn nurs_output_size(output: *const Output, idx: uint16_t) -> uint16_t;
    fn nurs_output_type(output: *const Output, idx: uint16_t) -> uint16_t;
    fn nurs_output_index(output: *const Output, name: *const c_char) -> uint16_t;

    fn nurs_output_set_bool(output: *mut Output, idx: uint16_t, value: bool) -> c_int;
    fn nurs_output_set_u8(output: *mut Output, idx: uint16_t, value: uint8_t) -> c_int;
    fn nurs_output_set_u16(output: *mut Output, idx: uint16_t, value: uint16_t) -> c_int;
    fn nurs_output_set_u32(output: *mut Output, idx: uint16_t, value: uint32_t) -> c_int;
    fn nurs_output_set_u64(output: *mut Output, idx: uint16_t, value: uint64_t) -> c_int;
    fn nurs_output_set_in_addr(output: *mut Output, idx: uint16_t, value: in_addr_t) -> c_int;
    fn nurs_output_set_in6_addr(output: *mut Output, idx: uint16_t, value: *const in6_addr) -> c_int;
    fn nurs_output_set_pointer(output: *mut Output, idx: uint16_t, value: *const c_void) -> c_int;
    fn nurs_output_set_string(output: *mut Output, idx: uint16_t, value: *const c_char) -> c_int;
    fn nurs_output_pointer(output: *const Output, idx: uint16_t) -> *mut c_void;
    fn nurs_output_set_valid(output: *mut Output, idx: uint16_t) -> c_int;
}

/**
 * plugin
 */
pub const RET_ERROR: c_int = -1;
pub const RET_STOP: c_int = -2;
pub const RET_OK: c_int = 0;

// #[repr(C)]
pub enum ReturnType {
    ERROR,
    STOP,
    OK,
}

pub fn return_t_cint(r: ReturnType) -> c_int {
    match r {
        ReturnType::ERROR => RET_ERROR,
        ReturnType::STOP => RET_STOP,
        ReturnType::OK => RET_OK,
    }
}

#[macro_export]
macro_rules! nurs_return {
    ($s:ident) => ( $crate::return_t_cint($crate::ReturnType::$s) )
}

pub enum Producer {}
pub enum Plugin{}

type Start = fn(*const Plugin) -> c_int;
type ProducerStart = fn(*const Producer) -> c_int;
type Stop = fn(*const Plugin) -> c_int;
type ProducerStop = fn(*const Producer) -> c_int;
type Signal = fn(*const Plugin, uint32_t) -> c_int;
type ProducerSignal = fn(*const Producer, uint32_t) -> c_int;
type Organize = fn(*const Plugin) -> c_int;
type CoveterOrganize = fn(*const Plugin, *const Input) -> c_int;
type ProducerOrganize = fn(*const Producer) -> c_int;
type Disorganize = fn(*const Plugin) -> c_int;
type ProducerDisorganize = fn(*const Producer) -> c_int;
type Interp = fn(*const Plugin, *const Input, *mut Output) -> c_int;
type ConsumerInterp = fn(*const Plugin, *const Input) -> c_int;

extern {
    fn nurs_producer_unregister_name(name: *const c_char) -> c_int;
    fn nurs_filter_unregister_name(name: *const c_char) -> c_int;
    fn nurs_consumer_unregister_name(name: *const c_char) -> c_int;
    fn nurs_coveter_unregister_name(name: *const c_char) -> c_int;
}

extern {
    fn nurs_producer_register_jsons(input: *const c_char, context_size: uint16_t) -> *const c_void;
    fn nurs_filter_register_jsons(input: *const c_char, context_size: uint16_t) -> *const c_void;
    fn nurs_consumer_register_jsons(input: *const c_char, context_size: uint16_t) -> *const c_void;
    fn nurs_coveter_register_jsons(input: *const c_char, context_size: uint16_t) -> *const c_void;
    fn nurs_producer_register_jsonf(fname: *const c_char, context_size: uint16_t) -> *const c_void;
    fn nurs_filter_register_jsonf(fname: *const c_char, context_size: uint16_t) -> *const c_void;
    fn nurs_consumer_register_jsonf(fname: *const c_char, context_size: uint16_t) -> *const c_void;
    fn nurs_coveter_register_jsonf(fname: *const c_char, context_size: uint16_t) -> *const c_void;
    fn nurs_plugins_register_jsonf(fname: *const c_char) -> c_int;
    fn nurs_plugins_unregister_jsonf(fname: *const c_char) -> c_int;
}

extern {
    fn nurs_producer_context(producer: *const Producer) -> *mut c_void;
    fn nurs_plugin_context(plugin: *const Plugin) -> *mut c_void;
    fn nurs_producer_config(producer: *const Producer) -> *const Config;
    fn nurs_plugin_config(plugin: *const Plugin) -> *const Config;
}

extern {
    fn nurs_publish(output: *mut Output) -> c_int;
    fn nurs_get_output(producer: *mut Producer) -> *mut Output;
    fn nurs_put_output(output: *mut Output) -> c_int;
}

/**
 * fd
 */
pub const FD_F_READ: u16 = 1;
pub const FD_F_WRITE: u16 = 2;
pub const FD_F_EXCEPT: u16 = 4;

pub enum Fd{}
type CFdCb = extern "C" fn(c_int, uint16_t, *mut c_void) -> c_int;

extern {
    fn nurs_fd_create(fd: c_int, when: uint16_t) -> *mut Fd;
    fn nurs_fd_destroy(nfd: *mut Fd);
    // fn nurs_fd_register(nfd: *mut Fd, cb: *const CFdCb, data: *mut c_void) -> c_int;
    fn nurs_fd_register(nfd: *mut Fd, cb: CFdCb, data: *mut c_void) -> c_int;
    fn nurs_fd_unregister(nfd: *mut Fd) -> c_int;
}

/**
 * timer
 */
pub enum Timer{}
type CTimerCb = extern "C" fn(*mut Timer, *mut c_void) -> c_int;

extern {
    // fn nurs_timer_create(cb: *const CTimerCb, data: *mut c_void) -> *mut Timer;
    fn nurs_timer_create(cb: CTimerCb, data: *mut c_void) -> *mut Timer;
    fn nurs_timer_destroy(timer: *mut Timer) -> c_int;
    fn nurs_timer_add(timer: *mut Timer, sc: time_t) -> c_int;
    fn nurs_itimer_add(timer: *mut Timer, ini: time_t, per: time_t) -> c_int;
    fn nurs_timer_del(timer: *mut Timer) -> c_int;
    fn nurs_timer_pending(timer: *mut Timer) -> c_int;
}

/*
 * misc
 */
// __nurs_log(int level, char *file, int line, const char *message, ...);

macro_rules! unsafe_errno_result {
    ($fcall:expr, $mayerr:expr) => ( {
        let ret = unsafe { $fcall };
        if ret != $mayerr {
            Ok(ret)
        } else {
            let err = Error::last_os_error();
            match err.raw_os_error() {
                Some(errno) => {
                    match errno {
                    0 => Ok(ret),
                        _ => Err(err),
                    }
                },
                _ => Ok(ret),
            }
        }
    } )
}

macro_rules! unsafe_errno_option {
    ($fcall:expr) => ( {
        if unsafe { $fcall } == 0 { // including NURS_RET_OK
            None
        } else {
            let err = Error::last_os_error();
            match err.raw_os_error() {
                Some(errno) => {
                    match errno {
                        0 => None,
                        _ => Some(err),
                    }
                },
                _ => None,
            }
        }
    } )
}

impl Config {
    pub fn integer(&self, idx: u8) -> Result<c_int, Error> {
        let ret = unsafe { nurs_config_integer(self, idx) };
        if ret != 0 {
            return Ok(ret);
        }

        let err = Error::last_os_error();
        match err.raw_os_error() {
            Some(errno) => {
                match errno {
                    0 => Ok(ret),
                    _ => Err(err),
                }
            },
            _ => Ok(ret),
        }
    }

    pub fn boolean(&self, idx: u8) -> Result<bool, Error> {
        unsafe_errno_result!(nurs_config_boolean(self, idx), false)
    }

    pub fn string(&self, idx: u8) -> Result<&str, Error> {
        match unsafe_errno_result!(nurs_config_string(self, idx), ptr::null()) {
            Ok(ret) => Ok(unsafe { CStr::from_ptr(ret).to_str().unwrap() }),
            Err(errno) => Err(errno),
        }
    }

    pub fn len(&self) -> uint8_t {
        unsafe { nurs_config_len(self) }
    }

    pub fn config_type(&self, idx: u8) -> Result<ConfigType, Error> {
        match unsafe_errno_result!(nurs_config_type(self, idx), 0) {
            Ok(ret) => Ok(u16_config_t(ret)),
            Err(errno) => Err(errno),
        }
    }

    pub fn index(&self, name: &str) -> Result<u8, Error> {
        let s = CString::new(name).unwrap();
        unsafe_errno_result!(nurs_config_index(self, s.as_ptr()), 0)
    }
}

impl Input {
    pub fn len(&self) -> u16 {
        unsafe { nurs_input_len(self) }
    }

    pub fn size(&self, idx: u16) -> Result<u16, Error> {
        unsafe_errno_result!(nurs_input_size(self, idx), 0)
    }

    pub fn name(&self, idx: u16) -> Result<&str, Error> {
        match unsafe_errno_result!(nurs_input_name(self, idx), ptr::null()) {
            Ok(ret) => Ok(unsafe { CStr::from_ptr(ret).to_str().unwrap() }),
            Err(errno) => Err(errno),
        }
    }

    pub fn key_type(&self, idx: u16) -> Result<KeyType, Error> {
        match unsafe_errno_result!(nurs_input_type(self, idx), 0) {
            Ok(ret) => Ok(u16_key_t(ret)),
            Err(errno) => Err(errno),
        }


    }

    pub fn index(&self, name: &str) -> Result<u16, Error> {
        let s = CString::new(name).unwrap();
        unsafe_errno_result!(nurs_input_index(self, s.as_ptr()), 0)
    }

    pub fn get_bool(&self, idx: u16) -> Result<bool, Error> {
        unsafe_errno_result!(nurs_input_bool(self, idx), false)
    }

    pub fn get_u8(&self, idx: u16) -> Result<u8, Error> {
        unsafe_errno_result!(nurs_input_u8(self, idx), 0)
    }

    pub fn get_u16(&self, idx: u16) -> Result<u16, Error> {
        unsafe_errno_result!(nurs_input_u16(self, idx), 0)
    }

    pub fn get_u32(&self, idx: u16) -> Result<u32, Error> {
        unsafe_errno_result!(nurs_input_u32(self, idx), 0)
    }

    pub fn get_u64(&self, idx: u16) -> Result<u64, Error> {
        unsafe_errno_result!(nurs_input_u64(self, idx), 0)
    }

    pub fn get_in_addr(&self, idx: u16) -> Result<Ipv4Addr, Error> {
        match unsafe_errno_result!(nurs_input_in_addr(self, idx), 0) {
            Ok(ret) => Ok(Ipv4Addr::from(ret as u32)),
            Err(errno) => Err(errno),
        }
    }

    pub fn get_in6_addr(&self, idx: u16) -> Result<Ipv6Addr, Error> {
        match unsafe_errno_result!(nurs_input_in6_addr(self, idx), ptr::null()) {
            Ok(ret) => unsafe {
                Ok(Ipv6Addr::new(((*ret).s6_addr[ 0] as u16) << 8 | (*ret).s6_addr[ 1] as u16,
                                 ((*ret).s6_addr[ 2] as u16) << 8 | (*ret).s6_addr[ 3] as u16,
                                 ((*ret).s6_addr[ 4] as u16) << 8 | (*ret).s6_addr[ 5] as u16,
                                 ((*ret).s6_addr[ 6] as u16) << 8 | (*ret).s6_addr[ 7] as u16,
                                 ((*ret).s6_addr[ 8] as u16) << 8 | (*ret).s6_addr[ 9] as u16,
                                 ((*ret).s6_addr[10] as u16) << 8 | (*ret).s6_addr[11] as u16,
                                 ((*ret).s6_addr[12] as u16) << 8 | (*ret).s6_addr[13] as u16,
                                 ((*ret).s6_addr[14] as u16) << 8 | (*ret).s6_addr[15] as u16))
            },
            Err(errno) => Err(errno),
        }
    }

    // http://stackoverflow.com/questions/24191249/working-with-c-void-in-an-ffi
    pub fn get_pointer(&self, idx: u16) -> Result<Option<*const c_void>, Error> {
        match unsafe_errno_result!(nurs_input_pointer(self, idx), ptr::null()) {
            Ok(ret) => {
                if ret.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(ret))
                }
            },
            Err(errno) => Err(errno),
        }
    }

    pub fn get_string(&self, idx: u16) -> Result<&str, Error> {
        match unsafe_errno_result!(nurs_input_string(self, idx), ptr::null()) {
            Ok(ret) => Ok(unsafe { CStr::from_ptr(ret).to_str().unwrap() }),
            Err(errno) => Err(errno),
        }
    }

    pub fn is_valid(&self, idx: u16) -> Result<bool, Error> {
        unsafe_errno_result!(nurs_input_is_valid(self, idx), false)
    }

    pub fn is_active(&self, idx: u16) -> Result<bool, Error> {
        unsafe_errno_result!(nurs_input_is_active(self, idx), false)
    }

    pub fn ipfix_vendor(&self, idx: u16) -> Result<u32, Error> {
        unsafe_errno_result!(nurs_input_ipfix_vendor(self, idx), 0)
    }

    pub fn ipfix_field(&self, idx: u16) -> Result<u16, Error> {
        unsafe_errno_result!(nurs_input_ipfix_field(self, idx), 0)
    }

    pub fn cim_name(&self, idx: u16) -> Result<&str, Error> {
        match unsafe_errno_result!(nurs_input_cim_name(self, idx), ptr::null()) {
            Ok(ret) => Ok(unsafe { CStr::from_ptr(ret).to_str().unwrap() }),
            Err(errno) => Err(errno),
        }
    }
}

impl Output {
    pub fn len(&self) -> u16 {
        unsafe { nurs_output_len(self) }
    }

    pub fn size(&self, idx: u16) -> Result<u16, Error> {
        unsafe_errno_result!(nurs_output_size(self, idx), 0)
    }

    pub fn key_type(&self, idx: u16) -> Result<KeyType, Error> {
        match unsafe_errno_result!(nurs_output_type(self, idx), 0) {
            Ok(ret) => Ok(u16_key_t(ret)),
            Err(errno) => Err(errno),
        }
    }

    pub fn index(&self, name: &str) -> Result<u16, Error> {
        let s = CString::new(name).unwrap();
        unsafe_errno_result!(nurs_output_index(self, s.as_ptr()), 0)
    }

    pub fn set_bool(&mut self, idx: u16, value: bool) -> Option<Error> {
        unsafe_errno_option!(nurs_output_set_bool(self, idx, value))
    }

    pub fn set_u8(&mut self, idx: u16, value: u8) -> Option<Error> {
        unsafe_errno_option!(nurs_output_set_u8(self, idx, value))
    }

    pub fn set_u16(&mut self, idx: u16, value: u16) -> Option<Error> {
        unsafe_errno_option!(nurs_output_set_u16(self, idx, value))
    }

    pub fn set_u32(&mut self, idx: u16, value: u32) -> Option<Error> {
        unsafe_errno_option!(nurs_output_set_u32(self, idx, value))
    }

    pub fn set_u64(&mut self, idx: u16, value: u64) -> Option<Error> {
        unsafe_errno_option!(nurs_output_set_u64(self, idx, value))
    }

    pub fn set_in_addr(&mut self, idx: u16, value: &Ipv4Addr) -> Option<Error> {
        let o = (*value).octets();
        let raw = (o[0] as u32) << 24
            | (o[1] as u32) << 16
            | (o[2] as u32) << 8
            | (o[3] as u32);
        unsafe_errno_option!(nurs_output_set_in_addr(self, idx, raw as in_addr_t))
    }

    pub fn set_in6_addr(&mut self, idx: u16, value: &Ipv6Addr) -> Option<Error> {
        unsafe_errno_option!(nurs_output_set_in6_addr(self, idx, value as *const _ as *const in6_addr))
    }

    pub fn set_pointer(&mut self, idx: u16, value: *const c_void) -> Option<Error> {
        unsafe_errno_option!(nurs_output_set_pointer(self, idx, value))
    }

    pub fn set_string(&mut self, idx: u16, value: &str) -> Option<Error> {
        let s = CString::new(value).unwrap();
        unsafe_errno_option!(nurs_output_set_string(self, idx, s.as_ptr()))
    }

    pub fn get_pointer(&self, idx: u16) -> Result<Option<*mut c_void>, Error> {
        match unsafe_errno_result!(nurs_output_pointer(self, idx), ptr::null_mut()) {
            Ok(ret) => {
                if ret.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(ret))
                }
            },
            Err(errno) => Err(errno),
        }
    }

    pub fn set_valid(&mut self, idx: u16) -> Option<Error> {
        unsafe_errno_option!(nurs_output_set_valid(self, idx))
    }

    pub fn publish(&mut self) -> Option<Error> {
        unsafe_errno_option!(nurs_publish(self))
    }

    pub fn put(&mut self) -> Option<Error> {
        unsafe_errno_option!(nurs_put_output(self))
    }

}

pub fn producer_unregister(name: &str) -> Option<Error> {
    let s = CString::new(name).unwrap();
    unsafe_errno_option!(nurs_producer_unregister_name(s.as_ptr()))
}

pub fn filter_unregister(name: &str) -> Option<Error> {
    let s = CString::new(name).unwrap();
    unsafe_errno_option!(nurs_filter_unregister_name(s.as_ptr()))
}

pub fn consumer_unregister(name: &str) -> Option<Error> {
    let s = CString::new(name).unwrap();
    unsafe_errno_option!(nurs_consumer_unregister_name(s.as_ptr()))
}

pub fn coveter_unregister(name: &str) -> Option<Error> {
    let s = CString::new(name).unwrap();
    unsafe_errno_option!(nurs_coveter_unregister_name(s.as_ptr()))
}

macro_rules! unsafe_str_null_errno_option {
    ($fcall:expr, $s:expr, $($a:expr),*) => ( {
        let s = CString::new($s).unwrap();
        // if unsafe { $fcall } != ptr::null() {
        if unsafe { $fcall(s.as_ptr(), $($a), *) != ptr::null() } {
            None
        } else {
            let err = Error::last_os_error();
            match err.raw_os_error() {
                Some(errno) => {
                    match errno {
                        0 => None,
                        _ => Some(err),
                    }
                },
                _ => None,
            }
        }
    } )
}

pub fn producer_register_jsons(input: &str, context_size: u16) -> Option<Error> {
    unsafe_str_null_errno_option!(nurs_producer_register_jsons, input, context_size)
}

pub fn filter_register_jsons(input: &str, context_size: u16) -> Option<Error> {
    unsafe_str_null_errno_option!(nurs_filter_register_jsons, input, context_size)
}

pub fn consumer_register_jsons(input: &str, context_size: u16) -> Option<Error> {
    unsafe_str_null_errno_option!(nurs_consumer_register_jsons, input, context_size)
}

pub fn coveter_register_jsons(input: &str, context_size: u16) -> Option<Error> {
    unsafe_str_null_errno_option!(nurs_coveter_register_jsons, input, context_size)
}

pub fn producer_resiger_jsonf(fname: &str, context_size: u16) -> Option<Error> {
    unsafe_str_null_errno_option!(nurs_producer_register_jsonf, fname, context_size)
}

pub fn filter_register_jsonf(fname: &str, context_size: u16) -> Option<Error> {
    unsafe_str_null_errno_option!(nurs_filter_register_jsonf, fname, context_size)
}

pub fn consumer_register_jsonf(fname: &str, context_size: u16) -> Option<Error> {
    unsafe_str_null_errno_option!(nurs_consumer_register_jsonf, fname, context_size)
}

pub fn coveter_register_jsonf(fname: &str, context_size: u16) -> Option<Error> {
    unsafe_str_null_errno_option!(nurs_coveter_register_jsonf, fname, context_size)
}

pub fn plugins_register_jfonf(fname: &str) -> Option<Error> {
    let s = CString::new(fname).unwrap();
    unsafe_errno_option!(nurs_plugins_register_jsonf(s.as_ptr()))
}

pub fn plugins_unregster_jsonf(fname: &str) -> Option<Error> {
    let s = CString::new(fname).unwrap();
    unsafe_errno_option!(nurs_plugins_unregister_jsonf(s.as_ptr()))
}

impl Plugin {
    // pub fn context(&self) -> Option<&mut Any> {
    pub fn context(&self) -> *mut c_void {
        let ret = unsafe { nurs_plugin_context(self) };
        if ret.is_null() {
            panic!("must acquire plugin private data but...");
        } else {
            // unsafe { Some(&mut(*(ret as *mut Any))) }
            ret
        }
    }

    pub fn config(&self) -> Option<&Config> {
        unsafe {
            let ret = nurs_plugin_config(self);
            // ret.as_ref() see rust issue #27780
            if ret.is_null() {
                None
            } else {
                Some(&(*ret))
            }
        }
    }
}

impl Producer {
    // pub fn context(&self) -> Option<&mut Any> {
    pub fn context(&self) -> *mut c_void {
        let ret = unsafe { nurs_producer_context(self) };
        if ret.is_null() {
            panic!("must acquire producer private data but...");
        } else {
            // unsafe { Some(&mut(*(ret as *mut Any))) }
            ret
        }
    }

    pub fn config<'a>(&self) -> Option<&'a Config> {
        unsafe {
            let ret = nurs_producer_config(self);
            // ret.as_ref() see rust issue #27780
            if ret.is_null() {
                None
            } else {
                Some(&(*ret))
            }
        }
    }

    pub fn get_output(&mut self) -> Result<&mut Output, Error> {
        let ret = unsafe { nurs_get_output(self) };
        if ! ret.is_null() {
            unsafe { Ok(&mut(*ret)) }
        } else {
            Err(Error::last_os_error())
        }
    }
}

/*
struct FdCbData <'a> {
    cb: &'a FdCb,
    data: &'a Any,
}
static FDS: HashMap <*mut Fd, FdCbData <'static>>= HashMap::new();
 */
pub type FdCb = fn(c_int, u16, &mut Any) -> ReturnType;
struct FdCbData <'a> {
    cb: FdCb,
    data: &'a mut Any,
}

extern fn fdcb(fd: c_int, what: uint16_t, data: *mut c_void) -> c_int {
    let mut cbdata = unsafe { Box::from_raw(data as *mut Box<FdCbData>) };
    let ret = (cbdata.cb)(fd, what, cbdata.data);
    Box::into_raw(cbdata);
    match ret {
        ReturnType::OK   => RET_OK,
        ReturnType::STOP => RET_STOP,
        _    		 => RET_ERROR,
    }
}

impl Fd {
    pub fn create(fd: &AsRawFd, when: u16) -> Result<&mut Fd, Error> {
        let errval: *const Fd = ptr::null();
        match unsafe_errno_result!(nurs_fd_create(fd.as_raw_fd(), when), errval as *mut Fd) {
            Ok(ret) => unsafe { Ok(&mut(*ret)) },
            Err(errno) => Err(errno),
        }
    }

    pub fn destroy(&mut self) {
        unsafe { nurs_fd_destroy(self as *mut Fd) }
    }

    pub fn register(&mut self, cb: FdCb, data: &mut Any) -> Option<Error> {
        let mut cbdata = Box::new(FdCbData {cb: cb, data: data});
        let pdata: *mut c_void = &mut cbdata as *mut _ as *mut c_void;
        let ret = unsafe_errno_option!(nurs_fd_register(self, fdcb, pdata));
        Box::into_raw(cbdata);
        ret
    }

    pub fn unregister(&mut self) -> Option<Error> {
        // XXX: cbdata leaks.
        unsafe_errno_option!(nurs_fd_unregister(self))
    }
}

pub type TimerCb = fn(&mut Timer, &mut Any) -> ReturnType;
struct TimerCbData <'a> {
    cb: TimerCb,
    data: &'a mut Any,
}

extern fn timercb(timer: *mut Timer, data: *mut c_void) -> c_int {
    let mut cbdata = unsafe { Box::from_raw(data as *mut Box<TimerCbData>) };
    let t = unsafe {&mut(*timer)};
    let ret = (cbdata.cb)(t, cbdata.data);
    Box::into_raw(cbdata);
    match ret {
        ReturnType::OK   => RET_OK,
        ReturnType::STOP => RET_STOP,
        _    		 => RET_ERROR,
    }
}

impl <'a> Timer {
    pub fn create(cb: TimerCb, data: &mut Any) -> Result<&'a mut Timer, Error> {
        let mut cbdata = Box::new(TimerCbData {cb: cb, data: data});
        let pdata: *mut c_void = &mut cbdata as *mut _ as *mut c_void;
        let errval: *const Fd = ptr::null();
        let ret = unsafe_errno_result!(nurs_timer_create(timercb, pdata), errval as *mut Timer);
        Box::into_raw(cbdata);
        match ret {
            Ok(ret) => unsafe { Ok(&mut(*ret)) },
            Err(errno) => Err(errno),
        }
    }

    pub fn destroy(&mut self) -> Option<Error> {
        unsafe_errno_option!(nurs_timer_destroy(self))
    }

    pub fn add(&mut self, sc: time_t) -> Option<Error> {
        unsafe_errno_option!(nurs_timer_add(self, sc))
    }

    pub fn iadd(&mut self, ini: time_t, per: time_t) -> Option<Error> {
        unsafe_errno_option!(nurs_itimer_add(self, ini, per))
    }

    pub fn del(&mut self) -> Option<Error> {
        unsafe_errno_option!(nurs_timer_del(self))
    }

    pub fn pending(&mut self) -> Result<bool, Error> {
        match unsafe_errno_result!(nurs_timer_pending(self), -1) {
            Ok(ret) => match ret {
                0 => Ok(false),
                _ => Ok(true),
            },
            Err(errno) => Err(errno),
        }
    }
}

extern {
    fn __nurs_log(level: c_int, file: *const c_char, line: c_int, message: *const c_char, ...);
}

pub const NURS_DEBUG:  c_int = 0;
pub const NURS_INFO:   c_int = 1;
pub const NURS_NOTICE: c_int = 2;
pub const NURS_ERROR:  c_int = 3;
pub const NURS_FATAL:  c_int = 4;

pub enum LogLevel {
    DEBUG,
    INFO,
    NOTICE,
    ERROR,
    FATAL,
}

pub fn loglevel_cint(lvl: LogLevel) -> c_int {
    match lvl {
        LogLevel::DEBUG  => NURS_DEBUG,
        LogLevel::INFO   => NURS_INFO,
        LogLevel::NOTICE => NURS_NOTICE,
        LogLevel::ERROR  => NURS_ERROR,
        LogLevel::FATAL  => NURS_FATAL,
    }
}

pub fn __log(level: c_int, file: &str, lineno: c_int, message: &str) {
    let fname = CString::new(file).unwrap(); // .as_ptr() here won't work?
    let fmt = CString::new("%s\n").unwrap();
    let msg = CString::new(message).unwrap();
    unsafe {
        __nurs_log(level, fname.as_ptr(), lineno, fmt.as_ptr(), msg.as_ptr());
    }
}

#[macro_export]
macro_rules! nurs_log {
    ($lvl:ident, $($arg:tt)*) =>
        ($crate::__log($crate::loglevel_cint($crate::LogLevel::$lvl),
                       file!(),
                       line!() as c_int,
                       &(format!($($arg)*))))
}
