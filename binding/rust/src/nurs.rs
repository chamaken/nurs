#![crate_type = "lib"]
#![crate_name = "nurs"]
#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::io;
use std::io::Error;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_void};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::ptr;

extern crate libc;
use libc::{c_int, in6_addr, in_addr_t, time_t};

// enum / #![feature(associated_consts)]

extern "C" {
    fn __nurs_log(level: c_int, file: *const c_char, line: c_int, message: *const c_char, ...);
}

pub const NURS_DEBUG: c_int = 0;
pub const NURS_INFO: c_int = 1;
pub const NURS_NOTICE: c_int = 2;
pub const NURS_ERROR: c_int = 3;
pub const NURS_FATAL: c_int = 4;

pub enum LogLevel {
    DEBUG,
    INFO,
    NOTICE,
    ERROR,
    FATAL,
}

pub fn loglevel_cint(lvl: LogLevel) -> c_int {
    match lvl {
        LogLevel::DEBUG => NURS_DEBUG,
        LogLevel::INFO => NURS_INFO,
        LogLevel::NOTICE => NURS_NOTICE,
        LogLevel::ERROR => NURS_ERROR,
        LogLevel::FATAL => NURS_FATAL,
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

/**
 * config
 */
pub const CONFIG_T_NONE: u16 = 0;
pub const CONFIG_T_INTEGER: u16 = 1;
pub const CONFIG_T_BOOLEAN: u16 = 2;
pub const CONFIG_T_STRING: u16 = 3;
pub const CONFIG_T_CALLBACK: u16 = 4;

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

pub enum Config {}
extern "C" {
    fn nurs_config_integer(config: *const Config, idx: u8) -> c_int;
    fn nurs_config_boolean(config: *const Config, idx: u8) -> bool;
    fn nurs_config_string(config: *const Config, idx: u8) -> *const c_char;
    fn nurs_config_len(config: *const Config) -> u8;
    fn nurs_config_type(config: *const Config, idx: u8) -> u16;
    fn nurs_config_index(config: *const Config, name: *const c_char) -> u8;
}

type ConfigParser = fn(*const c_char) -> i32;

/**
 * key
 */
pub const KEY_T_BOOL: u16 = 1;
pub const KEY_T_INT8: u16 = 2;
pub const KEY_T_INT16: u16 = 3;
pub const KEY_T_INT32: u16 = 4;
pub const KEY_T_INT64: u16 = 5;
pub const KEY_T_UINT8: u16 = 6;
pub const KEY_T_UINT16: u16 = 7;
pub const KEY_T_UINT32: u16 = 8;
pub const KEY_T_UINT64: u16 = 9;
pub const KEY_T_INADDR: u16 = 10;
pub const KEY_T_IN6ADDR: u16 = 11;
pub const KEY_T_POINTER: u16 = 12;
pub const KEY_T_STRING: u16 = 13;
pub const KEY_T_EMBED: u16 = 14;

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
        KEY_T_BOOL => KeyType::BOOL,
        KEY_T_INT8 => KeyType::INT8,
        KEY_T_INT16 => KeyType::INT16,
        KEY_T_INT32 => KeyType::INT32,
        KEY_T_INT64 => KeyType::INT64,
        KEY_T_UINT8 => KeyType::UINT8,
        KEY_T_UINT16 => KeyType::UINT16,
        KEY_T_UINT32 => KeyType::UINT32,
        KEY_T_UINT64 => KeyType::UINT64,
        KEY_T_INADDR => KeyType::INADDR,
        KEY_T_IN6ADDR => KeyType::IN6ADDR,
        KEY_T_POINTER => KeyType::POINTER,
        KEY_T_STRING => KeyType::STRING,
        KEY_T_EMBED => KeyType::EMBED,
        _ => KeyType::NONE,
    }
}

type KeyDestructor = fn(*mut c_void);

pub enum Input {}
extern "C" {
    fn nurs_input_len(input: *const Input) -> u16;
    fn nurs_input_size(input: *const Input, idx: u16) -> u32;

    fn nurs_input_name(input: *const Input, idx: u16) -> *const c_char;
    fn nurs_input_type(input: *const Input, idx: u16) -> u16;
    fn nurs_input_index(input: *const Input, name: *const c_char) -> u16;

    fn nurs_input_bool(input: *const Input, idx: u16) -> bool;
    fn nurs_input_u8(input: *const Input, idx: u16) -> u8;
    fn nurs_input_u16(input: *const Input, idx: u16) -> u16;
    fn nurs_input_u32(input: *const Input, idx: u16) -> u32;
    fn nurs_input_u64(input: *const Input, idx: u16) -> u64;
    fn nurs_input_in_addr(input: *const Input, idx: u16) -> in_addr_t;
    fn nurs_input_in6_addr(input: *const Input, idx: u16) -> *const in6_addr;
    fn nurs_input_pointer(input: *const Input, idx: u16) -> *const c_void;
    fn nurs_input_string(input: *const Input, idx: u16) -> *const c_char;
    fn nurs_input_is_valid(input: *const Input, idx: u16) -> bool;
    fn nurs_input_is_active(input: *const Input, idx: u16) -> bool;
    fn nurs_input_ipfix_vendor(input: *const Input, idx: u16) -> u32;
    fn nurs_input_ipfix_field(input: *const Input, idx: u16) -> u16;
    fn nurs_input_cim_name(input: *const Input, idx: u16) -> *const c_char;
}

pub enum Output {}
extern "C" {
    fn nurs_output_len(output: *const Output) -> u16;
    fn nurs_output_size(output: *const Output, idx: u16) -> u32;
    fn nurs_output_type(output: *const Output, idx: u16) -> u16;
    fn nurs_output_index(output: *const Output, name: *const c_char) -> u16;

    fn nurs_output_set_bool(output: *mut Output, idx: u16, value: bool) -> c_int;
    fn nurs_output_set_u8(output: *mut Output, idx: u16, value: u8) -> c_int;
    fn nurs_output_set_u16(output: *mut Output, idx: u16, value: u16) -> c_int;
    fn nurs_output_set_u32(output: *mut Output, idx: u16, value: u32) -> c_int;
    fn nurs_output_set_u64(output: *mut Output, idx: u16, value: u64) -> c_int;
    fn nurs_output_set_in_addr(output: *mut Output, idx: u16, value: in_addr_t) -> c_int;
    fn nurs_output_set_in6_addr(output: *mut Output, idx: u16, value: *const in6_addr) -> c_int;
    fn nurs_output_set_pointer(output: *mut Output, idx: u16, value: *const c_void) -> c_int;
    fn nurs_output_set_string(output: *mut Output, idx: u16, value: *const c_char) -> c_int;
    fn nurs_output_pointer(output: *const Output, idx: u16) -> *mut c_void;
    fn nurs_output_set_valid(output: *mut Output, idx: u16) -> c_int;
}

/**
 * plugin
 */
pub const RET_ERROR: c_int = -1;
pub const RET_STOP: c_int = -2;
pub const RET_OK: c_int = 0;

// #[repr(C)]
#[derive(Debug)]
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
    ($s:ident) => {
        $crate::return_t_cint($crate::ReturnType::$s)
    };
}

pub enum Producer {}
pub enum Plugin {}

type Start = fn(*const Plugin) -> c_int;
type ProducerStart = fn(*const Producer) -> c_int;
type Stop = fn(*const Plugin) -> c_int;
type ProducerStop = fn(*const Producer) -> c_int;
type Signal = fn(*const Plugin, u32) -> c_int;
type ProducerSignal = fn(*const Producer, u32) -> c_int;
type Organize = fn(*const Plugin) -> c_int;
type CoveterOrganize = fn(*const Plugin, *const Input) -> c_int;
type ProducerOrganize = fn(*const Producer) -> c_int;
type Disorganize = fn(*const Plugin) -> c_int;
type ProducerDisorganize = fn(*const Producer) -> c_int;
type Interp = fn(*const Plugin, *const Input, *mut Output) -> c_int;
type ConsumerInterp = fn(*const Plugin, *const Input) -> c_int;

extern "C" {
    fn nurs_producer_unregister_name(name: *const c_char) -> c_int;
    fn nurs_filter_unregister_name(name: *const c_char) -> c_int;
    fn nurs_consumer_unregister_name(name: *const c_char) -> c_int;
    fn nurs_coveter_unregister_name(name: *const c_char) -> c_int;
}

extern "C" {
    fn nurs_producer_register_jsons(input: *const c_char, context_size: u16) -> *const c_void;
    fn nurs_filter_register_jsons(input: *const c_char, context_size: u16) -> *const c_void;
    fn nurs_consumer_register_jsons(input: *const c_char, context_size: u16) -> *const c_void;
    fn nurs_coveter_register_jsons(input: *const c_char, context_size: u16) -> *const c_void;
    fn nurs_producer_register_jsonf(fname: *const c_char, context_size: u16) -> *const c_void;
    fn nurs_filter_register_jsonf(fname: *const c_char, context_size: u16) -> *const c_void;
    fn nurs_consumer_register_jsonf(fname: *const c_char, context_size: u16) -> *const c_void;
    fn nurs_coveter_register_jsonf(fname: *const c_char, context_size: u16) -> *const c_void;
    fn nurs_plugins_register_jsonf(fname: *const c_char) -> c_int;
    fn nurs_plugins_unregister_jsonf(fname: *const c_char) -> c_int;
}

extern "C" {
    fn nurs_producer_context(producer: *const Producer) -> *mut c_void;
    fn nurs_plugin_context(plugin: *const Plugin) -> *mut c_void;
    fn nurs_producer_config(producer: *const Producer) -> *const Config;
    fn nurs_plugin_config(plugin: *const Plugin) -> *const Config;
}

extern "C" {
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

enum RawNfd {}
type CFdCb = extern "C" fn(*mut RawNfd, u16) -> c_int;

extern "C" {
    fn nurs_fd_get_fd(nfd: *const RawNfd) -> c_int;
    fn nurs_fd_get_data(nfd: *const RawNfd) -> *mut c_void;
    fn nurs_fd_register(fd: c_int, when: u16, cb: CFdCb, data: *mut c_void) -> *mut RawNfd;
    fn nurs_fd_unregister(nfd: *mut RawNfd) -> c_int;
}

/**
 * timer
 */
pub enum RawTimer {}
type CTimerCb = extern "C" fn(*mut RawTimer) -> c_int;

extern "C" {
    fn nurs_timer_get_data(timer: *const RawTimer) -> *mut c_void;
    fn nurs_timer_register(sc: time_t, cb: CTimerCb, data: *mut c_void) -> *mut RawTimer;
    fn nurs_itimer_register(
        ini: time_t,
        per: time_t,
        cb: CTimerCb,
        data: *mut c_void,
    ) -> *mut RawTimer;
    fn nurs_timer_unregister(timer: *mut RawTimer) -> c_int;
    fn nurs_timer_pending(timer: *const RawTimer) -> c_int;
}

/*
 * misc
 */
// __nurs_log(int level, char *file, int line, const char *message, ...);

macro_rules! cvt_may_error {
    ($fcall:expr, $mayerr:expr) => {{
        let ret = unsafe { $fcall };
        if ret != $mayerr {
            Ok(ret)
        } else {
            let err = Error::last_os_error();
            match err.raw_os_error() {
                Some(errno) => match errno {
                    0 => Ok(ret),
                    _ => Err(err),
                },
                _ => Ok(ret),
            }
        }
    }};
}

impl Config {
    pub fn integer(&self, idx: u8) -> io::Result<isize> {
        let ret = unsafe { nurs_config_integer(self, idx) };
        if ret != 0 {
            return Ok(ret as isize);
        }

        let err = Error::last_os_error();
        match err.raw_os_error() {
            Some(errno) => match errno {
                0 => Ok(ret as isize),
                _ => Err(err),
            },
            _ => Ok(ret as isize),
        }
    }

    pub fn boolean(&self, idx: u8) -> io::Result<bool> {
        cvt_may_error!(nurs_config_boolean(self, idx), false)
    }

    pub fn string<'a>(&'a self, idx: u8) -> io::Result<&'a str> {
        match cvt_may_error!(nurs_config_string(self, idx), ptr::null()) {
            Ok(ret) => Ok(unsafe { CStr::from_ptr(ret).to_str().unwrap() }),
            // Ok(ret) => Ok(unsafe { CStr::from_ptr(ret).to_string_lossy().into_owned() }),
            Err(errno) => Err(errno),
        }
    }

    pub fn len(&self) -> u8 {
        unsafe { nurs_config_len(self) }
    }

    pub fn config_type(&self, idx: u8) -> io::Result<ConfigType> {
        match cvt_may_error!(nurs_config_type(self, idx), 0) {
            Ok(ret) => Ok(u16_config_t(ret)),
            Err(errno) => Err(errno),
        }
    }

    pub fn index(&self, name: &str) -> io::Result<u8> {
        let s = CString::new(name).unwrap();
        cvt_may_error!(nurs_config_index(self, s.as_ptr()), 0)
    }
}

impl Input {
    pub fn len(&self) -> u16 {
        unsafe { nurs_input_len(self) }
    }

    pub fn size(&self, idx: u16) -> io::Result<u32> {
        cvt_may_error!(nurs_input_size(self, idx), 0)
    }

    pub fn name<'a>(&'a self, idx: u16) -> io::Result<&'a str> {
        match cvt_may_error!(nurs_input_name(self, idx), ptr::null()) {
            Ok(ret) => Ok(unsafe { CStr::from_ptr(ret).to_str().unwrap() }),
            Err(errno) => Err(errno),
        }
    }

    pub fn key_type(&self, idx: u16) -> io::Result<KeyType> {
        match cvt_may_error!(nurs_input_type(self, idx), 0) {
            Ok(ret) => Ok(u16_key_t(ret)),
            Err(errno) => Err(errno),
        }
    }

    pub fn index(&self, name: &str) -> io::Result<u16> {
        let s = CString::new(name).unwrap();
        cvt_may_error!(nurs_input_index(self, s.as_ptr()), 0)
    }

    pub fn get_bool(&self, idx: u16) -> io::Result<bool> {
        cvt_may_error!(nurs_input_bool(self, idx), false)
    }

    pub fn get_u8(&self, idx: u16) -> io::Result<u8> {
        cvt_may_error!(nurs_input_u8(self, idx), 0)
    }

    pub fn get_u16(&self, idx: u16) -> io::Result<u16> {
        cvt_may_error!(nurs_input_u16(self, idx), 0)
    }

    pub fn get_u32(&self, idx: u16) -> io::Result<u32> {
        cvt_may_error!(nurs_input_u32(self, idx), 0)
    }

    pub fn get_u64(&self, idx: u16) -> io::Result<u64> {
        cvt_may_error!(nurs_input_u64(self, idx), 0)
    }

    pub fn get_in_addr(&self, idx: u16) -> io::Result<Ipv4Addr> {
        match cvt_may_error!(nurs_input_in_addr(self, idx), 0) {
            Ok(ret) => Ok(Ipv4Addr::from(ret as u32)),
            Err(errno) => Err(errno),
        }
    }

    pub fn get_in6_addr(&self, idx: u16) -> io::Result<Ipv6Addr> {
        match cvt_may_error!(nurs_input_in6_addr(self, idx), ptr::null()) {
            Ok(ret) => unsafe {
                Ok(Ipv6Addr::new(
                    ((*ret).s6_addr[0] as u16) << 8 | (*ret).s6_addr[1] as u16,
                    ((*ret).s6_addr[2] as u16) << 8 | (*ret).s6_addr[3] as u16,
                    ((*ret).s6_addr[4] as u16) << 8 | (*ret).s6_addr[5] as u16,
                    ((*ret).s6_addr[6] as u16) << 8 | (*ret).s6_addr[7] as u16,
                    ((*ret).s6_addr[8] as u16) << 8 | (*ret).s6_addr[9] as u16,
                    ((*ret).s6_addr[10] as u16) << 8 | (*ret).s6_addr[11] as u16,
                    ((*ret).s6_addr[12] as u16) << 8 | (*ret).s6_addr[13] as u16,
                    ((*ret).s6_addr[14] as u16) << 8 | (*ret).s6_addr[15] as u16,
                ))
            },
            Err(errno) => Err(errno),
        }
    }

    // http://stackoverflow.com/questions/24191249/working-with-c-void-in-an-ffi
    pub fn get_pointer<T>(&self, idx: u16) -> io::Result<Option<&T>> {
        match cvt_may_error!(nurs_input_pointer(self, idx), ptr::null()) {
            Ok(ret) => {
                if ret.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(unsafe { &*(ret as *const T) }))
                }
            }
            Err(errno) => Err(errno),
        }
    }

    pub fn get_string<'a>(&'a self, idx: u16) -> io::Result<&'a str> {
        match cvt_may_error!(nurs_input_string(self, idx), ptr::null()) {
            Ok(ret) => Ok(unsafe { CStr::from_ptr(ret).to_str().unwrap() }),
            Err(errno) => Err(errno),
        }
    }

    pub fn is_valid(&self, idx: u16) -> io::Result<bool> {
        cvt_may_error!(nurs_input_is_valid(self, idx), false)
    }

    pub fn is_active(&self, idx: u16) -> io::Result<bool> {
        cvt_may_error!(nurs_input_is_active(self, idx), false)
    }

    pub fn ipfix_vendor(&self, idx: u16) -> io::Result<u32> {
        cvt_may_error!(nurs_input_ipfix_vendor(self, idx), 0)
    }

    pub fn ipfix_field(&self, idx: u16) -> io::Result<u16> {
        cvt_may_error!(nurs_input_ipfix_field(self, idx), 0)
    }

    pub fn cim_name<'a>(&'a self, idx: u16) -> io::Result<&'a str> {
        match cvt_may_error!(nurs_input_cim_name(self, idx), ptr::null()) {
            Ok(ret) => Ok(unsafe { CStr::from_ptr(ret).to_str().unwrap() }),
            Err(errno) => Err(errno),
        }
    }
}

impl<'a> Output {
    pub fn len(&self) -> u16 {
        unsafe { nurs_output_len(self) }
    }

    pub fn size(&self, idx: u16) -> io::Result<u32> {
        cvt_may_error!(nurs_output_size(self, idx), 0)
    }

    pub fn key_type(&self, idx: u16) -> io::Result<KeyType> {
        match cvt_may_error!(nurs_output_type(self, idx), 0) {
            Ok(ret) => Ok(u16_key_t(ret)),
            Err(errno) => Err(errno),
        }
    }

    pub fn index(&self, name: &str) -> io::Result<u16> {
        let s = CString::new(name).unwrap();
        cvt_may_error!(nurs_output_index(self, s.as_ptr()), 0)
    }

    pub fn set_bool(&mut self, idx: u16, value: bool) -> io::Result<()> {
        cvt_may_error!(nurs_output_set_bool(self, idx, value), -1)?;
        Ok(())
    }

    pub fn set_u8(&mut self, idx: u16, value: u8) -> io::Result<()> {
        cvt_may_error!(nurs_output_set_u8(self, idx, value), -1)?;
        Ok(())
    }

    pub fn set_u16(&mut self, idx: u16, value: u16) -> io::Result<()> {
        cvt_may_error!(nurs_output_set_u16(self, idx, value), -1)?;
        Ok(())
    }

    pub fn set_u32(&mut self, idx: u16, value: u32) -> io::Result<()> {
        cvt_may_error!(nurs_output_set_u32(self, idx, value), -1)?;
        Ok(())
    }

    pub fn set_u64(&mut self, idx: u16, value: u64) -> io::Result<()> {
        cvt_may_error!(nurs_output_set_u64(self, idx, value), -1)?;
        Ok(())
    }

    pub fn set_in_addr(&mut self, idx: u16, value: &Ipv4Addr) -> io::Result<()> {
        let o = (*value).octets();
        let raw = (o[0] as u32) << 24 | (o[1] as u32) << 16 | (o[2] as u32) << 8 | (o[3] as u32);
        cvt_may_error!(nurs_output_set_in_addr(self, idx, raw as in_addr_t), -1)?;
        Ok(())
    }

    pub fn set_in6_addr(&mut self, idx: u16, value: &Ipv6Addr) -> io::Result<()> {
        cvt_may_error!(
            nurs_output_set_in6_addr(self, idx, value as *const _ as *const in6_addr),
            -1
        )?;
        Ok(())
    }

    pub fn set_pointer(&mut self, idx: u16, value: *const c_void) -> io::Result<()> {
        cvt_may_error!(nurs_output_set_pointer(self, idx, value), -1)?;
        Ok(())
    }

    pub fn set_string(&mut self, idx: u16, value: &str) -> io::Result<()> {
        let s = CString::new(value).unwrap();
        cvt_may_error!(nurs_output_set_string(self, idx, s.as_ptr()), -1)?;
        Ok(())
    }

    pub fn get_pointer<T>(&self, idx: u16) -> io::Result<Option<&'a mut T>> {
        match cvt_may_error!(nurs_output_pointer(self, idx), ptr::null_mut()) {
            Ok(ret) => {
                if ret.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(unsafe { &mut *(ret as *mut T) }))
                }
            }
            Err(errno) => Err(errno),
        }
    }

    pub fn set_valid(&mut self, idx: u16) -> io::Result<()> {
        cvt_may_error!(nurs_output_set_valid(self, idx), -1)?;
        Ok(())
    }

    pub fn publish(&mut self) -> io::Result<()> {
        cvt_may_error!(nurs_publish(self), -1)?;
        Ok(())
    }

    pub fn put(&mut self) -> io::Result<()> {
        cvt_may_error!(nurs_put_output(self), -1)?;
        Ok(())
    }
}

pub fn producer_unregister(name: &str) -> io::Result<()> {
    let s = CString::new(name).unwrap();
    cvt_may_error!(nurs_producer_unregister_name(s.as_ptr()), -1)?;
    Ok(())
}

pub fn filter_unregister(name: &str) -> io::Result<()> {
    let s = CString::new(name).unwrap();
    cvt_may_error!(nurs_filter_unregister_name(s.as_ptr()), -1)?;
    Ok(())
}

pub fn consumer_unregister(name: &str) -> io::Result<()> {
    let s = CString::new(name).unwrap();
    cvt_may_error!(nurs_consumer_unregister_name(s.as_ptr()), -1)?;
    Ok(())
}

pub fn coveter_unregister(name: &str) -> io::Result<()> {
    let s = CString::new(name).unwrap();
    cvt_may_error!(nurs_coveter_unregister_name(s.as_ptr()), -1)?;
    Ok(())
}

pub fn producer_register_jsons(input: &str, context_size: u16) -> io::Result<()> {
    let s = CString::new(input).unwrap();
    cvt_may_error!(
        nurs_producer_register_jsons(s.as_ptr(), context_size),
        ptr::null()
    )?;
    Ok(())
}

pub fn filter_register_jsons(input: &str, context_size: u16) -> io::Result<()> {
    let s = CString::new(input).unwrap();
    cvt_may_error!(
        nurs_filter_register_jsons(s.as_ptr(), context_size),
        ptr::null()
    )?;
    Ok(())
}

pub fn consumer_register_jsons(input: &str, context_size: u16) -> io::Result<()> {
    let s = CString::new(input).unwrap();
    cvt_may_error!(
        nurs_consumer_register_jsons(s.as_ptr(), context_size),
        ptr::null()
    )?;
    Ok(())
}

pub fn coveter_register_jsons(input: &str, context_size: u16) -> io::Result<()> {
    let s = CString::new(input).unwrap();
    cvt_may_error!(
        nurs_coveter_register_jsons(s.as_ptr(), context_size),
        ptr::null()
    )?;
    Ok(())
}

pub fn producer_resiger_jsonf(fname: &str, context_size: u16) -> io::Result<()> {
    let s = CString::new(fname).unwrap();
    cvt_may_error!(
        nurs_producer_register_jsonf(s.as_ptr(), context_size),
        ptr::null()
    )?;
    Ok(())
}

pub fn filter_register_jsonf(fname: &str, context_size: u16) -> io::Result<()> {
    let s = CString::new(fname).unwrap();
    cvt_may_error!(
        nurs_filter_register_jsonf(s.as_ptr(), context_size),
        ptr::null()
    )?;
    Ok(())
}

pub fn consumer_register_jsonf(fname: &str, context_size: u16) -> io::Result<()> {
    let s = CString::new(fname).unwrap();
    cvt_may_error!(
        nurs_consumer_register_jsonf(s.as_ptr(), context_size),
        ptr::null()
    )?;
    Ok(())
}

pub fn coveter_register_jsonf(fname: &str, context_size: u16) -> io::Result<()> {
    let s = CString::new(fname).unwrap();
    cvt_may_error!(
        nurs_coveter_register_jsonf(s.as_ptr(), context_size),
        ptr::null()
    )?;
    Ok(())
}

pub fn plugins_register_jfonf(fname: &str) -> io::Result<()> {
    let s = CString::new(fname).unwrap();
    cvt_may_error!(nurs_plugins_register_jsonf(s.as_ptr()), -1)?;
    Ok(())
}

pub fn plugins_unregster_jsonf(fname: &str) -> io::Result<()> {
    let s = CString::new(fname).unwrap();
    cvt_may_error!(nurs_plugins_unregister_jsonf(s.as_ptr()), -1)?;
    Ok(())
}

impl<'a> Plugin {
    pub fn context<T>(&mut self) -> Option<&'a mut T> {
        let ret = unsafe { nurs_plugin_context(self) };
        if ret.is_null() {
            return None;
        } else {
            unsafe { Some(&mut (*(ret as *mut T))) }
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

impl<'a> Producer {
    pub fn context<T>(&self) -> Option<&'a mut T> {
        let ret = unsafe { nurs_producer_context(self) };
        if ret.is_null() {
            return None;
        } else {
            unsafe { Some(&mut (*(ret as *mut T))) }
        }
    }

    pub fn config(&self) -> Option<&'a Config> {
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

    pub fn get_output(&mut self) -> io::Result<&'a mut Output> {
        let ret = unsafe { nurs_get_output(self) };
        if !ret.is_null() {
            unsafe { Ok(&mut (*ret)) }
        } else {
            Err(Error::last_os_error())
        }
    }
}

pub type FdCb<S, T> = fn(&mut Fd<S, T>, u16) -> ReturnType;
pub struct Fd<S: AsRawFd + IntoRawFd + FromRawFd, T> {
    raw: *mut RawNfd,
    fd: S,
    cb: FdCb<S, T>,
    data: T,
}

extern "C" fn fdcb<S, T>(rawnfd: *mut RawNfd, what: u16) -> c_int
where
    S: AsRawFd + IntoRawFd + FromRawFd,
{
    let mut cbdata = unsafe { Box::from_raw(nurs_fd_get_data(rawnfd) as *mut Fd<S, T>) };
    let ret = (cbdata.cb)(&mut cbdata, what);
    mem::forget(cbdata);
    match ret {
        ReturnType::OK => RET_OK,
        ReturnType::STOP => RET_STOP,
        _ => RET_ERROR,
    }
}

impl<'a, S, T> Fd<S, T>
where
    S: AsRawFd + IntoRawFd + FromRawFd,
{
    pub fn register(fd: S, when: u16, cb: FdCb<S, T>, data: T) -> io::Result<&'a mut Fd<S, T>> {
        let errval: *mut RawNfd = ptr::null_mut();
        let rawfd = fd.as_raw_fd();
        let cbdata = Box::into_raw(Box::new(Fd {
            raw: errval,
            fd: fd,
            cb: cb,
            data: data,
        }));
        let rawnfd = cvt_may_error!(
            nurs_fd_register(rawfd, when, fdcb::<S, T>, cbdata as *mut c_void),
            errval
        )?;
        unsafe {
            (*cbdata).raw = rawnfd;
        }
        Ok(unsafe { &mut *cbdata })
    }

    pub fn data(&self) -> &'a mut T {
        // XXX: or change &self to &mut self, then just return &mut self.data
        unsafe {
            let rawdata = Box::from_raw(nurs_fd_get_data(self.raw) as *mut Fd<S, T>);
            &mut (*Box::into_raw(rawdata)).data
        }
    }

    pub fn fd(&self) -> &'a mut S {
        unsafe {
            let rawdata = Box::from_raw(nurs_fd_get_data(self.raw) as *mut Fd<S, T>);
            &mut (*Box::into_raw(rawdata)).fd
        }
    }

    pub fn unregister(&mut self) -> io::Result<()> {
        let cbdata = unsafe { Box::from_raw(nurs_fd_get_data(self.raw) as *mut Fd<S, T>) };
        if let Err(err) = cvt_may_error!(nurs_fd_unregister(cbdata.raw), -1) {
            mem::forget(cbdata);
            return Err(err);
        }
        // XXX: assume Box drop closes fd.
        // unsafe { S::from_raw_fd(nurs_fd_get_fd(cbdata.raw)); }
        Ok(())
    }
}

pub type TimerCb<T> = fn(&mut Timer<T>) -> ReturnType;
pub struct Timer<T> {
    raw: *mut RawTimer,
    cb: TimerCb<T>,
    data: T,
}

extern "C" fn timercb<T>(timer: *mut RawTimer) -> c_int {
    let mut cbdata = unsafe { Box::from_raw(nurs_timer_get_data(timer) as *mut Timer<T>) };
    let ret = (cbdata.cb)(&mut cbdata);
    mem::forget(cbdata);
    match ret {
        ReturnType::OK => RET_OK,
        ReturnType::STOP => RET_STOP,
        _ => RET_ERROR,
    }
}

impl<'a, T> Timer<T> {
    pub fn register(sc: time_t, cb: TimerCb<T>, data: T) -> io::Result<&'a mut Timer<T>> {
        let errval: *mut RawTimer = ptr::null_mut();
        let cbdata = Box::into_raw(Box::new(Timer {
            raw: errval,
            cb: cb,
            data: data,
        }));
        let rawtimer = cvt_may_error!(
            nurs_timer_register(sc, timercb::<T>, cbdata as *mut c_void),
            errval
        )?;
        unsafe {
            (*cbdata).raw = rawtimer;
        }
        Ok(unsafe { &mut *cbdata })
    }

    pub fn iregister(
        ini: time_t,
        per: time_t,
        cb: TimerCb<T>,
        data: T,
    ) -> io::Result<&'a mut Timer<T>> {
        let errval: *mut RawTimer = ptr::null_mut();
        let cbdata = Box::into_raw(Box::new(Timer {
            raw: errval,
            cb: cb,
            data: data,
        }));
        let rawtimer = cvt_may_error!(
            nurs_itimer_register(ini, per, timercb::<T>, cbdata as *mut c_void),
            errval
        )?;
        unsafe {
            (*cbdata).raw = rawtimer;
        }
        Ok(unsafe { &mut *cbdata })
    }

    pub fn data(&self) -> &mut T {
        unsafe {
            let rawdata = Box::from_raw(nurs_timer_get_data(self.raw) as *mut Timer<T>);
            &mut (*Box::into_raw(rawdata)).data
        }
    }

    pub fn unregister(&mut self) -> io::Result<()> {
        let cbdata = unsafe { Box::from_raw(nurs_timer_get_data(self.raw) as *mut Timer<T>) };
        if let Err(err) = cvt_may_error!(nurs_timer_unregister(cbdata.raw), -1) {
            mem::forget(cbdata);
            return Err(err);
        }
        Ok(())
    }

    pub fn pending(&self) -> io::Result<bool> {
        match cvt_may_error!(nurs_timer_pending(self.raw), -1) {
            Ok(ret) => match ret {
                0 => Ok(false),
                _ => Ok(true),
            },
            Err(errno) => Err(errno),
        }
    }
}
