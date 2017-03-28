use std::mem;

extern crate libc;
use libc::c_int;

#[macro_use(nurs_return)]
#[macro_use(nurs_log)]
extern crate nurs;


struct TickPriv <'a> {
    name: &'a str,
}

#[no_mangle]
pub extern fn tick_organize(plugin: &mut nurs::Plugin) -> c_int {
    let mut ctx = plugin.context::<TickPriv>().unwrap();
    let config = plugin.config().unwrap();
    ctx.name = config.string(0).unwrap();
    nurs_return!(OK)
}

#[no_mangle]
pub extern fn tick_interp(plugin: &mut nurs::Plugin, input: &nurs::Input) -> c_int {
    let ctx = plugin.context::<TickPriv>().unwrap();
    let srcname = input.get_string(1).unwrap();
    match input.get_u64(0) {
        Ok(value) => {
            nurs_log!(INFO, "counter x 1: {}, {} -> {}", value, srcname, ctx.name);
            nurs_return!(OK)
        },
        Err(errno) => {
            nurs_log!(ERROR, "errno: {}", errno);
            nurs_return!(ERROR)
        }
    }
}

pub extern fn tick_consumer_init() {
    let fname = "consumer_rs.json";
    nurs::consumer_register_jsonf(fname, mem::size_of::<TickPriv>() as u16).unwrap();
}

#[link_section = ".ctors"]
pub static CONSTRUCTOR: extern fn() = tick_consumer_init;
