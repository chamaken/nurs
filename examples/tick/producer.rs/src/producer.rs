use std::any::Any;

extern crate libc;
use libc::c_int;

#[macro_use(nurs_return)]
#[macro_use(nurs_log)]
extern crate nurs;


struct TickPriv <'a> {
    counter: u64,
    timer: &'a mut nurs::Timer,
    myname: &'a str,
}

fn timercb(_: &mut nurs::Timer, data: &mut Any) -> nurs::ReturnType {
    let mut producer = data.downcast_mut::<nurs::Producer>().unwrap();
    let mut ctx = unsafe { &mut(*(producer.context() as *mut TickPriv)) };
    let mut output = producer.get_output().unwrap();
    output.set_u64(0, ctx.counter);
    ctx.counter += 1;
    output.set_string(1, ctx.myname);
    output.publish();
    nurs::ReturnType::OK
}

#[no_mangle]
pub extern fn tick_organize(producer: &mut nurs::Producer) -> c_int {
    let mut ctx = unsafe { &mut(*(producer.context() as *mut TickPriv)) };
    let config = producer.config().unwrap();
    ctx.myname = config.string(0).unwrap();
    ctx.counter = 0;
    match nurs::Timer::create(timercb, producer) {
        Ok(timer)  => {
            ctx.timer = timer;
            nurs_return!(OK)
        },
        Err(errno) => {
            nurs_log!(ERROR, "failed to create timer: {}", errno);
            nurs_return!(ERROR)
        }
    }
}

#[no_mangle]
pub extern fn tick_disorganize(producer: &mut nurs::Producer) -> c_int {
    let mut ctx = unsafe { &mut(*(producer.context() as *mut TickPriv)) };
    if let Some(errno) = ctx.timer.destroy() {
        nurs_log!(ERROR, "failed to destroy timer: {}", errno);
        nurs_return!(ERROR)
    } else {
        nurs_return!(OK)
    }
}

#[no_mangle]
pub extern fn tick_start(producer: &mut nurs::Producer) -> c_int {
    let mut ctx = unsafe { &mut(*(producer.context() as *mut TickPriv)) };
    if let Some(errno) = ctx.timer.iadd(1, 1) {
        nurs_log!(ERROR, "failed to add itimer: {}", errno);
        nurs_return!(ERROR)
    } else {
        nurs_return!(OK)
    }
}

#[no_mangle]
pub extern fn tick_stop(producer: &mut nurs::Producer) -> c_int {
    let mut ctx = unsafe { &mut(*(producer.context() as *mut TickPriv)) };
    if let Some(errno) = ctx.timer.del() {
        nurs_log!(ERROR, "failed to del timer: {}", errno);
        nurs_return!(ERROR)
    } else {
        nurs_return!(OK)
    }
}

static JSONRC: &'static str = r#"
{
    "version": "0.1",
    "name": "RS_TICK_PRODUCER",
    "config": [
	{ "name": "myname",
	  "type": "NURS_CONFIG_T_STRING",
	  "flags": ["NURS_CONFIG_F_MANDATORY"]}
    ],
    "output" : [
	{ "name": "counter",
	  "type": "NURS_KEY_T_UINT64",
	  "flags": ["NURS_OKEY_F_ALWAYS"] },
	{ "name": "producer.name",
	  "type": "NURS_KEY_T_STRING",
	  "flags": ["NURS_OKEY_F_ALWAYS"],
	  "len":  32 }
    ],
    "organize":		"tick_organize",
    "disorganize":	"tick_disorganize",
    "start":		"tick_start",
    "stop":		"tick_stop"
}"#;

pub extern fn tick_producer_init() {
    nurs::producer_register_jsons(JSONRC, 0);
}

#[link_section = ".ctors"]
pub static CONSTRUCTOR: extern fn() = tick_producer_init;
