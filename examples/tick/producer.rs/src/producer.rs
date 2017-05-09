extern crate libc;
use libc::c_int;

#[macro_use(nurs_return)]
#[macro_use(nurs_log)]
extern crate nurs;


struct TickPriv <'a> {
    counter: u64,
    timer: &'a mut nurs::Timer<&'a mut nurs::Producer>,
    myname: &'a str,
}

fn itimercb(timer: &mut nurs::Timer<&mut nurs::Producer>) -> nurs::ReturnType {
    let mut producer = timer.data();
    let mut ctx = producer.context::<TickPriv>().unwrap();
    let mut output = producer.get_output().unwrap();
    if let Err(errno) = output.set_u64(0, ctx.counter) {
        nurs_log!(ERROR, "failed to set u64 output value{}", errno);
        return nurs::ReturnType::ERROR;
    }
    ctx.counter += 1;
    if let Err(errno) = output.set_string(1, ctx.myname) {
        nurs_log!(ERROR, "failed to set string output value: {}", errno);
        return nurs::ReturnType::ERROR;
    }
    if let Err(errno) = output.publish() {
        nurs_log!(ERROR, "failed to publish output: {}", errno);
        return nurs::ReturnType::ERROR;
    }
    nurs::ReturnType::OK
}

#[no_mangle]
pub extern fn tick_organize(producer: &mut nurs::Producer) -> c_int {
    let mut ctx = producer.context::<TickPriv>().unwrap();
    let config = producer.config().unwrap();
    ctx.myname = config.string(0).unwrap();
    ctx.counter = 0;
    nurs_return!(OK)
}

#[no_mangle]
pub extern fn tick_start(producer: &mut nurs::Producer) -> c_int {
    let mut ctx = producer.context::<TickPriv>().unwrap();
    match nurs::Timer::iregister(1, 1, itimercb, producer) {
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
pub extern fn tick_stop(producer: &mut nurs::Producer) -> c_int {
    let mut ctx = producer.context::<TickPriv>().unwrap();
    if let Err(errno) = ctx.timer.unregister() {
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
    "start":		"tick_start",
    "stop":		"tick_stop"
}"#;

pub extern fn tick_producer_init() {
    nurs::producer_register_jsons(JSONRC, 0).unwrap();
}

#[link_section = ".ctors"]
pub static CONSTRUCTOR: extern fn() = tick_producer_init;
