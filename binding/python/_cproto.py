import errno, ctypes

NURS = ctypes.CDLL("/usr/local/sbin/nursd", use_errno=False)

#
# config
#
c_nurs_config_integer = NURS.nurs_config_integer
c_nurs_config_integer.__doc__ = """\
int nurs_config_integer(const struct nurs_config *config, uint8_t idx)"""
c_nurs_config_integer.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_config_integer.restype = ctypes.c_int

c_nurs_config_boolean = NURS.nurs_config_boolean
c_nurs_config_boolean.__doc__ = """\
bool nurs_config_boolean(const struct nurs_config *config, uint8_t idx)"""
c_nurs_config_boolean.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_config_integer.restype = ctypes.c_bool

c_nurs_config_string = NURS.nurs_config_string
c_nurs_config_string.__doc__ = """\
const char *nurs_config_string(const struct nurs_config *config, uint8_t idx)"""
c_nurs_config_string.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_config_integer.restype = ctypes.c_char_p

#
# key
#
c_nurs_input_len = NURS.nurs_input_len
c_nurs_input_len.__doc__ = """\
uint16_t nurs_input_len(const struct nurs_input *input)"""
c_nurs_input_len.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_len.restype = ctypes.c_uint16

c_nurs_input_size = NURS.nurs_input_size
c_nurs_input_size.__doc__ = """\
uint16_t nurs_input_size(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_size.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_size.restype = ctypes.c_uint16

c_nurs_input_name = NURS.nurs_input_name
c_nurs_input_name.__doc__ = """\
const char *nurs_input_name(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_name.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_name.restype = ctypes.c_char_p

c_nurs_input_type = NURS.nurs_input_type
c_nurs_input_type.__doc__ = """\
uint16_t nurs_input_type(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_type.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_type.restype = ctypes.c_uint16

c_nurs_input_index = NURS.nurs_input_index
c_nurs_input_index.__doc__ = """\
uint8_t nurs_input_index(const struct nurs_input *input, const char *name)"""
c_nurs_input_index.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
c_nurs_input_index.restype = ctypes.c_uint8

c_nurs_input_bool = NURS.nurs_input_bool
c_nurs_input_bool.__doc__ = """\
bool nurs_input_bool(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_bool.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_bool.restype = ctypes.c_bool

c_nurs_input_u8 = NURS.nurs_input_u8
c_nurs_input_u8.__doc__ = """\
uint8_t nurs_input_u8(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_u8.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_u8.restype = ctypes.c_uint8

c_nurs_input_u16 = NURS.nurs_input_u16
c_nurs_input_u16.__doc__ = """\
uint16_t nurs_input_u16(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_u16.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_u16.restype = ctypes.c_uint16

c_nurs_input_u32 = NURS.nurs_input_u32
c_nurs_input_u32.__doc__ = """\
uint32_t nurs_input_u32(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_u32.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_u32.restype = ctypes.c_uint32

c_nurs_input_u64 = NURS.nurs_input_u64
c_nurs_input_u64.__doc__ = """\
uint64_t nurs_input_u64(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_u64.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_u64.restype = ctypes.c_uint64

c_nurs_input_in_addr = NURS.nurs_input_in_addr
c_nurs_input_in_addr.__doc__ = """\
in_addr_t nurs_input_in_addr(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_in_addr.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_in_addr.restype = ctypes.c_uint32 # XXX

c_nurs_input_in6_addr = NURS.nurs_input_in6_addr
c_nurs_input_in6_addr.__doc__ = """\
const struct in6_addr *
	nurs_input_in6_addr(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_in6_addr.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_in6_addr.restype = ctypes.c_void_p # XXX

c_nurs_input_pointer = NURS.nurs_input_pointer
c_nurs_input_pointer.__doc__ = """\
const void *nurs_input_pointer(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_pointer.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_pointer.restype = ctypes.c_void_p

c_nurs_input_is_valid = NURS.nurs_input_is_valid
c_nurs_input_is_valid.__doc__ = """\
bool nurs_input_is_valid(const struct nurs_input *input, uint8_t idx)"""
c_nurs_input_is_valid.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_input_is_valid.restype = ctypes.c_bool

c_nurs_output_len = NURS.nurs_output_len
c_nurs_output_len.__doc__ = """\
uint16_t nurs_output_len(const struct nurs_output *output)"""
c_nurs_output_len.argtypes = [ctypes.c_void_p]
c_nurs_output_len.restype = ctypes.c_uint16

c_nurs_output_size = NURS.nurs_output_size
c_nurs_output_size.__doc__ = """\
uint16_t nurs_output_size(const struct nurs_output *output, uint8_t idx)"""
c_nurs_output_size.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_output_size.restype = ctypes.uint16

c_nurs_output_set_bool = NURS.nurs_output_set_bool
c_nurs_output_set_bool.__doc__ = """\
int nurs_output_set_bool(struct nurs_output *output,
			 uint8_t idx, bool value)"""
c_nurs_output_set_bool.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.c_bool]
c_nurs_output_set_bool.restype = ctypes.c_int

c_nurs_output_set_u8 = NURS.nurs_output_set_u8
c_nurs_output_set_u8.__doc__ = """\
int nurs_output_set_u8(struct nurs_output *output,
		       uint8_t idx, uint8_t value)"""
c_nurs_output_set_u8.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint8]
c_nurs_output_set_u8.restype = ctypes.c_int

c_nurs_output_set_u16 = NURS.nurs_output_set_u16
c_nurs_output_set_u16.__doc__ = """\
int nurs_output_set_u16(struct nurs_output *output,
			uint8_t idx, uint16_t value)"""
c_nurs_output_set_u16.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint16]
c_nurs_output_set_u16.restype = ctypes.c_int

c_nurs_output_set_u32 = NURS.nurs_output_set_u32
c_nurs_output_set_u32.__doc__ = """\
int nurs_output_set_u32(struct nurs_output *output,
			uint8_t idx, uint32_t value)"""
c_nurs_output_set_u32.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint32]
c_nurs_output_set_u32.restype = ctypes.c_int

c_nurs_output_set_u64 = NURS.nurs_output_set_u64
c_nurs_output_set_u64.__doc__ = """\
int nurs_output_set_u64(struct nurs_output *output,
			uint8_t idx, uint64_t value)"""
c_nurs_output_set_u64.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint64]
c_nurs_output_set_u64.restype = c_int

c_nurs_output_set_in_addr = NURS.nurs_output_set_in_addr
c_nurs_output_set_in_addr.__doc__ = """\
int nurs_output_set_in_addr(struct nurs_output *output,
			    uint8_t idx, in_addr_t value)"""
c_nurs_output_set_in_addr.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint32] # XXX
c_nurs_output_set_in_addr.restype = ctypes.c_int

c_nurs_output_set_in6_addr = NURS.nurs_output_set_in6_addr
c_nurs_output_set_in6_addr.__doc__ = """\
int nurs_output_set_in6_addr(struct nurs_output *output,
			     uint8_t idx, const struct in6_addr *value)"""
c_nurs_output_set_in6_addr.argtypes = [ctypes.c_void_p, ctypes.c_uint8, c_void_p] # XXX
c_nurs_output_set_in6_addr.restype = ctypes.c_int

c_nurs_output_set_pointer = NURS.nurs_output_set_pointer
c_nurs_output_set_pointer.__doc__ = """\
int nurs_output_set_pointer(struct nurs_output *output,
			    uint8_t idx, const void *value)"""
c_nurs_output_set_pointer.argtypes = [ctypes.c_void_p, ctypes.c_uint8, ctypes.c_void_p]
c_nurs_output_set_pointer.restype = ctypes.c_int

c_nurs_output_pointer = NURS.nurs_output_pointer
c_nurs_output_pointer.__doc__ = """\
void *nurs_output_pointer(const struct nurs_output *output, uint8_t idx)"""
c_nurs_output_pointer.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
c_nurs_output_pointer.restype = ctypes.c_void_p

c_nurs_output_set_valid = NURS.nurs_output_set_valid
c_nurs_output_set_valid.__doc__ = """\
int nurs_output_set_valid(struct nurs_output *output, uint8_t idx)"""
c_nurs_output_set_valid.argtypes = [ctypes.c_void_p, c_uint8]
c_nurs_output_set_valid.restype = ctypes.c_int

#
# plugin
#
NURS_START_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p], user_errno=False)
NURS_START_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_start_t)(const struct nurs_plugin *instance)"""

NURS_PRODUCER_START_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p], user_errno=False)
NURS_PRODUCER_START_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_producer_start_t)(const struct nurs_producer *producer)"""

NURS_STOP_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p], user_errno=False)
NURS_STOP_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_stop_t)(const struct nurs_plugin *instance)"""

NURS_PRODUCER_STOP_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p], user_errno=False)
NURS_PRODUCER_STOP_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_producer_stop_t)(const struct nurs_producer *producer)"""

NURS_SIGNAL_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p, ctypes_c_uin32], user_errno=False)
NURS_SIGNAL_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_signal_t)(const struct nurs_plugin *instance, uint32_t signum)"""

NURS_PRODUCER_SIGNAL_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p, ctypes_c_uin32], user_errno=False)
NURS_PRODUCER_SIGNAL_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_producer_signal_t)(const struct nurs_producer *producer, uint32_t signum)"""

NURS_ORGANIZE_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p], user_errno=False)
NURS_ORGANIZE_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_organize_t)(const struct nurs_plugin *instance)"""

NURS_COVETER_ORGANIZE_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p, ctypes_c_void_p], user_errno=False)
NURS_COVETER_ORGANIZE_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_coveter_organize_t)(const struct nurs_plugin *instance,
				   const struct nurs_input_def *input_def)"""

NURS_PRODUCER_ORGANIZE_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p], user_errno=False)
NURS_PRODUCER_ORGANIZE_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_producer_organize_t)(const struct nurs_producer *producer);
"""

NURS_DISORGANIZE_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p], user_errno=False)
NURS_DISORGANIZE_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_disorganize_t)(const struct nurs_plugin *instance)"""

NURS_PRODUCER_DISORGANIZE_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p], user_errno=False)
NURS_PRODUCER_DISORGANIZE_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_producer_disorganize_t)(const struct nurs_producer *producer)"""

NURS_FILTER_INTERP_T = ctypes.CFUNCTYPE(ctypes.c_int,
                                        [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p],
                                        user_errno=False)
NURS_FILTER_INTERP_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_filter_interp_t)(const struct nurs_plugin *instance,
				const struct nurs_input *input,
				struct nurs_output *output)"""

NURS_CONSUMER_INTERP_T = ctypes.CFUNCTYPE(ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p], user_errno=False)
NURS_CONSUMER_INTERP_T.__doc__ = """\
typedef enum nurs_plugin_return
	(*nurs_consumner_interp_t)(const struct nurs_plugin *instance,
				   const struct nurs_input *input)"""

c_nurs_propagate = NURS.nurs_propagate
c_nurs_propagate.__doc__ = """\
enum nurs_plugin_return
	nurs_propagate(struct nurs_producer *producer,
		       struct nurs_output *output)"""
c_nurs_propagate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
c_nurs_propagate.restype = ctypes.c_int

c_nurs_producer_context = NURS.nurs_producer_context
c_nurs_producer_context.__doc__ = """\
void *nurs_producer_context(const struct nurs_producer *producer)"""
c_nurs_proeucer_context.argtypes = [ctypes.c_void_p]
c_nurs_producer_context.restype = ctypes.c_void_p

c_nurs_plugin_context = NURS.nurs_plugin_context
c_nurs_plugin_context.__doc__ = """\
void *nurs_plugin_context(const struct nurs_plugin *instance)"""
c_nurs_plugin_context.argtypes = [ctypes.c_void_p]
c_nurs_plugin_context.restype = ctypes.c_void_p

c_nurs_producer_config = NURS.nurs_producer_config
c_nurs_producer_config.__doc__ = """\
const struct nurs_config *nurs_producer_config(const struct nurs_producer *producer)"""
c_nurs_producer_config.argtypes = [ctypes.c_void_p]
c_nurs_producer_config.restype = ctypes.c_void_p

c_nurs_plugin_config = NURS.nurs_plugin_config
c_nurs_plugin_config.__doc__ = """\
const struct nurs_config *nurs_plugin_config(const struct nurs_plugin *instance)"""
c_nurs_plugin_config.argtypes = [ctypes.c_void_p]
c_nurs_plugin_config.restype = ctypes.c_void_p
