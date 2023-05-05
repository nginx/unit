#ifndef _UNIT_WASM_H_
#define _UNIT_WASM_H_

#include <stddef.h>
#include <stdint.h>

typedef uint64_t u64;
typedef int64_t  s64;
typedef uint32_t u32;
typedef int32_t  s32;
typedef uint16_t u16;
typedef int16_t  s16;
typedef uint8_t   u8;
typedef int8_t    s8;

#ifndef __unused
#define __unused                __attribute__((unused))
#endif
#ifndef __maybe_unused
#define __maybe_unused          __unused
#endif
#ifndef __always_unused
#define __always_unused         __unused
#endif

struct hdr_field {
	u32 name_offs;
	u32 name_len;
	u32 value_offs;
	u32 value_len;
};

struct req {
	u32 method_offs;
	u32 method_len;
	u32 version_offs;
	u32 version_len;
	u32 path_offs;
	u32 path_len;
	u32 query_offs;
	u32 query_len;
	u32 remote_offs;
	u32 remote_len;
	u32 local_addr_offs;
	u32 local_addr_len;
	u32 local_port_offs;
	u32 local_port_len;
	u32 server_name_offs;
	u32 server_name_len;

	u32 content_offs;
	u32 content_len;
	u32 content_sent;
	u32 total_content_sent;

	u32 request_size;

	u32 nr_fields;

	u32 tls;

	struct hdr_field fields[];
};

struct resp {
	u32 size;

	u8 data[];
};

struct resp_hdr {
	u32 nr_fields;

	struct hdr_field fields[];
};

extern void send_headers(u8 *addr, const char *ct, size_t len);

#endif /* _UNIT_WASM_H_ */
