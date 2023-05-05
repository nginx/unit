#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include "unit-wasm-raw.h"

__attribute__((import_module("env"), import_name("nxt_wasm_send_headers")))
void nxt_wasm_send_headers(u32 offset);

void send_headers(u8 *addr, const char *ct, size_t len)
{
	struct resp_hdr *rh;
	char clen[32];
	u8 *p;
	static const u32 hdr_offs = 0;

	rh = (struct resp_hdr *)addr;

#define SET_HDR_FIELD(idx, name, val) \
	do { \
		rh->fields[idx].name_offs = p - addr; \
		rh->fields[idx].name_len = strlen(name); \
		p = mempcpy(p, name, rh->fields[idx].name_len); \
		rh->fields[idx].value_offs = p - addr; \
		rh->fields[idx].value_len = strlen(val); \
		p = mempcpy(p, val, rh->fields[idx].value_len); \
	} while (0)

	rh->nr_fields = 2;
	p = addr + sizeof(struct resp_hdr) +
	    (rh->nr_fields * sizeof(struct hdr_field));

	SET_HDR_FIELD(0, "Content-Type", ct);
	snprintf(clen, sizeof(clen), "%lu", len);
	SET_HDR_FIELD(1, "Content-Length", clen);

	nxt_wasm_send_headers(hdr_offs);
}
