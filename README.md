# WebSocket codec

Platform-independent RFC 6455 WebSocket codec in C.

Bytes ↔ one WebSocket frame (RFC 6455 §§5.2–5.3): FIN, RSV, opcode, MASK,
payload length, masking key, payload. No HTTP, TCP, TLS, session, or
message reassembly.

```
  framer / protocol  <-->  wsc (one frame)  <-->  bytes
```

An app that uses a framer or protocol on top of this should not need this
API.

## Build

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

## Style

`--experimental-custom-checks` is required so `CustomChecks` in `.clang-tidy` run.

```sh
clang-format-23 --dry-run --Werror include/*.h src/*.[ch] examples/*.c tests/*.c
clang-tidy-23 --experimental-custom-checks $(jq -r '.[].file' compile_commands.json)
```

## API sketch

`examples/hello.c` encodes one frame into a caller-owned buffer and feeds
those bytes to a decoder:

```c
#include "wsc.h"

struct wsc_frame frame = {
    .payload = (const uint8_t *)"hello",
    .payload_len = 5,
    .opcode = WSC_OP_TEXT,
    .fin = true,
};
uint8_t buf[64];
size_t n = wsc_encode(buf, sizeof buf, &frame);

struct wsc_dec *dec = wsc_dec_create();
struct wsc_result result = wsc_dec_feed(dec, buf, n);
/* result.frames[0] is the same frame, payload unmasked */
```

Pass a 4-byte `mask_key` and `masked = true` to mask on encode. Decode
unmasks when MASK is set. A frame may be split across `wsc_dec_feed` calls.

## Layout

```
include/wsc.h       public API
src/wsc.c           frame codec
examples/hello.c    encode then decode one frame
tests/test_wsc.c    length, mask, and header cases
```

Apache-2.0. See `LICENSE`.
