# Sans-I/O WebSocket codec

Platform-independent, sans-I/O RFC 6455 WebSocket **codec** in C
(sections 5–7): framing, masking, fragmentation, ping/pong, the closing
handshake, and UTF-8 checks on text.

It does **not** implement HTTP, TCP, TLS, the opening handshake (section 4),
or a send queue. After `101 Switching Protocols`, feed bytes from the socket
and send encoded helper bytes back. Short `send()` and control-before-data
ordering belong in a separate library (`swsq` / sansio-websocket-queue).

```
  application  <-->  swsc (frames / events)  <-->  your I/O
                          no sockets
```

## Build

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

## Style

`--experimental-custom-checks` is required so `CustomChecks` in `.clang-tidy` run.

```sh
clang-format-23 --dry-run --Werror include/*.h src/*.[ch] examples/*.c
clang-tidy-23 --experimental-custom-checks $(jq -r '.[].file' compile_commands.json)
```

## API sketch

`examples/hello.c` is two sessions in one process (no sockets). Encode a frame, feed those bytes to the peer:

```c
#include "swsc.h"

struct swsc *cli = swsc_create_client(nullptr, nullptr);
struct swsc *srv = swsc_create_server();

struct swsc_enc b = swsc_text_frame(cli, (const uint8_t *)"hello", 5);
struct swsc_result in = swsc_feed(srv, b.bytes.data, b.bytes.length);

/* in.evs[0] is SWSC_EV_TEXT "hello" */
```

On a real connection, `send()` the encoded bytes; `feed` takes bytes from `recv()`.
Copy helper bytes if `send()` can short-write. Encode Pong, Close echo, and fail Close
from the events (`swsc_pong_frame`, `swsc_close_frame`).

A later encode helper on the same session invalidates the previous helper's
`struct swsc_bytes`. Copy if you need to hold them. `swsc_feed`'s events stay valid
until the next `swsc_feed`.

Clients mask every outgoing frame (RFC 6455 §5.3). The default PRNG is
**not** a CSPRNG; pass `rng` to `swsc_create_client` if you need unpredictable
masks. Servers never mask.

## What is in vs out of scope

| In library | Outside |
| --- | --- |
| Frame parse/encode | TCP, TLS |
| Client masking / server unmasking | HTTP/1.1 upgrade, `Sec-WebSocket-Key` |
| Continuation / interleaved control frames | URL routing, subprotocols |
| Close codes and UTF-8 (incl. split code points) | `permessage-deflate` (RFC 7692) |
| | Fail Close, Pong for Ping, Close echo |
| | Unsolicited Ping / Pong, initiating Close |
| | Send queue (`swsq`) |

## Layout

```
include/swsc.h      public API
src/swsc.c          codec
src/utf8.c          streaming UTF-8
src/rng.c           default mask PRNG
examples/hello.c    in-memory client + server
```

Apache-2.0. See `LICENSE`.
