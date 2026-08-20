# swsf

Platform-independent, sans-I/O RFC 6455 WebSocket **framer** in C
(sections 5–7): framing, masking, fragmentation, ping/pong, the closing
handshake, and UTF-8 checks on text. Hosted C99 (`malloc`); no sockets.

It does **not** implement HTTP, TCP, TLS, the opening handshake (section 4),
or a send queue. After `101 Switching Protocols`, feed bytes from the socket
and send the returned frames back. Short `send()` and control-before-data
ordering belong in a separate library (`swsq` / sansio-websocket-queue).

```
  application  <-->  swsf (frames / events)  <-->  your I/O
                          no sockets
```

## Build

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

## API sketch

`examples/hello.c` is two sessions in one process (no sockets). Encode a frame, feed those bytes to the peer:

```c
#include "swsf.h"

swsf *cli = swsf_create_client(NULL, NULL);
swsf *srv = swsf_create_server();

swsf_bytes b = swsf_text_frame(cli, (const uint8_t *)"hello", 5);
swsf_result in = swsf_feed(srv, b.p, b.n);

/* in.evs[0] is SWSF_EV_TEXT "hello" */
/* in.out is Pong / Close echo / fail Close from this parse, if any */
```

On a real connection, `send()` the frame bytes and `in.out`; `feed` takes bytes from `recv()`. Copy helper bytes if `send()` can short-write. `examples/threaded.c` is a sketch of control-before-data until `swsq` exists. `examples/echo_server.c` is the Autobahn testee after the HTTP upgrade.

A later `swsf_*_frame` / `swsf_fragment*` on the same session invalidates the previous helper’s `swsf_bytes`. Copy if you need to hold them. `swsf_feed`’s events and `out` stay valid until the next `swsf_feed`.

Clients mask every outgoing frame (RFC 6455 §5.3). The default PRNG is
**not** a CSPRNG; pass `rng` to `swsf_create_client` if you need unpredictable masks.
Servers never mask.

## What is in vs out of scope

| In library | Outside (your code / Autobahn testee) |
| --- | --- |
| Frame parse/encode | TCP, TLS |
| Client masking / server unmasking | HTTP/1.1 upgrade, `Sec-WebSocket-Key` |
| Continuation / interleaved control frames | URL routing, subprotocols |
| Close codes and UTF-8 (incl. split code points) | `permessage-deflate` (RFC 7692) |
| Fail Close, Pong for Ping, Close echo | Unsolicited Ping / Pong, initiating Close |
| | Send queue (`swsq`: peek/consume, control before data) |

Autobahn cases 12.* and 13.* (compression) are excluded for that reason.

## Autobahn Testsuite

`examples/echo_server.c` is a POSIX echo **testee**: it performs the HTTP
upgrade, then speaks only through `swsf`. That is the intended split.

```sh
cmake -B build && cmake --build build --target echo_server
./scripts/run-autobahn.sh
```

The script starts the echo server on port 9001 and runs
`crossbario/autobahn-testsuite` in `fuzzingclient` mode (Docker), or `wstest`
if that is on `PATH`. Reports land in `autobahn/reports/servers/`.

Config: `autobahn/fuzzingclient.json` (host) and
`autobahn/fuzzingclient.docker.json` (container paths). Compression cases
`12.*` / `13.*` are excluded.

## Layout

```
include/swsf.h            public API
src/swsf.c                framer
src/utf8.c               streaming UTF-8
tests/test_swsf.c         unit tests
examples/hello.c         in-memory client + server
examples/threaded.c      threads + send-order sketch (not the library)
examples/echo_server.c   Autobahn testee (HTTP + sockets)
autobahn/                fuzzingclient specs
scripts/run-autobahn.sh
```

Apache-2.0. See `LICENSE`.
