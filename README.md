# swsc

Platform-independent, sans-I/O RFC 6455 WebSocket **codec** in C
(sections 5–7): framing, masking, fragmentation, ping/pong, the closing
handshake, and UTF-8 checks on text. Hosted C23 (`malloc`); no sockets.

It does **not** implement HTTP, TCP, TLS, the opening handshake (section 4),
or a send queue. After `101 Switching Protocols`, feed bytes from the socket
and send the returned frames back. Short `send()` and control-before-data
ordering belong in a separate library (`swsq` / sansio-websocket-queue).

```
  application  <-->  swsc (frames / events)  <-->  your I/O
                          no sockets
```

## Build

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

## API sketch

`examples/hello.c` is two sessions in one process (no sockets). Encode a frame, feed those bytes to the peer:

```c
#include "swsc.h"

swsc *cli = swsc_create_client(NULL, NULL);
swsc *srv = swsc_create_server();

swsc_bytes b = swsc_text_frame(cli, (const uint8_t *)"hello", 5);
swsc_result in = swsc_feed(srv, b.p, b.n);

/* in.evs[0] is SWSC_EV_TEXT "hello" */
/* in.out is Pong / Close echo / fail Close from this parse, if any */
```

On a real connection, `send()` the frame bytes and `in.out`; `feed` takes
bytes from `recv()`. Copy helper bytes if `send()` can short-write.

A later `swsc_*_frame` / `swsc_fragment*` on the same session invalidates the
previous helper’s `swsc_bytes`. Copy if you need to hold them. `swsc_feed`’s
events and `out` stay valid until the next `swsc_feed`.

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
| Fail Close, Pong for Ping, Close echo | Unsolicited Ping / Pong, initiating Close |
| | Send queue (`swsq`) |

## Layout

```
include/swsc.h      public API
src/swsc.c          codec
src/utf8.c          streaming UTF-8
examples/hello.c    in-memory client + server
```

Apache-2.0. See `LICENSE`.
