# sws

Sans-I/O C library for the **WebSocket data protocol** in
[RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455) (sections 5–7):
framing, masking, fragmentation, ping/pong, the closing handshake, and UTF-8
checks on text.

It does **not** implement HTTP, TCP, TLS, or the opening handshake (section 4).
You own those. After `101 Switching Protocols`, feed bytes from the socket and
drain bytes back to it.

```
  application  <-->  sws (frames / events)  <-->  your I/O
                          no sockets
```

## Build

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

## API sketch

`examples/hello.c` is two sessions in one process (no sockets). Peek bytes from one, feed them to the other:

```c
#include "sws.h"

sws *cli = sws_create(SWS_ROLE_CLIENT, 64 * 1024);
sws *srv = sws_create(SWS_ROLE_SERVER, 64 * 1024);

sws_queue_text(cli, (const uint8_t *)"hello", 5);

size_t n;
const uint8_t *p = sws_peek(cli, &n);
sws_result in = sws_feed(srv, p, n);
sws_mark_consumed(cli, n);

/* in.evs[0] is SWS_EV_TEXT "hello" */
```

On a real connection, `peek` / `mark_consumed` go to `send()`, and `feed` takes bytes from `recv()`. `examples/echo_server.c` does that after the HTTP upgrade.

`max_message_size` is the inbound assembled-message cap (must be > 0).
The library does not pick a default; `examples/echo_server.c` uses 32 MiB
for Autobahn.

Clients mask every outgoing frame (RFC 6455 §5.3). The default PRNG is
**not** a CSPRNG; set `sws_config.rng` if you need unpredictable masks.
Servers never mask.

## What is in vs out of scope

| In library | Outside (your code / Autobahn testee) |
| --- | --- |
| Frame parse/encode | TCP, TLS |
| Client masking / server unmasking | HTTP/1.1 upgrade, `Sec-WebSocket-Key` |
| Continuation / interleaved control frames | URL routing, subprotocols |
| Close codes and UTF-8 (incl. split code points) | `permessage-deflate` (RFC 7692) |
| Auto close reply | Application pong to ping |

Autobahn cases 12.* and 13.* (compression) are excluded for that reason.

## Autobahn Testsuite

`examples/echo_server.c` is a POSIX echo **testee**: it performs the HTTP
upgrade, then speaks only through `sws`. That is the intended split.

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
include/sws.h            public API
src/sws.c                framer
src/sws_utf8.c           streaming UTF-8
tests/test_sws.c         unit tests
examples/hello.c         in-memory client + server
examples/echo_server.c   Autobahn testee (HTTP + sockets)
autobahn/                fuzzingclient specs
scripts/run-autobahn.sh
```

Apache-2.0. See `LICENSE`.
