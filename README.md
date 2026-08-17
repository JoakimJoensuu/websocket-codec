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

```c
#include "sws.h"

sws *ws = sws_create(SWS_ROLE_SERVER); /* or SWS_ROLE_CLIENT */

/* inbound TCP bytes */
sws_result in = sws_feed(ws, buf, n);
size_t i;
for (i = 0; i < in.n; i++) {
    if (in.evs[i].kind == SWS_EV_TEXT) {
        sws_send_text(ws, in.evs[i].data, in.evs[i].len);
    }
    if (in.evs[i].kind == SWS_EV_BIN) {
        sws_send_bin(ws, in.evs[i].data, in.evs[i].len);
    }
    /* ping is auto-answered; close is auto-answered unless you disable it */
}

/* outbound TCP bytes */
size_t n;
const uint8_t *p = sws_peek(ws, &n);
send(fd, p, n, 0);
sws_consume(ws, n);

sws_destroy(ws);
```

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
| Auto pong / auto close reply | |

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
include/sws.h           public API
src/sws.c               framer
src/sws_utf8.c          streaming UTF-8
tests/test_sws.c        unit tests
examples/echo_server.c   Autobahn testee (HTTP + sockets)
autobahn/                fuzzingclient specs
scripts/run-autobahn.sh
```

Apache-2.0. See `LICENSE`.
