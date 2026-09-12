# WebSocket codec

Encode and decode WebSocket frames (RFC 6455 §§5.2–5.3). Incremental: a
frame may split across feeds; each feed returns zero or more completed frames.
No HTTP, TCP, TLS, session, or message reassembly. API in
[include/wsc.h](include/wsc.h).

## Build

Hosted (`-DWSC_HOSTED=ON` required on every configure; the cache keeps the last value otherwise):

```sh
cmake -B build -DWSC_HOSTED=ON && cmake --build build && ctest --test-dir build
```

Freestanding:

```sh
cmake -B build -DWSC_HOSTED=OFF && cmake --build build && ctest --test-dir build
```

See [CMakeLists.txt](CMakeLists.txt) and [tests/CMakeLists.txt](tests/CMakeLists.txt) for
options and dependencies.

## Style

Run the [build](#build) step first when `compile_commands.json` is missing or stale.

`--experimental-custom-checks` is required for `CustomChecks` in `.clang-tidy`.

To fix formatting, rerun the clang-format command below with `-i` in place of
`--dry-run --Werror`.

```sh
clang-format-23 --dry-run --Werror $(find include src examples tests -type f -name '*.[ch]' | sort)
clang-tidy-23 --experimental-custom-checks $(jq -r '.[].file' compile_commands.json)
```
