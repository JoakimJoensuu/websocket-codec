# WebSocket codec

Encode and decode one WebSocket frame (RFC 6455 §§5.2–5.3). Incremental: a
frame may split across feeds. No HTTP, TCP, TLS, session, or message
reassembly. API in [include/wsc.h](include/wsc.h).

## Build

```sh
cmake -B build && cmake --build build && ctest --test-dir build
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
