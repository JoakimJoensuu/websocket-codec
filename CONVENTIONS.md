# Conventions

How we write this repository. Not the same as language or protocol
standards (those are C99 and RFC 6455).

## Errors

Programming errors abort. Do not return an error code, and do not use
`assert` (that disappears under `NDEBUG`). Call `abort()`.

That includes NULL where a pointer is required, `len > 0` with a NULL
buffer, send after Close, an illegal outgoing opcode/close code, a
control payload over 125 bytes, and invalid UTF-8 on *outgoing* text.

`wsio_destroy(NULL)` is allowed (same as `free`).

Expected failures still return `wsio_err`: out of memory, and peer
protocol / UTF-8 / message-too-big (queue a Close when possible). Do not
add `WSIO_ERR_INVAL`.

## Comments

Comment only what names, types, and control flow cannot say. The root
`LICENSE` is enough; no per-file banners. When a public declaration needs
a comment, use Doxygen on the header, not the `.c` definition.

## Commits

The title says what the commit does, not what the program does afterwards.
It must complete the sentence "This commit will …".
