#!/usr/bin/env python3
"""Smoke-test examples/echo_server.c against RFC 6455 framing (no Autobahn)."""
from __future__ import annotations

import hashlib
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ROOT = Path(__file__).resolve().parents[1]


def accept_key(key: str) -> str:
    import base64

    dig = hashlib.sha1(key.encode("ascii") + GUID).digest()
    return base64.b64encode(dig).decode("ascii")


def frame(fin: int, opcode: int, payload: bytes, mask_key: bytes = b"\x01\x02\x03\x04") -> bytes:
    b0 = (0x80 if fin else 0) | opcode
    n = len(payload)
    if n <= 125:
        hdr = bytes([b0, 0x80 | n])
    elif n <= 65535:
        hdr = bytes([b0, 0x80 | 126]) + struct.pack("!H", n)
    else:
        hdr = bytes([b0, 0x80 | 127]) + struct.pack("!Q", n)
    masked = bytes(payload[i] ^ mask_key[i % 4] for i in range(n))
    return hdr + mask_key + masked


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    hdr = recvn(sock, 2)
    fin_op = hdr[0]
    ln = hdr[1] & 0x7F
    assert (hdr[1] & 0x80) == 0  # server must not mask
    if ln == 126:
        ln = struct.unpack("!H", recvn(sock, 2))[0]
    elif ln == 127:
        ln = struct.unpack("!Q", recvn(sock, 8))[0]
    payload = recvn(sock, ln) if ln else b""
    return fin_op & 0x0F, payload


def recvn(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("socket closed")
        out += chunk
    return bytes(out)


def handshake(sock: socket.socket) -> None:
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    req = (
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(req.encode("ascii"))
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("handshake")
        data += chunk
    text = data.decode("iso-8859-1")
    assert "101" in text.split("\r\n", 1)[0]
    assert accept_key(key) in text


def main() -> int:
    port = int(os.environ.get("PORT", "19001"))
    server = os.environ.get("ECHO_SERVER")
    if not server:
        cand = ROOT / "build" / "echo_server"
        server = str(cand if cand.exists() else ROOT / "echo_server")
    proc = subprocess.Popen([server, str(port)], stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("server did not start")

        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        handshake(s)
        s.sendall(frame(1, 0x1, b"hello"))
        op, payload = read_frame(s)
        assert op == 0x1 and payload == b"hello", (op, payload)
        s.sendall(frame(1, 0x2, b"\x00\xff"))
        op, payload = read_frame(s)
        assert op == 0x2 and payload == b"\x00\xff"
        s.sendall(frame(1, 0x9, b"ping"))
        op, payload = read_frame(s)
        assert op == 0xA and payload == b"ping"
        s.sendall(frame(1, 0x8, struct.pack("!H", 1000) + b"bye"))
        op, payload = read_frame(s)
        assert op == 0x8
        assert payload[:2] == struct.pack("!H", 1000)
        s.close()
        print("echo_server smoke ok")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
