/**
 * Autobahn testee: POSIX TCP + HTTP upgrade, then wsio.
 *
 * Usage: `echo_server [port]`
 */

#define _POSIX_C_SOURCE 200809L

#include "wsio.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* SHA-1 only for Sec-WebSocket-Accept. */
typedef struct {
    uint32_t h[5];
    uint64_t nbits;
    uint8_t block[64];
    size_t nblock;
} sha1;

static uint32_t rol(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void sha1_init(sha1 *s)
{
    s->h[0] = 0x67452301u;
    s->h[1] = 0xEFCDAB89u;
    s->h[2] = 0x98BADCFEu;
    s->h[3] = 0x10325476u;
    s->h[4] = 0xC3D2E1F0u;
    s->nbits = 0;
    s->nblock = 0;
}

static void sha1_block(sha1 *s, const uint8_t b[64])
{
    uint32_t w[80];
    uint32_t a, c, d, e, f, k, temp;
    int i;
    uint32_t bb;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)b[4 * i] << 24) | ((uint32_t)b[4 * i + 1] << 16) |
               ((uint32_t)b[4 * i + 2] << 8) | (uint32_t)b[4 * i + 3];
    }
    for (i = 16; i < 80; i++) {
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    a = s->h[0];
    bb = s->h[1];
    c = s->h[2];
    d = s->h[3];
    e = s->h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (bb & c) | ((~bb) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = bb ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (bb & c) | (bb & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = bb ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        temp = rol(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol(bb, 30);
        bb = a;
        a = temp;
    }
    s->h[0] += a;
    s->h[1] += bb;
    s->h[2] += c;
    s->h[3] += d;
    s->h[4] += e;
}

static void sha1_update(sha1 *s, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    s->nbits += (uint64_t)len * 8;
    while (len) {
        size_t take = 64 - s->nblock;
        if (take > len) {
            take = len;
        }
        memcpy(s->block + s->nblock, p, take);
        s->nblock += take;
        p += take;
        len -= take;
        if (s->nblock == 64) {
            sha1_block(s, s->block);
            s->nblock = 0;
        }
    }
}

static void sha1_final(sha1 *s, uint8_t out[20])
{
    size_t i;
    s->block[s->nblock++] = 0x80;
    if (s->nblock > 56) {
        while (s->nblock < 64) {
            s->block[s->nblock++] = 0;
        }
        sha1_block(s, s->block);
        s->nblock = 0;
    }
    while (s->nblock < 56) {
        s->block[s->nblock++] = 0;
    }
    for (i = 0; i < 8; i++) {
        s->block[56 + i] = (uint8_t)(s->nbits >> (56 - 8 * (int)i));
    }
    sha1_block(s, s->block);
    for (i = 0; i < 5; i++) {
        out[4 * i] = (uint8_t)(s->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)s->h[i];
    }
}

static void b64_20(const uint8_t in[20], char out[29])
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j = 0;
    for (i = 0; i < 18; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[j++] = T[(v >> 18) & 63];
        out[j++] = T[(v >> 12) & 63];
        out[j++] = T[(v >> 6) & 63];
        out[j++] = T[v & 63];
    }
    {
        uint32_t v = ((uint32_t)in[18] << 16) | ((uint32_t)in[19] << 8);
        out[j++] = T[(v >> 18) & 63];
        out[j++] = T[(v >> 12) & 63];
        out[j++] = T[(v >> 6) & 63];
        out[j++] = '=';
    }
    out[j] = 0;
}

static int header_key(const char *hdrs, char key[32])
{
    const char *p = hdrs;
    for (;;) {
        const char *nl, *colon;
        if (!*p) {
            return -1;
        }
        if (p[0] == '\r' && p[1] == '\n') {
            return -1;
        }
        nl = strstr(p, "\r\n");
        if (!nl) {
            return -1;
        }
        colon = memchr(p, ':', (size_t)(nl - p));
        if (colon) {
            size_t n = (size_t)(colon - p);
            if (n == 17 && strncasecmp(p, "Sec-WebSocket-Key", 17) == 0) {
                const char *v = colon + 1;
                size_t i = 0;
                while (v < nl && (*v == ' ' || *v == '\t')) {
                    v++;
                }
                while (v < nl && i < 31 && *v != ' ' && *v != '\t' && *v != '\r') {
                    key[i++] = *v++;
                }
                key[i] = 0;
                return i == 24 ? 0 : -1;
            }
        }
        p = nl + 2;
    }
}

/* Leftover socket bytes after the HTTP headers go in leftover. */
static int handshake(int fd, uint8_t *leftover, size_t *nleft, size_t cap)
{
    char buf[8192];
    size_t n = 0;
    char key[32];
    sha1 s;
    uint8_t dig[20];
    char accept[29];
    char resp[256];
    int w;
    const char *end;

    while (n < sizeof buf - 1) {
        ssize_t r = recv(fd, buf + n, sizeof buf - 1 - n, 0);
        if (r <= 0) {
            return -1;
        }
        n += (size_t)r;
        buf[n] = 0;
        end = strstr(buf, "\r\n\r\n");
        if (end) {
            size_t hlen = (size_t)(end + 4 - buf);
            if (header_key(buf, key) != 0) {
                return -1;
            }
            sha1_init(&s);
            sha1_update(&s, key, strlen(key));
            sha1_update(&s, GUID, strlen(GUID));
            sha1_final(&s, dig);
            b64_20(dig, accept);
            w = snprintf(resp, sizeof resp,
                         "HTTP/1.1 101 Switching Protocols\r\n"
                         "Upgrade: websocket\r\n"
                         "Connection: Upgrade\r\n"
                         "Sec-WebSocket-Accept: %s\r\n"
                         "\r\n",
                         accept);
            if (w < 0 || send(fd, resp, (size_t)w, 0) != w) {
                return -1;
            }
            *nleft = n - hlen;
            if (*nleft > cap) {
                return -1;
            }
            memcpy(leftover, buf + hlen, *nleft);
            return 0;
        }
    }
    return -1;
}

static int flush_ws(int fd, wsio *ws)
{
    for (;;) {
        size_t n;
        const uint8_t *p = wsio_peek(ws, &n);
        ssize_t w;
        if (!n) {
            return 0;
        }
        w = send(fd, p, n, 0);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (w == 0) {
            return -1;
        }
        wsio_consume(ws, (size_t)w);
    }
}

static void session(int fd)
{
    wsio_config cfg;
    wsio *ws;
    uint8_t leftover[8192];
    size_t nleft = 0;
    uint8_t buf[64 * 1024];
    int one = 1;

    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (handshake(fd, leftover, &nleft, sizeof leftover) != 0) {
        return;
    }

    memset(&cfg, 0, sizeof cfg);
    cfg.role = WSIO_ROLE_SERVER;
    cfg.max_message_size = 32u * 1024u * 1024u;
    cfg.auto_pong = true;
    cfg.auto_close = true;
    ws = wsio_create_cfg(&cfg);
    if (!ws) {
        return;
    }

    if (nleft && wsio_feed(ws, leftover, nleft) != WSIO_OK) {
        flush_ws(fd, ws);
        wsio_destroy(ws);
        return;
    }

    for (;;) {
        wsio_event ev;
        bool stop = false;
        for (;;) {
            ev = wsio_poll(ws);
            if (ev.kind == WSIO_EV_NONE) {
                break;
            }
            if (ev.kind == WSIO_EV_TEXT) {
                if (wsio_send_text(ws, ev.data, ev.len) != WSIO_OK) {
                    stop = true;
                }
            } else if (ev.kind == WSIO_EV_BIN) {
                if (wsio_send_bin(ws, ev.data, ev.len) != WSIO_OK) {
                    stop = true;
                }
            } else if (ev.kind == WSIO_EV_CLOSE || ev.kind == WSIO_EV_ERROR) {
                stop = true;
            }
        }
        if (flush_ws(fd, ws) != 0) {
            break;
        }
        if (stop || wsio_closing(ws)) {
            break;
        }
        {
            ssize_t r = recv(fd, buf, sizeof buf, 0);
            if (r <= 0) {
                break;
            }
            if (wsio_feed(ws, buf, (size_t)r) != WSIO_OK) {
                flush_ws(fd, ws);
                break;
            }
        }
    }
    wsio_destroy(ws);
}

int main(int argc, char **argv)
{
    int port = 9001;
    int fd, one = 1;
    struct sockaddr_in addr;

    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "usage: %s [port]\n", argv[0]);
            return 1;
        }
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(fd, 128) < 0) {
        perror("listen");
        return 1;
    }
    fprintf(stderr, "wsio echo server on port %d\n", port);
    for (;;) {
        int c = accept(fd, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            return 1;
        }
        session(c);
        close(c);
    }
}
