#include "wsio.h"
#include "wsio_utf8.h"

#include <stdlib.h>
#include <string.h>

#define WSIO_DEFAULT_MAX (16u * 1024u * 1024u)
#define WSIO_EVQ 16
#define WSIO_CTRL_MAX 125

typedef enum { ST_HDR = 0, ST_PAYLOAD, ST_DEAD } parse_st;

typedef struct {
    wsio_event_kind kind;
    uint16_t close_code;
    size_t len;
    uint8_t *data;
} ev_item;

struct wsio {
    wsio_role role;
    size_t max_message_size;
    int auto_pong;
    int auto_close;
    uint32_t (*rng)(void *);
    void *rng_ctx;
    uint32_t rng_state;

    parse_st st;
    uint8_t hdr[14];
    size_t hdr_got;
    size_t hdr_need;

    int fin;
    int opcode;
    int masked;
    uint64_t payload_len;
    uint8_t mask_key[4];
    uint64_t payload_got;
    unsigned mask_off;

    int msg_opcode; /* 0 = none in progress */
    int msg_kind;   /* TEXT or BIN of the assembled message */
    uint8_t *msg;
    size_t msg_len;
    size_t msg_cap;
    int msg_pending;
    wsio_utf8 utf8;

    uint8_t ctrl[WSIO_CTRL_MAX];
    size_t ctrl_len;

    uint8_t *in;
    size_t in_len;
    size_t in_cap;

    uint8_t *out;
    size_t out_len;
    size_t out_off;
    size_t out_cap;

    ev_item evq[WSIO_EVQ];
    int ev_r, ev_w, ev_n;
    uint8_t *held; /* last polled control payload, freed on next mutate */

    int close_sent;
    int close_recv;
    uint16_t close_code;
    wsio_err last_err;
};

static uint32_t default_rng(void *ctx)
{
    uint32_t *s = (uint32_t *)ctx;
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    if (x == 0) {
        x = 0xA5A5A5A5u;
    }
    *s = x;
    return x;
}

int wsio_close_code_valid(uint16_t code)
{
    if (code >= 3000u && code <= 4999u) {
        return 1;
    }
    if (code >= 1000u && code <= 1014u && code != 1004u && code != 1005u &&
        code != 1006u) {
        return 1;
    }
    return 0;
}

static int is_control(int op)
{
    return (op & 0x8) != 0;
}

static int is_known_opcode(int op)
{
    return op == WSIO_OP_CONT || op == WSIO_OP_TEXT || op == WSIO_OP_BIN ||
           op == WSIO_OP_CLOSE || op == WSIO_OP_PING || op == WSIO_OP_PONG;
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static int buf_reserve(uint8_t **p, size_t *cap, size_t need)
{
    uint8_t *nbuf;
    size_t ncap;
    if (need <= *cap) {
        return 0;
    }
    ncap = *cap ? *cap : 256;
    while (ncap < need) {
        if (ncap > ((size_t)-1) / 2) {
            ncap = need;
            break;
        }
        ncap *= 2;
    }
    nbuf = (uint8_t *)realloc(*p, ncap);
    if (!nbuf) {
        return -1;
    }
    *p = nbuf;
    *cap = ncap;
    return 0;
}

static void in_consume(wsio *ws, size_t n)
{
    if (n >= ws->in_len) {
        ws->in_len = 0;
        return;
    }
    memmove(ws->in, ws->in + n, ws->in_len - n);
    ws->in_len -= n;
}

static void out_compact(wsio *ws)
{
    if (ws->out_off == 0) {
        return;
    }
    if (ws->out_off >= ws->out_len) {
        ws->out_len = 0;
        ws->out_off = 0;
        return;
    }
    memmove(ws->out, ws->out + ws->out_off, ws->out_len - ws->out_off);
    ws->out_len -= ws->out_off;
    ws->out_off = 0;
}

static int out_reserve(wsio *ws, size_t extra)
{
    size_t used = ws->out_len - ws->out_off;
    if (ws->out_off > 0 && (ws->out_off > 4096 || ws->out_off > used)) {
        out_compact(ws);
    }
    return buf_reserve(&ws->out, &ws->out_cap, ws->out_len + extra);
}

static void drop_held(wsio *ws)
{
    free(ws->held);
    ws->held = NULL;
}

static int ev_push(wsio *ws, wsio_event_kind kind, const uint8_t *data, size_t len,
                   uint16_t close_code)
{
    ev_item *e;
    if (ws->ev_n >= WSIO_EVQ) {
        return -1;
    }
    e = &ws->evq[ws->ev_w];
    e->kind = kind;
    e->close_code = close_code;
    e->len = len;
    e->data = NULL;
    if (len > 0) {
        e->data = (uint8_t *)malloc(len);
        if (!e->data) {
            return -1;
        }
        memcpy(e->data, data, len);
    }
    ws->ev_w = (ws->ev_w + 1) % WSIO_EVQ;
    ws->ev_n++;
    return 0;
}

static uint32_t next_rng(wsio *ws)
{
    if (ws->rng) {
        return ws->rng(ws->rng_ctx);
    }
    return default_rng(&ws->rng_state);
}

static void fill_mask(wsio *ws, uint8_t key[4])
{
    uint32_t r = next_rng(ws);
    key[0] = (uint8_t)r;
    key[1] = (uint8_t)(r >> 8);
    key[2] = (uint8_t)(r >> 16);
    key[3] = (uint8_t)(r >> 24);
}

static void apply_mask(uint8_t *p, size_t n, const uint8_t key[4])
{
    size_t i;
    for (i = 0; i < n; i++) {
        p[i] = (uint8_t)(p[i] ^ key[i & 3]);
    }
}

static int encode_frame(wsio *ws, int fin, int opcode, const uint8_t *data, size_t len)
{
    uint8_t hdr[14];
    size_t hlen = 2;
    int mask = (ws->role == WSIO_ROLE_CLIENT);
    uint8_t key[4];
    size_t total;

    if (ws->close_sent && opcode != WSIO_OP_CLOSE) {
        return WSIO_ERR_CLOSED;
    }
    if (is_control(opcode) && (!fin || len > WSIO_CTRL_MAX)) {
        return WSIO_ERR_INVAL;
    }

    hdr[0] = (uint8_t)((fin ? 0x80u : 0u) | (opcode & 0x0Fu));
    if (len <= 125) {
        hdr[1] = (uint8_t)len;
    } else if (len <= 0xFFFFu) {
        hdr[1] = 126;
        wr16(hdr + 2, (uint16_t)len);
        hlen = 4;
    } else {
        hdr[1] = 127;
        wr64(hdr + 2, (uint64_t)len);
        hlen = 10;
    }
    if (mask) {
        hdr[1] = (uint8_t)(hdr[1] | 0x80u);
        fill_mask(ws, key);
        memcpy(hdr + hlen, key, 4);
        hlen += 4;
    }

    total = hlen + len;
    if (out_reserve(ws, total) != 0) {
        return WSIO_ERR_NOMEM;
    }
    memcpy(ws->out + ws->out_len, hdr, hlen);
    if (len) {
        memcpy(ws->out + ws->out_len + hlen, data, len);
        if (mask) {
            apply_mask(ws->out + ws->out_len + hlen, len, key);
        }
    }
    ws->out_len += total;
    if (opcode == WSIO_OP_CLOSE) {
        ws->close_sent = 1;
    }
    return WSIO_OK;
}

static int fail(wsio *ws, wsio_err err, uint16_t code, const char *reason)
{
    uint8_t payload[125];
    size_t rlen = 0;
    size_t plen = 2;

    if (ws->last_err == WSIO_OK) {
        ws->last_err = err;
    }
    ws->st = ST_DEAD;
    ws->close_code = code;
    ws->in_len = 0;

    if (!ws->close_sent) {
        wr16(payload, code);
        if (reason) {
            rlen = strlen(reason);
            if (rlen > 123) {
                rlen = 123;
            }
            memcpy(payload + 2, reason, rlen);
            plen = 2 + rlen;
        }
        encode_frame(ws, 1, WSIO_OP_CLOSE, payload, plen);
    }
    ev_push(ws, WSIO_EV_ERROR, (const uint8_t *)reason, rlen, code);
    return err;
}

static int header_len(uint8_t b1)
{
    int n = 2;
    int len7 = b1 & 0x7F;
    if (len7 == 126) {
        n += 2;
    } else if (len7 == 127) {
        n += 8;
    }
    if (b1 & 0x80) {
        n += 4;
    }
    return n;
}

static int finish_message(wsio *ws)
{
    if (ws->msg_opcode == WSIO_OP_TEXT) {
        if (wsio_utf8_finish(&ws->utf8) != 0) {
            return fail(ws, WSIO_ERR_UTF8, WSIO_CLOSE_INVALID_DATA, "invalid utf-8");
        }
    }
    ws->msg_kind = ws->msg_opcode;
    ws->msg_pending = 1;
    return WSIO_OK;
}

static int on_control(wsio *ws)
{
    if (ws->opcode == WSIO_OP_PING) {
        if (ws->auto_pong && !ws->close_sent) {
            int rc = encode_frame(ws, 1, WSIO_OP_PONG, ws->ctrl, ws->ctrl_len);
            if (rc != WSIO_OK) {
                return fail(ws, (wsio_err)rc, WSIO_CLOSE_INTERNAL, "encode");
            }
        }
        if (ev_push(ws, WSIO_EV_PING, ws->ctrl, ws->ctrl_len, 0) != 0) {
            return fail(ws, WSIO_ERR_NOMEM, WSIO_CLOSE_INTERNAL, "oom");
        }
        return WSIO_OK;
    }
    if (ws->opcode == WSIO_OP_PONG) {
        if (ev_push(ws, WSIO_EV_PONG, ws->ctrl, ws->ctrl_len, 0) != 0) {
            return fail(ws, WSIO_ERR_NOMEM, WSIO_CLOSE_INTERNAL, "oom");
        }
        return WSIO_OK;
    }

    ws->close_recv = 1;
    if (ws->ctrl_len == 0) {
        ws->close_code = WSIO_CLOSE_NO_STATUS;
        if (ws->auto_close && !ws->close_sent) {
            encode_frame(ws, 1, WSIO_OP_CLOSE, NULL, 0);
        }
        if (ev_push(ws, WSIO_EV_CLOSE, NULL, 0, WSIO_CLOSE_NO_STATUS) != 0) {
            return fail(ws, WSIO_ERR_NOMEM, WSIO_CLOSE_INTERNAL, "oom");
        }
        ws->st = ST_DEAD;
        return WSIO_OK;
    }
    if (ws->ctrl_len == 1) {
        return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "bad close payload");
    }
    {
        uint16_t code = rd16(ws->ctrl);
        const uint8_t *reason = ws->ctrl + 2;
        size_t rlen = ws->ctrl_len - 2;
        wsio_utf8 u;
        if (!wsio_close_code_valid(code)) {
            return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "bad close code");
        }
        wsio_utf8_init(&u);
        if (wsio_utf8_feed(&u, reason, rlen) != 0 || wsio_utf8_finish(&u) != 0) {
            return fail(ws, WSIO_ERR_UTF8, WSIO_CLOSE_INVALID_DATA, "bad close reason");
        }
        ws->close_code = code;
        if (ws->auto_close && !ws->close_sent) {
            encode_frame(ws, 1, WSIO_OP_CLOSE, ws->ctrl, ws->ctrl_len);
        }
        if (ev_push(ws, WSIO_EV_CLOSE, reason, rlen, code) != 0) {
            return fail(ws, WSIO_ERR_NOMEM, WSIO_CLOSE_INTERNAL, "oom");
        }
        ws->st = ST_DEAD;
        return WSIO_OK;
    }
}

static int dispatch_empty_or_start(wsio *ws)
{
    if (is_control(ws->opcode)) {
        ws->ctrl_len = 0;
        return on_control(ws);
    }
    if (ws->opcode != WSIO_OP_CONT) {
        ws->msg_opcode = ws->opcode;
        ws->msg_len = 0;
        wsio_utf8_init(&ws->utf8);
    }
    if (ws->fin) {
        int rc = finish_message(ws);
        ws->msg_opcode = 0;
        return rc;
    }
    return WSIO_OK;
}

/* Returns 1 if the caller should leave the header bytes unconsumed. */
static int on_frame_header(wsio *ws)
{
    uint8_t b0 = ws->hdr[0];
    uint8_t b1 = ws->hdr[1];
    uint64_t plen;
    int len7;
    size_t off = 2;

    ws->fin = (b0 & 0x80) != 0;
    ws->opcode = b0 & 0x0F;
    ws->masked = (b1 & 0x80) != 0;
    len7 = b1 & 0x7F;

    if ((b0 & 0x70) != 0) {
        return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "rsv nonzero");
    }
    if (!is_known_opcode(ws->opcode)) {
        return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "bad opcode");
    }
    if (ws->role == WSIO_ROLE_SERVER) {
        if (!ws->masked) {
            return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "unmasked client frame");
        }
    } else if (ws->masked) {
        return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "masked server frame");
    }

    if (len7 == 126) {
        plen = rd16(ws->hdr + 2);
        off = 4;
        if (plen <= 125) {
            return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "non-minimal length");
        }
    } else if (len7 == 127) {
        plen = rd64(ws->hdr + 2);
        off = 10;
        if (plen & 0x8000000000000000ull) {
            return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "length msb");
        }
        if (plen <= 0xFFFFull) {
            return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "non-minimal length");
        }
    } else {
        plen = (uint64_t)len7;
    }

    if (ws->masked) {
        memcpy(ws->mask_key, ws->hdr + off, 4);
    }

    if (is_control(ws->opcode)) {
        if (!ws->fin) {
            return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "fragmented control");
        }
        if (plen > WSIO_CTRL_MAX) {
            return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "control too long");
        }
    } else {
        if (ws->opcode == WSIO_OP_CONT) {
            if (ws->msg_opcode == 0) {
                return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "orphan continuation");
            }
        } else {
            if (ws->msg_opcode != 0) {
                return fail(ws, WSIO_ERR_PROTOCOL, WSIO_CLOSE_PROTOCOL, "new data while fragmented");
            }
            if (ws->msg_pending) {
                return 1;
            }
        }
        if (plen > (uint64_t)ws->max_message_size ||
            (uint64_t)ws->msg_len + plen > (uint64_t)ws->max_message_size) {
            return fail(ws, WSIO_ERR_TOO_BIG, WSIO_CLOSE_TOO_BIG, "message too big");
        }
    }

    ws->payload_len = plen;
    ws->payload_got = 0;
    ws->mask_off = 0;
    ws->ctrl_len = 0;

    if (plen == 0) {
        ws->st = ST_HDR;
        ws->hdr_got = 0;
        ws->hdr_need = 2;
        return dispatch_empty_or_start(ws);
    }

    ws->st = ST_PAYLOAD;
    if (!is_control(ws->opcode) && ws->opcode != WSIO_OP_CONT) {
        ws->msg_opcode = ws->opcode;
        ws->msg_len = 0;
        wsio_utf8_init(&ws->utf8);
    }
    return WSIO_OK;
}

static int on_payload_bytes(wsio *ws, const uint8_t *src, size_t n)
{
    uint8_t tmp[512];
    size_t off = 0;

    while (off < n) {
        size_t i;
        size_t chunk = n - off;
        if (chunk > sizeof tmp) {
            chunk = sizeof tmp;
        }
        memcpy(tmp, src + off, chunk);
        if (ws->masked) {
            for (i = 0; i < chunk; i++) {
                tmp[i] = (uint8_t)(tmp[i] ^ ws->mask_key[(ws->mask_off + i) & 3]);
            }
        }
        ws->mask_off = (ws->mask_off + (unsigned)chunk) & 3;

        if (is_control(ws->opcode)) {
            memcpy(ws->ctrl + ws->ctrl_len, tmp, chunk);
            ws->ctrl_len += chunk;
        } else {
            if (buf_reserve(&ws->msg, &ws->msg_cap, ws->msg_len + chunk) != 0) {
                return fail(ws, WSIO_ERR_NOMEM, WSIO_CLOSE_INTERNAL, "oom");
            }
            memcpy(ws->msg + ws->msg_len, tmp, chunk);
            if (ws->msg_opcode == WSIO_OP_TEXT) {
                if (wsio_utf8_feed(&ws->utf8, ws->msg + ws->msg_len, chunk) != 0) {
                    return fail(ws, WSIO_ERR_UTF8, WSIO_CLOSE_INVALID_DATA, "invalid utf-8");
                }
            }
            ws->msg_len += chunk;
        }
        off += chunk;
    }
    return WSIO_OK;
}

static int on_payload_done(wsio *ws)
{
    ws->st = ST_HDR;
    ws->hdr_got = 0;
    ws->hdr_need = 2;
    if (is_control(ws->opcode)) {
        return on_control(ws);
    }
    if (ws->fin) {
        int rc = finish_message(ws);
        ws->msg_opcode = 0;
        return rc;
    }
    return WSIO_OK;
}

static int parse_in(wsio *ws)
{
    while (ws->in_len > 0 && ws->st != ST_DEAD && ws->last_err == WSIO_OK) {
        if (ws->st == ST_HDR) {
            size_t need, take;
            int rc;
            if (ws->hdr_got < 2) {
                ws->hdr_need = 2;
            }
            need = ws->hdr_need;
            take = need - ws->hdr_got;
            if (take > ws->in_len) {
                take = ws->in_len;
            }
            memcpy(ws->hdr + ws->hdr_got, ws->in, take);
            ws->hdr_got += take;
            in_consume(ws, take);
            if (ws->hdr_got >= 2) {
                ws->hdr_need = (size_t)header_len(ws->hdr[1]);
            }
            if (ws->hdr_got < ws->hdr_need) {
                if (ws->in_len == 0) {
                    break;
                }
                continue;
            }
            rc = on_frame_header(ws);
            if (rc == 1) {
                /* Restore header bytes into `in` so a later poll can retry. */
                size_t h = ws->hdr_got;
                if (buf_reserve(&ws->in, &ws->in_cap, ws->in_len + h) != 0) {
                    return fail(ws, WSIO_ERR_NOMEM, WSIO_CLOSE_INTERNAL, "oom");
                }
                memmove(ws->in + h, ws->in, ws->in_len);
                memcpy(ws->in, ws->hdr, h);
                ws->in_len += h;
                ws->hdr_got = 0;
                ws->hdr_need = 2;
                break;
            }
            if (rc < 0) {
                return rc;
            }
            continue;
        }

        if (ws->st == ST_PAYLOAD) {
            uint64_t left = ws->payload_len - ws->payload_got;
            size_t take = ws->in_len;
            int rc;
            if ((uint64_t)take > left) {
                take = (size_t)left;
            }
            rc = on_payload_bytes(ws, ws->in, take);
            if (rc < 0) {
                return rc;
            }
            in_consume(ws, take);
            ws->payload_got += take;
            if (ws->payload_got >= ws->payload_len) {
                rc = on_payload_done(ws);
                if (rc < 0) {
                    return rc;
                }
            }
            continue;
        }
        break;
    }
    return ws->last_err == WSIO_OK ? WSIO_OK : (int)ws->last_err;
}

wsio *wsio_create(wsio_role role)
{
    wsio_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.role = role;
    cfg.auto_pong = 1;
    cfg.auto_close = 1;
    return wsio_create_cfg(&cfg);
}

wsio *wsio_create_cfg(const wsio_config *cfg)
{
    wsio *ws;
    if (!cfg) {
        return NULL;
    }
    ws = (wsio *)calloc(1, sizeof *ws);
    if (!ws) {
        return NULL;
    }
    ws->role = cfg->role;
    ws->max_message_size = cfg->max_message_size ? cfg->max_message_size : WSIO_DEFAULT_MAX;
    ws->auto_pong = cfg->auto_pong;
    ws->auto_close = cfg->auto_close;
    ws->rng = cfg->rng;
    ws->rng_ctx = cfg->rng_ctx;
    ws->rng_state = 0xC0FFEEu ^ (uint32_t)(uintptr_t)ws;
    ws->st = ST_HDR;
    ws->hdr_need = 2;
    ws->close_code = WSIO_CLOSE_NO_STATUS;
    return ws;
}

void wsio_destroy(wsio *ws)
{
    int i;
    if (!ws) {
        return;
    }
    free(ws->msg);
    free(ws->in);
    free(ws->out);
    free(ws->held);
    for (i = 0; i < WSIO_EVQ; i++) {
        free(ws->evq[i].data);
    }
    free(ws);
}

int wsio_feed(wsio *ws, const uint8_t *src, size_t len)
{
    if (!ws || (len && !src)) {
        return WSIO_ERR_INVAL;
    }
    drop_held(ws);
    if (ws->st == ST_DEAD) {
        return ws->last_err ? (int)ws->last_err : WSIO_ERR_CLOSED;
    }
    if (len) {
        if (buf_reserve(&ws->in, &ws->in_cap, ws->in_len + len) != 0) {
            return fail(ws, WSIO_ERR_NOMEM, WSIO_CLOSE_INTERNAL, "oom");
        }
        memcpy(ws->in + ws->in_len, src, len);
        ws->in_len += len;
    }
    return parse_in(ws);
}

size_t wsio_pending(const wsio *ws)
{
    if (!ws || ws->out_len <= ws->out_off) {
        return 0;
    }
    return ws->out_len - ws->out_off;
}

const uint8_t *wsio_peek(const wsio *ws, size_t *len)
{
    size_t n = wsio_pending(ws);
    if (len) {
        *len = n;
    }
    if (!ws || n == 0) {
        return NULL;
    }
    return ws->out + ws->out_off;
}

void wsio_consume(wsio *ws, size_t n)
{
    size_t pend;
    if (!ws) {
        return;
    }
    pend = wsio_pending(ws);
    if (n > pend) {
        n = pend;
    }
    ws->out_off += n;
    if (ws->out_off >= ws->out_len) {
        ws->out_off = 0;
        ws->out_len = 0;
    }
}

size_t wsio_write(wsio *ws, uint8_t *dst, size_t cap)
{
    size_t n;
    const uint8_t *p = wsio_peek(ws, &n);
    if (!p || !dst) {
        return 0;
    }
    if (n > cap) {
        n = cap;
    }
    memcpy(dst, p, n);
    wsio_consume(ws, n);
    return n;
}

static wsio_event pop_control(wsio *ws)
{
    wsio_event ev;
    ev_item *e = &ws->evq[ws->ev_r];
    memset(&ev, 0, sizeof ev);
    ev.kind = e->kind;
    ev.close_code = e->close_code;
    ev.len = e->len;
    ev.data = e->data;
    ws->held = e->data;
    e->data = NULL;
    ws->ev_r = (ws->ev_r + 1) % WSIO_EVQ;
    ws->ev_n--;
    return ev;
}

static wsio_event pop_message(wsio *ws)
{
    wsio_event ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = (ws->msg_kind == WSIO_OP_BIN) ? WSIO_EV_BIN : WSIO_EV_TEXT;
    ev.data = ws->msg;
    ev.len = ws->msg_len;
    ws->msg_pending = 0;
    return ev;
}

wsio_event wsio_poll(wsio *ws)
{
    wsio_event ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = WSIO_EV_NONE;
    if (!ws) {
        return ev;
    }
    drop_held(ws);

    if (ws->ev_n > 0) {
        return pop_control(ws);
    }
    if (ws->msg_pending) {
        return pop_message(ws);
    }
    /* Safe to reuse msg[]: the previous message was already polled. */
    parse_in(ws);
    if (ws->ev_n > 0) {
        return pop_control(ws);
    }
    if (ws->msg_pending) {
        return pop_message(ws);
    }
    return ev;
}

int wsio_send(wsio *ws, wsio_opcode opcode, const uint8_t *data, size_t len, int fin)
{
    if (!ws) {
        return WSIO_ERR_INVAL;
    }
    if (len && !data) {
        return WSIO_ERR_INVAL;
    }
    if (ws->close_sent) {
        return WSIO_ERR_CLOSED;
    }
    if (opcode == WSIO_OP_TEXT && fin) {
        wsio_utf8 u;
        wsio_utf8_init(&u);
        if ((len && wsio_utf8_feed(&u, data, len) != 0) || wsio_utf8_finish(&u) != 0) {
            return WSIO_ERR_UTF8;
        }
    }
    drop_held(ws);
    return encode_frame(ws, fin ? 1 : 0, (int)opcode, data, len);
}

int wsio_send_text(wsio *ws, const uint8_t *data, size_t len)
{
    return wsio_send(ws, WSIO_OP_TEXT, data, len, 1);
}

int wsio_send_bin(wsio *ws, const uint8_t *data, size_t len)
{
    return wsio_send(ws, WSIO_OP_BIN, data, len, 1);
}

int wsio_send_ping(wsio *ws, const uint8_t *data, size_t len)
{
    return wsio_send(ws, WSIO_OP_PING, data, len, 1);
}

int wsio_send_pong(wsio *ws, const uint8_t *data, size_t len)
{
    return wsio_send(ws, WSIO_OP_PONG, data, len, 1);
}

int wsio_send_close(wsio *ws, uint16_t code, const uint8_t *reason, size_t reason_len)
{
    uint8_t payload[125];
    size_t plen;
    if (!ws) {
        return WSIO_ERR_INVAL;
    }
    if (ws->close_sent) {
        return WSIO_ERR_CLOSED;
    }
    drop_held(ws);
    if (code == 0) {
        if (reason_len) {
            return WSIO_ERR_INVAL;
        }
        return encode_frame(ws, 1, WSIO_OP_CLOSE, NULL, 0);
    }
    if (!wsio_close_code_valid(code)) {
        return WSIO_ERR_INVAL;
    }
    if (reason_len > 123) {
        return WSIO_ERR_INVAL;
    }
    wr16(payload, code);
    plen = 2;
    if (reason_len) {
        wsio_utf8 u;
        wsio_utf8_init(&u);
        if (wsio_utf8_feed(&u, reason, reason_len) != 0 || wsio_utf8_finish(&u) != 0) {
            return WSIO_ERR_UTF8;
        }
        memcpy(payload + 2, reason, reason_len);
        plen = 2 + reason_len;
    }
    return encode_frame(ws, 1, WSIO_OP_CLOSE, payload, plen);
}

int wsio_closing(const wsio *ws)
{
    return ws && (ws->close_sent || ws->close_recv);
}

int wsio_closed(const wsio *ws)
{
    return ws && ws->close_sent && ws->close_recv;
}

wsio_err wsio_error(const wsio *ws)
{
    return ws ? ws->last_err : WSIO_ERR_INVAL;
}

uint16_t wsio_last_close(const wsio *ws)
{
    return ws ? ws->close_code : WSIO_CLOSE_ABNORMAL;
}
