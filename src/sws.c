#include "sws.h"
#include "sws_utf8.h"

#include <stdlib.h>
#include <string.h>

#define SWS_CTRL_MAX 125

static void bug(bool ok)
{
    if (!ok) {
        abort();
    }
}

typedef enum {
    ST_HDR = 0,
    ST_PAYLOAD,
    ST_DEAD
} parse_st;

struct sws {
    uint32_t (*rng)(void *);
    void *rng_ctx;
    size_t hdr_got;
    size_t hdr_need;
    uint64_t payload_len;
    uint64_t payload_got;
    uint8_t *msg;
    size_t msg_len;
    size_t msg_cap;
    size_t ctrl_len;
    uint8_t *in;
    size_t in_len;
    size_t in_cap;
    uint8_t *out;
    size_t out_len;
    size_t out_off;
    size_t out_cap;
    sws_event *evs;
    size_t ev_n;
    size_t ev_cap;
    sws_role role;
    uint32_t rng_state;
    parse_st st;
    int opcode;
    unsigned mask_off;
    int msg_opcode;
    sws_err last_err;
    sws_utf8 utf8;
    uint16_t close_code;
    bool fin;
    bool masked;
    bool close_sent;
    bool close_recv;
    uint8_t mask_key[4];
    uint8_t hdr[14];
    uint8_t ctrl[SWS_CTRL_MAX];
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

bool sws_close_code_valid(uint16_t code)
{
    if (code >= 3000u && code <= 4999u) {
        return true;
    }
    if (code >= 1000u && code <= 1014u && code != 1004u && code != 1005u &&
        code != 1006u) {
        return true;
    }
    return false;
}

static bool is_control(int op)
{
    return (op & 0x8) != 0;
}

static bool is_known_opcode(int op)
{
    return op == SWS_OP_CONT || op == SWS_OP_TEXT || op == SWS_OP_BIN ||
           op == SWS_OP_CLOSE || op == SWS_OP_PING || op == SWS_OP_PONG;
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

static void in_consume(sws *ws, size_t n)
{
    if (n >= ws->in_len) {
        ws->in_len = 0;
        return;
    }
    memmove(ws->in, ws->in + n, ws->in_len - n);
    ws->in_len -= n;
}

static void out_compact(sws *ws)
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

static int out_reserve(sws *ws, size_t extra)
{
    size_t used = ws->out_len - ws->out_off;
    if (ws->out_off > 0 && (ws->out_off > 4096 || ws->out_off > used)) {
        out_compact(ws);
    }
    return buf_reserve(&ws->out, &ws->out_cap, ws->out_len + extra);
}

static void clear_events(sws *ws)
{
    size_t i;
    for (i = 0; i < ws->ev_n; i++) {
        free((void *)ws->evs[i].data);
        ws->evs[i].data = NULL;
    }
    ws->ev_n = 0;
}

static int ev_push(sws *ws, sws_event_kind kind, const uint8_t *data, size_t len,
                   uint16_t close_code)
{
    sws_event *e;
    uint8_t *copy = NULL;
    if (ws->ev_n == ws->ev_cap) {
        size_t ncap = ws->ev_cap ? ws->ev_cap * 2 : 8;
        sws_event *nbuf;
        if (ncap <= ws->ev_cap) {
            return -1;
        }
        nbuf = (sws_event *)realloc(ws->evs, ncap * sizeof *nbuf);
        if (!nbuf) {
            return -1;
        }
        ws->evs = nbuf;
        ws->ev_cap = ncap;
    }
    if (len > 0) {
        bug(data != NULL);
        copy = (uint8_t *)malloc(len);
        if (!copy) {
            return -1;
        }
        memcpy(copy, data, len);
    }
    e = &ws->evs[ws->ev_n++];
    e->kind = kind;
    e->data = copy;
    e->len = len;
    e->close_code = close_code;
    return 0;
}

static uint32_t next_rng(sws *ws)
{
    if (ws->rng) {
        return ws->rng(ws->rng_ctx);
    }
    return default_rng(&ws->rng_state);
}

static void fill_mask(sws *ws, uint8_t key[4])
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

static int encode_frame(sws *ws, bool fin, int opcode, const uint8_t *data, size_t len)
{
    uint8_t hdr[14];
    size_t hlen = 2;
    bool mask = (ws->role == SWS_ROLE_CLIENT);
    uint8_t key[4];
    size_t total;

    bug(ws != NULL);
    bug(!ws->close_sent);
    bug(is_known_opcode(opcode));
    bug(!is_control(opcode) || (fin && len <= SWS_CTRL_MAX));
    bug(!(len && !data));

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
        return SWS_ERR_NOMEM;
    }
    memcpy(ws->out + ws->out_len, hdr, hlen);
    if (len) {
        memcpy(ws->out + ws->out_len + hlen, data, len);
        if (mask) {
            apply_mask(ws->out + ws->out_len + hlen, len, key);
        }
    }
    ws->out_len += total;
    if (opcode == SWS_OP_CLOSE) {
        ws->close_sent = true;
    }
    return SWS_OK;
}

static int fail(sws *ws, sws_err err, uint16_t code, const char *reason)
{
    uint8_t payload[125];
    size_t rlen = 0;
    size_t plen = 2;

    if (ws->last_err == SWS_OK) {
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
        encode_frame(ws, true, SWS_OP_CLOSE, payload, plen);
    }
    ev_push(ws, SWS_EV_ERROR, (const uint8_t *)reason, rlen, code);
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

static int finish_message(sws *ws)
{
    sws_event_kind kind;
    if (ws->msg_opcode == SWS_OP_TEXT) {
        if (sws_utf8_finish(&ws->utf8) != 0) {
            return fail(ws, SWS_ERR_UTF8, SWS_CLOSE_INVALID_DATA, "invalid utf-8");
        }
        kind = SWS_EV_TEXT;
    } else {
        kind = SWS_EV_BIN;
    }
    if (ev_push(ws, kind, ws->msg, ws->msg_len, 0) != 0) {
        return fail(ws, SWS_ERR_NOMEM, SWS_CLOSE_INTERNAL, "oom");
    }
    ws->msg_len = 0;
    return SWS_OK;
}

static int on_control(sws *ws)
{
    if (ws->opcode == SWS_OP_PING) {
        if (ev_push(ws, SWS_EV_PING, ws->ctrl, ws->ctrl_len, 0) != 0) {
            return fail(ws, SWS_ERR_NOMEM, SWS_CLOSE_INTERNAL, "oom");
        }
        return SWS_OK;
    }
    if (ws->opcode == SWS_OP_PONG) {
        if (ev_push(ws, SWS_EV_PONG, ws->ctrl, ws->ctrl_len, 0) != 0) {
            return fail(ws, SWS_ERR_NOMEM, SWS_CLOSE_INTERNAL, "oom");
        }
        return SWS_OK;
    }

    ws->close_recv = true;
    if (ws->ctrl_len == 0) {
        ws->close_code = SWS_CLOSE_NO_STATUS;
        if (ev_push(ws, SWS_EV_CLOSE, NULL, 0, SWS_CLOSE_NO_STATUS) != 0) {
            return fail(ws, SWS_ERR_NOMEM, SWS_CLOSE_INTERNAL, "oom");
        }
        ws->st = ST_DEAD;
        return SWS_OK;
    }
    if (ws->ctrl_len == 1) {
        return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "bad close payload");
    }
    {
        uint16_t code = rd16(ws->ctrl);
        const uint8_t *reason = ws->ctrl + 2;
        size_t rlen = ws->ctrl_len - 2;
        sws_utf8 u;
        if (!sws_close_code_valid(code)) {
            return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "bad close code");
        }
        sws_utf8_init(&u);
        if (sws_utf8_feed(&u, reason, rlen) != 0 || sws_utf8_finish(&u) != 0) {
            return fail(ws, SWS_ERR_UTF8, SWS_CLOSE_INVALID_DATA, "bad close reason");
        }
        ws->close_code = code;
        if (ev_push(ws, SWS_EV_CLOSE, reason, rlen, code) != 0) {
            return fail(ws, SWS_ERR_NOMEM, SWS_CLOSE_INTERNAL, "oom");
        }
        ws->st = ST_DEAD;
        return SWS_OK;
    }
}

static int dispatch_empty_or_start(sws *ws)
{
    if (is_control(ws->opcode)) {
        ws->ctrl_len = 0;
        return on_control(ws);
    }
    if (ws->opcode != SWS_OP_CONT) {
        ws->msg_opcode = ws->opcode;
        ws->msg_len = 0;
        sws_utf8_init(&ws->utf8);
    }
    if (ws->fin) {
        int rc = finish_message(ws);
        ws->msg_opcode = 0;
        return rc;
    }
    return SWS_OK;
}

static int on_frame_header(sws *ws)
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
        return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "rsv nonzero");
    }
    if (!is_known_opcode(ws->opcode)) {
        return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "bad opcode");
    }
    if (ws->role == SWS_ROLE_SERVER) {
        if (!ws->masked) {
            return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "unmasked client frame");
        }
    } else if (ws->masked) {
        return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "masked server frame");
    }

    if (len7 == 126) {
        plen = rd16(ws->hdr + 2);
        off = 4;
        if (plen <= 125) {
            return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "non-minimal length");
        }
    } else if (len7 == 127) {
        plen = rd64(ws->hdr + 2);
        off = 10;
        if (plen & 0x8000000000000000ull) {
            return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "length msb");
        }
        if (plen <= 0xFFFFull) {
            return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "non-minimal length");
        }
    } else {
        plen = (uint64_t)len7;
    }

    if (ws->masked) {
        memcpy(ws->mask_key, ws->hdr + off, 4);
    }

    if (is_control(ws->opcode)) {
        if (!ws->fin) {
            return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "fragmented control");
        }
        if (plen > SWS_CTRL_MAX) {
            return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "control too long");
        }
    } else {
        if (ws->opcode == SWS_OP_CONT) {
            if (ws->msg_opcode == 0) {
                return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "orphan continuation");
            }
        } else {
            if (ws->msg_opcode != 0) {
                return fail(ws, SWS_ERR_PROTOCOL, SWS_CLOSE_PROTOCOL, "new data while fragmented");
            }
        }
        if (plen > (uint64_t)(size_t)-1 ||
            (uint64_t)ws->msg_len > (uint64_t)(size_t)-1 - plen) {
            return fail(ws, SWS_ERR_NOMEM, SWS_CLOSE_INTERNAL, "oom");
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
    if (!is_control(ws->opcode) && ws->opcode != SWS_OP_CONT) {
        ws->msg_opcode = ws->opcode;
        ws->msg_len = 0;
        sws_utf8_init(&ws->utf8);
    }
    return SWS_OK;
}

static int on_payload_bytes(sws *ws, const uint8_t *src, size_t n)
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
                return fail(ws, SWS_ERR_NOMEM, SWS_CLOSE_INTERNAL, "oom");
            }
            memcpy(ws->msg + ws->msg_len, tmp, chunk);
            if (ws->msg_opcode == SWS_OP_TEXT) {
                if (sws_utf8_feed(&ws->utf8, ws->msg + ws->msg_len, chunk) != 0) {
                    return fail(ws, SWS_ERR_UTF8, SWS_CLOSE_INVALID_DATA, "invalid utf-8");
                }
            }
            ws->msg_len += chunk;
        }
        off += chunk;
    }
    return SWS_OK;
}

static int on_payload_done(sws *ws)
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
    return SWS_OK;
}

static int parse_in(sws *ws)
{
    while (ws->in_len > 0 && ws->st != ST_DEAD && ws->last_err == SWS_OK) {
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
    return ws->last_err == SWS_OK ? SWS_OK : (int)ws->last_err;
}

void sws_config_default(sws_config *cfg)
{
    bug(cfg != NULL);
    memset(cfg, 0, sizeof *cfg);
}

sws *sws_create(sws_role role)
{
    sws_config cfg;
    bug(role == SWS_ROLE_CLIENT || role == SWS_ROLE_SERVER);
    sws_config_default(&cfg);
    cfg.role = role;
    return sws_create_cfg(&cfg);
}

sws *sws_create_cfg(const sws_config *cfg)
{
    sws *ws;
    bug(cfg != NULL);
    bug(cfg->role == SWS_ROLE_CLIENT || cfg->role == SWS_ROLE_SERVER);
    ws = (sws *)calloc(1, sizeof *ws);
    if (!ws) {
        return NULL;
    }
    ws->role = cfg->role;
    ws->rng = cfg->rng;
    ws->rng_ctx = cfg->rng_ctx;
    ws->rng_state = 0xC0FFEEu ^ (uint32_t)(uintptr_t)ws;
    ws->st = ST_HDR;
    ws->hdr_need = 2;
    ws->close_code = SWS_CLOSE_NO_STATUS;
    return ws;
}

void sws_destroy(sws *ws)
{
    if (!ws) {
        return;
    }
    clear_events(ws);
    free(ws->evs);
    free(ws->msg);
    free(ws->in);
    free(ws->out);
    free(ws);
}

static sws_result make_result(sws *ws, sws_err err)
{
    sws_result r;
    r.err = err;
    r.evs = ws->ev_n ? ws->evs : NULL;
    r.n = ws->ev_n;
    return r;
}

sws_result sws_feed(sws *ws, const uint8_t *src, size_t len)
{
    bug(ws != NULL);
    bug(!(len && !src));
    clear_events(ws);
    if (ws->st == ST_DEAD) {
        return make_result(ws, ws->last_err ? ws->last_err : SWS_ERR_CLOSED);
    }
    if (len) {
        if (buf_reserve(&ws->in, &ws->in_cap, ws->in_len + len) != 0) {
            return make_result(ws, (sws_err)fail(ws, SWS_ERR_NOMEM, SWS_CLOSE_INTERNAL, "oom"));
        }
        memcpy(ws->in + ws->in_len, src, len);
        ws->in_len += len;
    }
    return make_result(ws, (sws_err)parse_in(ws));
}

size_t sws_pending(const sws *ws)
{
    bug(ws != NULL);
    if (ws->out_len <= ws->out_off) {
        return 0;
    }
    return ws->out_len - ws->out_off;
}

const uint8_t *sws_peek(const sws *ws, size_t *len)
{
    size_t n;
    bug(ws != NULL);
    bug(len != NULL);
    n = sws_pending(ws);
    *len = n;
    if (n == 0) {
        return NULL;
    }
    return ws->out + ws->out_off;
}

void sws_mark_consumed(sws *ws, size_t n)
{
    size_t pend;
    bug(ws != NULL);
    pend = sws_pending(ws);
    bug(n <= pend);
    ws->out_off += n;
    if (ws->out_off >= ws->out_len) {
        ws->out_off = 0;
        ws->out_len = 0;
    }
}

size_t sws_write(sws *ws, uint8_t *dst, size_t cap)
{
    size_t n;
    const uint8_t *p;
    bug(ws != NULL);
    bug(cap == 0 || dst != NULL);
    p = sws_peek(ws, &n);
    if (!p) {
        return 0;
    }
    if (n > cap) {
        n = cap;
    }
    memcpy(dst, p, n);
    sws_mark_consumed(ws, n);
    return n;
}

sws_err sws_queue(sws *ws, sws_opcode opcode, const uint8_t *data, size_t len, bool fin)
{
    bug(ws != NULL);
    bug(!(len && !data));
    bug(!ws->close_sent);
    if (opcode == SWS_OP_TEXT && fin) {
        sws_utf8 u;
        sws_utf8_init(&u);
        if (len) {
            bug(sws_utf8_feed(&u, data, len) == 0);
        }
        bug(sws_utf8_finish(&u) == 0);
    }
    return encode_frame(ws, fin, (int)opcode, data, len);
}

sws_err sws_queue_text(sws *ws, const uint8_t *data, size_t len)
{
    return sws_queue(ws, SWS_OP_TEXT, data, len, true);
}

sws_err sws_queue_bin(sws *ws, const uint8_t *data, size_t len)
{
    return sws_queue(ws, SWS_OP_BIN, data, len, true);
}

sws_err sws_queue_ping(sws *ws, const uint8_t *data, size_t len)
{
    return sws_queue(ws, SWS_OP_PING, data, len, true);
}

sws_err sws_queue_pong(sws *ws, const uint8_t *data, size_t len)
{
    return sws_queue(ws, SWS_OP_PONG, data, len, true);
}

sws_err sws_queue_close(sws *ws, uint16_t code, const uint8_t *reason, size_t reason_len)
{
    uint8_t payload[125];
    size_t plen;
    bug(ws != NULL);
    bug(!ws->close_sent);
    if (code == 0) {
        bug(reason_len == 0);
        return encode_frame(ws, true, SWS_OP_CLOSE, NULL, 0);
    }
    bug(sws_close_code_valid(code));
    bug(reason_len <= 123);
    wr16(payload, code);
    plen = 2;
    if (reason_len) {
        sws_utf8 u;
        sws_utf8_init(&u);
        bug(sws_utf8_feed(&u, reason, reason_len) == 0 && sws_utf8_finish(&u) == 0);
        memcpy(payload + 2, reason, reason_len);
        plen = 2 + reason_len;
    }
    return encode_frame(ws, true, SWS_OP_CLOSE, payload, plen);
}

bool sws_closing(const sws *ws)
{
    bug(ws != NULL);
    return ws->close_sent || ws->close_recv;
}

bool sws_closed(const sws *ws)
{
    bug(ws != NULL);
    return ws->close_sent && ws->close_recv;
}

sws_err sws_error(const sws *ws)
{
    bug(ws != NULL);
    return ws->last_err;
}

uint16_t sws_last_close(const sws *ws)
{
    bug(ws != NULL);
    return ws->close_code;
}
