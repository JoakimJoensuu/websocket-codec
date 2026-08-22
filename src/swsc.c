#include "swsc.h"
#include "utf8.h"

#include <stdlib.h>
#include <string.h>

#define SWSC_CTRL_MAX 125

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

struct swsc {
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
    uint8_t *reply;
    size_t reply_len;
    size_t reply_cap;
    uint8_t *enc;
    size_t enc_len;
    size_t enc_cap;
    swsc_event *evs;
    size_t ev_n;
    size_t ev_cap;
    uint32_t rng_state;
    parse_st st;
    int opcode;
    int send_opcode;
    unsigned mask_off;
    int msg_opcode;
    swsc_err last_err;
    utf8 utf8;
    utf8 send_utf8;
    uint16_t close_code;
    bool fin;
    bool masked;
    bool client;
    bool close_sent;
    bool close_recv;
    uint8_t mask_key[4];
    uint8_t hdr[14];
    uint8_t ctrl[SWSC_CTRL_MAX];
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

bool swsc_close_code_valid(uint16_t code)
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
    return op == SWSC_OP_CONT || op == SWSC_OP_TEXT || op == SWSC_OP_BIN ||
           op == SWSC_OP_CLOSE || op == SWSC_OP_PING || op == SWSC_OP_PONG;
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

static void in_consume(swsc *ws, size_t n)
{
    if (n >= ws->in_len) {
        ws->in_len = 0;
        return;
    }
    memmove(ws->in, ws->in + n, ws->in_len - n);
    ws->in_len -= n;
}

static void clear_events(swsc *ws)
{
    size_t i;
    for (i = 0; i < ws->ev_n; i++) {
        free((void *)ws->evs[i].data);
        ws->evs[i].data = NULL;
    }
    ws->ev_n = 0;
}

static int ev_push(swsc *ws, swsc_event_kind kind, const uint8_t *data, size_t len,
                   uint16_t close_code)
{
    swsc_event *e;
    uint8_t *copy = NULL;
    if (ws->ev_n == ws->ev_cap) {
        size_t ncap = ws->ev_cap ? ws->ev_cap * 2 : 8;
        swsc_event *nbuf;
        if (ncap <= ws->ev_cap) {
            return -1;
        }
        nbuf = (swsc_event *)realloc(ws->evs, ncap * sizeof *nbuf);
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

static uint32_t next_rng(swsc *ws)
{
    if (ws->rng) {
        return ws->rng(ws->rng_ctx);
    }
    return default_rng(&ws->rng_state);
}

static void fill_mask(swsc *ws, uint8_t key[4])
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

static int encode_frame(swsc *ws, bool fin, int opcode, const uint8_t *data, size_t len,
                        uint8_t **buf, size_t *blen, size_t *bcap, bool append)
{
    uint8_t hdr[14];
    size_t hlen = 2;
    bool mask = ws->client;
    uint8_t key[4];
    size_t total;
    size_t off;

    bug(ws != NULL);
    bug(opcode == SWSC_OP_PONG || !ws->close_sent);
    bug(is_known_opcode(opcode));
    bug(!is_control(opcode) || (fin && len <= SWSC_CTRL_MAX));
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
    off = append ? *blen : 0;
    if (buf_reserve(buf, bcap, off + total) != 0) {
        return SWSC_ERR_NOMEM;
    }
    if (!append) {
        *blen = 0;
        off = 0;
    }
    memcpy(*buf + off, hdr, hlen);
    if (len) {
        memcpy(*buf + off + hlen, data, len);
        if (mask) {
            apply_mask(*buf + off + hlen, len, key);
        }
    }
    *blen = off + total;
    if (opcode == SWSC_OP_CLOSE) {
        ws->close_sent = true;
    }
    return SWSC_OK;
}

static int reply_frame(swsc *ws, bool fin, int opcode, const uint8_t *data, size_t len)
{
    return encode_frame(ws, fin, opcode, data, len, &ws->reply, &ws->reply_len,
                        &ws->reply_cap, true);
}

static swsc_bytes enc_bytes(const swsc *ws, int rc)
{
    swsc_bytes b;
    if (rc != SWSC_OK || ws->enc_len == 0) {
        b.p = NULL;
        b.n = 0;
        return b;
    }
    b.p = ws->enc;
    b.n = ws->enc_len;
    return b;
}

static swsc_bytes encode_app(swsc *ws, bool fin, int opcode, const uint8_t *data, size_t len)
{
    int rc = encode_frame(ws, fin, opcode, data, len, &ws->enc, &ws->enc_len,
                          &ws->enc_cap, false);
    return enc_bytes(ws, rc);
}

static int fail(swsc *ws, swsc_err err, uint16_t code, const char *reason)
{
    uint8_t payload[125];
    size_t rlen = 0;
    size_t plen = 2;

    if (ws->last_err == SWSC_OK) {
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
        encode_frame(ws, true, SWSC_OP_CLOSE, payload, plen, &ws->reply, &ws->reply_len,
                     &ws->reply_cap, true);
    }
    ev_push(ws, SWSC_EV_ERROR, (const uint8_t *)reason, rlen, code);
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

static int finish_message(swsc *ws)
{
    swsc_event_kind kind;
    if (ws->msg_opcode == SWSC_OP_TEXT) {
        if (utf8_finish(&ws->utf8) != 0) {
            return fail(ws, SWSC_ERR_UTF8, SWSC_CLOSE_INVALID_DATA, "invalid utf-8");
        }
        kind = SWSC_EV_TEXT;
    } else {
        kind = SWSC_EV_BIN;
    }
    if (ev_push(ws, kind, ws->msg, ws->msg_len, 0) != 0) {
        return fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom");
    }
    ws->msg_len = 0;
    return SWSC_OK;
}

static int on_control(swsc *ws)
{
    if (ws->opcode == SWSC_OP_PING) {
        if (reply_frame(ws, true, SWSC_OP_PONG, ws->ctrl, ws->ctrl_len) != SWSC_OK) {
            return fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom");
        }
        if (ev_push(ws, SWSC_EV_PING, ws->ctrl, ws->ctrl_len, 0) != 0) {
            return fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom");
        }
        return SWSC_OK;
    }
    if (ws->opcode == SWSC_OP_PONG) {
        if (ev_push(ws, SWSC_EV_PONG, ws->ctrl, ws->ctrl_len, 0) != 0) {
            return fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom");
        }
        return SWSC_OK;
    }

    ws->close_recv = true;
    if (ws->ctrl_len == 0) {
        ws->close_code = SWSC_CLOSE_NO_STATUS;
        if (!ws->close_sent) {
            if (reply_frame(ws, true, SWSC_OP_CLOSE, NULL, 0) != SWSC_OK) {
                return fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom");
            }
        }
        if (ev_push(ws, SWSC_EV_CLOSE, NULL, 0, SWSC_CLOSE_NO_STATUS) != 0) {
            return fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom");
        }
        ws->st = ST_DEAD;
        return SWSC_OK;
    }
    if (ws->ctrl_len == 1) {
        return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "bad close payload");
    }
    {
        uint16_t code = rd16(ws->ctrl);
        const uint8_t *reason = ws->ctrl + 2;
        size_t rlen = ws->ctrl_len - 2;
        utf8 u;
        if (!swsc_close_code_valid(code)) {
            return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "bad close code");
        }
        utf8_init(&u);
        if (utf8_feed(&u, reason, rlen) != 0 || utf8_finish(&u) != 0) {
            return fail(ws, SWSC_ERR_UTF8, SWSC_CLOSE_INVALID_DATA, "bad close reason");
        }
        ws->close_code = code;
        if (!ws->close_sent) {
            if (reply_frame(ws, true, SWSC_OP_CLOSE, ws->ctrl, ws->ctrl_len) != SWSC_OK) {
                return fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom");
            }
        }
        if (ev_push(ws, SWSC_EV_CLOSE, reason, rlen, code) != 0) {
            return fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom");
        }
        ws->st = ST_DEAD;
        return SWSC_OK;
    }
}

static int dispatch_empty_or_start(swsc *ws)
{
    if (is_control(ws->opcode)) {
        ws->ctrl_len = 0;
        return on_control(ws);
    }
    if (ws->opcode != SWSC_OP_CONT) {
        ws->msg_opcode = ws->opcode;
        ws->msg_len = 0;
        utf8_init(&ws->utf8);
    }
    if (ws->fin) {
        int rc = finish_message(ws);
        ws->msg_opcode = 0;
        return rc;
    }
    return SWSC_OK;
}

static int on_frame_header(swsc *ws)
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
        return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "rsv nonzero");
    }
    if (!is_known_opcode(ws->opcode)) {
        return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "bad opcode");
    }
    if (!ws->client) {
        if (!ws->masked) {
            return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "unmasked client frame");
        }
    } else if (ws->masked) {
        return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "masked server frame");
    }

    if (len7 == 126) {
        plen = rd16(ws->hdr + 2);
        off = 4;
        if (plen <= 125) {
            return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "non-minimal length");
        }
    } else if (len7 == 127) {
        plen = rd64(ws->hdr + 2);
        off = 10;
        if (plen & 0x8000000000000000ull) {
            return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "length msb");
        }
        if (plen <= 0xFFFFull) {
            return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "non-minimal length");
        }
    } else {
        plen = (uint64_t)len7;
    }

    if (ws->masked) {
        memcpy(ws->mask_key, ws->hdr + off, 4);
    }

    if (is_control(ws->opcode)) {
        if (!ws->fin) {
            return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "fragmented control");
        }
        if (plen > SWSC_CTRL_MAX) {
            return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "control too long");
        }
    } else {
        if (ws->opcode == SWSC_OP_CONT) {
            if (ws->msg_opcode == 0) {
                return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "orphan continuation");
            }
        } else {
            if (ws->msg_opcode != 0) {
                return fail(ws, SWSC_ERR_PROTOCOL, SWSC_CLOSE_PROTOCOL, "new data while fragmented");
            }
        }
        if (plen > (uint64_t)(size_t)-1 ||
            (uint64_t)ws->msg_len > (uint64_t)(size_t)-1 - plen) {
            return fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom");
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
    if (!is_control(ws->opcode) && ws->opcode != SWSC_OP_CONT) {
        ws->msg_opcode = ws->opcode;
        ws->msg_len = 0;
        utf8_init(&ws->utf8);
    }
    return SWSC_OK;
}

static int on_payload_bytes(swsc *ws, const uint8_t *src, size_t n)
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
                return fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom");
            }
            memcpy(ws->msg + ws->msg_len, tmp, chunk);
            if (ws->msg_opcode == SWSC_OP_TEXT) {
                if (utf8_feed(&ws->utf8, ws->msg + ws->msg_len, chunk) != 0) {
                    return fail(ws, SWSC_ERR_UTF8, SWSC_CLOSE_INVALID_DATA, "invalid utf-8");
                }
            }
            ws->msg_len += chunk;
        }
        off += chunk;
    }
    return SWSC_OK;
}

static int on_payload_done(swsc *ws)
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
    return SWSC_OK;
}

static int parse_in(swsc *ws)
{
    while (ws->in_len > 0 && ws->st != ST_DEAD && ws->last_err == SWSC_OK) {
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
    return ws->last_err == SWSC_OK ? SWSC_OK : (int)ws->last_err;
}

static swsc *create(bool client, uint32_t (*rng)(void *), void *rng_ctx)
{
    swsc *ws = (swsc *)calloc(1, sizeof *ws);
    if (!ws) {
        return NULL;
    }
    ws->client = client;
    ws->rng = rng;
    ws->rng_ctx = rng_ctx;
    ws->rng_state = 0xC0FFEEu ^ (uint32_t)(uintptr_t)ws;
    ws->st = ST_HDR;
    ws->hdr_need = 2;
    ws->close_code = SWSC_CLOSE_NO_STATUS;
    return ws;
}

swsc *swsc_create_client(uint32_t (*rng)(void *ctx), void *rng_ctx)
{
    return create(true, rng, rng_ctx);
}

swsc *swsc_create_server(void)
{
    return create(false, NULL, NULL);
}

void swsc_destroy(swsc *ws)
{
    if (!ws) {
        return;
    }
    clear_events(ws);
    free(ws->evs);
    free(ws->msg);
    free(ws->in);
    free(ws->reply);
    free(ws->enc);
    free(ws);
}

static swsc_result make_result(swsc *ws, swsc_err err)
{
    swsc_result r;
    r.err = err;
    r.evs = ws->ev_n ? ws->evs : NULL;
    r.n = ws->ev_n;
    r.out.p = ws->reply_len ? ws->reply : NULL;
    r.out.n = ws->reply_len;
    return r;
}

swsc_result swsc_feed(swsc *ws, const uint8_t *src, size_t len)
{
    bug(ws != NULL);
    bug(!(len && !src));
    clear_events(ws);
    ws->reply_len = 0;
    if (ws->st == ST_DEAD) {
        return make_result(ws, ws->last_err ? ws->last_err : SWSC_ERR_CLOSED);
    }
    if (len) {
        if (buf_reserve(&ws->in, &ws->in_cap, ws->in_len + len) != 0) {
            return make_result(ws, (swsc_err)fail(ws, SWSC_ERR_NOMEM, SWSC_CLOSE_INTERNAL, "oom"));
        }
        memcpy(ws->in + ws->in_len, src, len);
        ws->in_len += len;
    }
    return make_result(ws, (swsc_err)parse_in(ws));
}

static void require_send_idle(const swsc *ws)
{
    bug(ws->send_opcode == 0);
}

static void check_text(const uint8_t *data, size_t len)
{
    utf8 u;
    utf8_init(&u);
    if (len) {
        bug(utf8_feed(&u, data, len) == 0);
    }
    bug(utf8_finish(&u) == 0);
}

static utf8 check_send_text(utf8 u, const uint8_t *data, size_t len, bool finish)
{
    if (len) {
        bug(utf8_feed(&u, data, len) == 0);
    }
    if (finish) {
        bug(utf8_finish(&u) == 0);
    }
    return u;
}

swsc_bytes swsc_text_frame(swsc *ws, const uint8_t *data, size_t len)
{
    bug(ws != NULL);
    bug(!(len && !data));
    bug(!ws->close_sent);
    require_send_idle(ws);
    check_text(data, len);
    return encode_app(ws, true, SWSC_OP_TEXT, data, len);
}

swsc_bytes swsc_bin_frame(swsc *ws, const uint8_t *data, size_t len)
{
    bug(ws != NULL);
    bug(!(len && !data));
    bug(!ws->close_sent);
    require_send_idle(ws);
    return encode_app(ws, true, SWSC_OP_BIN, data, len);
}

swsc_bytes swsc_ping_frame(swsc *ws, const uint8_t *data, size_t len)
{
    bug(ws != NULL);
    bug(!(len && !data));
    bug(!ws->close_sent);
    return encode_app(ws, true, SWSC_OP_PING, data, len);
}

swsc_bytes swsc_pong_frame(swsc *ws, const uint8_t *data, size_t len)
{
    bug(ws != NULL);
    bug(!(len && !data));
    return encode_app(ws, true, SWSC_OP_PONG, data, len);
}

swsc_bytes swsc_close_frame(swsc *ws, uint16_t code, const uint8_t *reason, size_t reason_len)
{
    uint8_t payload[125];
    size_t plen;
    bug(ws != NULL);
    bug(!ws->close_sent);
    if (code == 0) {
        bug(reason_len == 0);
        return encode_app(ws, true, SWSC_OP_CLOSE, NULL, 0);
    }
    bug(swsc_close_code_valid(code));
    bug(reason_len <= 123);
    wr16(payload, code);
    plen = 2;
    if (reason_len) {
        check_text(reason, reason_len);
        memcpy(payload + 2, reason, reason_len);
        plen = 2 + reason_len;
    }
    return encode_app(ws, true, SWSC_OP_CLOSE, payload, plen);
}

swsc_bytes swsc_fragment(swsc *ws, swsc_opcode opcode, const uint8_t *data, size_t len)
{
    swsc_bytes b;
    utf8 next;
    bool text;
    bug(ws != NULL);
    bug(!(len && !data));
    bug(!ws->close_sent);
    if (opcode == SWSC_OP_CONT) {
        bug(ws->send_opcode == SWSC_OP_TEXT || ws->send_opcode == SWSC_OP_BIN);
    } else {
        bug(opcode == SWSC_OP_TEXT || opcode == SWSC_OP_BIN);
        require_send_idle(ws);
    }
    text = (opcode == SWSC_OP_TEXT) ||
           (opcode == SWSC_OP_CONT && ws->send_opcode == SWSC_OP_TEXT);
    if (text) {
        if (opcode == SWSC_OP_TEXT) {
            utf8_init(&next);
        } else {
            next = ws->send_utf8;
        }
        next = check_send_text(next, data, len, false);
    }
    b = encode_app(ws, false, (int)opcode, data, len);
    if (b.p) {
        if (opcode != SWSC_OP_CONT) {
            ws->send_opcode = (int)opcode;
        }
        if (text) {
            ws->send_utf8 = next;
        }
    }
    return b;
}

swsc_bytes swsc_fragment_end(swsc *ws, const uint8_t *data, size_t len)
{
    swsc_bytes b;
    utf8 next;
    bool text;
    bug(ws != NULL);
    bug(!(len && !data));
    bug(!ws->close_sent);
    bug(ws->send_opcode == SWSC_OP_TEXT || ws->send_opcode == SWSC_OP_BIN);
    text = (ws->send_opcode == SWSC_OP_TEXT);
    if (text) {
        next = check_send_text(ws->send_utf8, data, len, true);
    }
    b = encode_app(ws, true, SWSC_OP_CONT, data, len);
    if (b.p) {
        if (text) {
            ws->send_utf8 = next;
        }
        ws->send_opcode = 0;
    }
    return b;
}

bool swsc_closing(const swsc *ws)
{
    bug(ws != NULL);
    return ws->close_sent || ws->close_recv;
}

bool swsc_closed(const swsc *ws)
{
    bug(ws != NULL);
    return ws->close_sent && ws->close_recv;
}

swsc_err swsc_error(const swsc *ws)
{
    bug(ws != NULL);
    return ws->last_err;
}

uint16_t swsc_last_close(const swsc *ws)
{
    bug(ws != NULL);
    return ws->close_code;
}
