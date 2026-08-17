#include "wsio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;

#define EXPECT(cond)                                                        \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_fail = 1;                                                     \
        }                                                                   \
    } while (0)

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

static void apply_mask(uint8_t *p, size_t n, const uint8_t key[4])
{
    size_t i;
    for (i = 0; i < n; i++) {
        p[i] ^= key[i & 3];
    }
}

static size_t build_frame(uint8_t *out, bool fin, int opcode, bool mask, const uint8_t *payload,
                          size_t len, const uint8_t key[4])
{
    size_t h = 2;
    out[0] = (uint8_t)((fin ? 0x80u : 0u) | (opcode & 0x0Fu));
    if (len <= 125) {
        out[1] = (uint8_t)len;
    } else if (len <= 0xFFFFu) {
        out[1] = 126;
        wr16(out + 2, (uint16_t)len);
        h = 4;
    } else {
        out[1] = 127;
        wr64(out + 2, (uint64_t)len);
        h = 10;
    }
    if (mask) {
        out[1] |= 0x80u;
        memcpy(out + h, key, 4);
        h += 4;
    }
    if (len) {
        memcpy(out + h, payload, len);
        if (mask) {
            apply_mask(out + h, len, key);
        }
    }
    return h + len;
}

static const uint8_t KEY[4] = {0x01, 0x02, 0x03, 0x04};

static int feed(wsio *ws, const uint8_t *src, size_t len, const wsio_event **evs, size_t *n)
{
    const wsio_event *e = NULL;
    size_t ne = 0;
    return wsio_feed(ws, src, len, evs ? evs : &e, n ? n : &ne);
}

static int pump_out(wsio *from, wsio *to, const wsio_event **evs, size_t *n)
{
    size_t nbytes;
    const uint8_t *p = wsio_peek(from, &nbytes);
    int rc = WSIO_OK;
    if (nbytes) {
        rc = feed(to, p, nbytes, evs, n);
        EXPECT(rc == WSIO_OK || wsio_error(to) != WSIO_OK);
        wsio_consume(from, nbytes);
    } else if (evs && n) {
        *evs = NULL;
        *n = 0;
    }
    return rc;
}

static void test_64k_binary(void)
{
    const size_t n = 65536;
    uint8_t *payload = (uint8_t *)malloc(n);
    uint8_t *frame = (uint8_t *)malloc(n + 32);
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    size_t flen;
    const wsio_event *evs;
    size_t nev;
    size_t i;

    EXPECT(payload && frame && srv);
    for (i = 0; i < n; i++) {
        payload[i] = (uint8_t)(i * 3);
    }
    flen = build_frame(frame, 1, WSIO_OP_BIN, 1, payload, n, KEY);
    EXPECT(feed(srv, frame, flen, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_BIN);
    EXPECT(evs[0].len == n);
    EXPECT(memcmp(evs[0].data, payload, n) == 0);
    free(payload);
    free(frame);
    wsio_destroy(srv);
}

static void test_incomplete_utf8_at_fin(void)
{
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    uint8_t frame[32];
    const uint8_t part[] = {0xC3}; /* start of 2-byte seq, then FIN */
    size_t n = build_frame(frame, 1, WSIO_OP_TEXT, 1, part, 1, KEY);
    EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_UTF8);
    EXPECT(wsio_last_close(srv) == WSIO_CLOSE_INVALID_DATA);
    wsio_destroy(srv);
}

static void test_roundtrip_text(void)
{
    wsio *cli = wsio_create(WSIO_ROLE_CLIENT);
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    const char *msg = "hello";
    const wsio_event *evs;
    size_t nev;

    EXPECT(cli && srv);
    EXPECT(wsio_send_text(cli, (const uint8_t *)msg, 5) == WSIO_OK);
    pump_out(cli, srv, &evs, &nev);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_TEXT);
    EXPECT(evs[0].len == 5);
    EXPECT(memcmp(evs[0].data, msg, 5) == 0);

    EXPECT(wsio_send_text(srv, evs[0].data, evs[0].len) == WSIO_OK);
    pump_out(srv, cli, &evs, &nev);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_TEXT);
    EXPECT(evs[0].len == 5);
    EXPECT(memcmp(evs[0].data, "hello", 5) == 0);

    wsio_destroy(cli);
    wsio_destroy(srv);
}

static void test_binary_and_empty(void)
{
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    uint8_t frame[64];
    uint8_t payload[3] = {0, 1, 255};
    size_t n;
    const wsio_event *evs;
    size_t nev;

    n = build_frame(frame, 1, WSIO_OP_BIN, 1, payload, 3, KEY);
    EXPECT(feed(srv, frame, n, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_BIN);
    EXPECT(evs[0].len == 3);
    EXPECT(memcmp(evs[0].data, payload, 3) == 0);

    n = build_frame(frame, 1, WSIO_OP_TEXT, 1, NULL, 0, KEY);
    EXPECT(feed(srv, frame, n, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_TEXT);
    EXPECT(evs[0].len == 0);

    wsio_destroy(srv);
}

static void test_extended_lengths(void)
{
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    uint8_t *payload = (uint8_t *)malloc(200);
    uint8_t *frame = (uint8_t *)malloc(200 + 16);
    size_t n;
    const wsio_event *evs;
    size_t nev;
    int i;

    EXPECT(payload && frame);
    for (i = 0; i < 200; i++) {
        payload[i] = (uint8_t)i;
    }
    n = build_frame(frame, 1, WSIO_OP_BIN, 1, payload, 200, KEY);
    EXPECT(n > 200);
    EXPECT(feed(srv, frame, n, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_BIN);
    EXPECT(evs[0].len == 200);
    EXPECT(memcmp(evs[0].data, payload, 200) == 0);

    free(payload);
    free(frame);
    wsio_destroy(srv);
}

static void test_fragmentation_and_ping(void)
{
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    uint8_t frame[128];
    size_t n;
    const wsio_event *evs;
    size_t nev;
    const uint8_t ping[] = {'p', 'i'};
    const uint8_t a[] = {'H', 'e'};
    const uint8_t b[] = {'l', 'l', 'o'};

    n = build_frame(frame, 0, WSIO_OP_TEXT, 1, a, 2, KEY);
    EXPECT(feed(srv, frame, n, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 0);

    n = build_frame(frame, 1, WSIO_OP_PING, 1, ping, 2, KEY);
    EXPECT(feed(srv, frame, n, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_PING);
    EXPECT(evs[0].len == 2 && evs[0].data[0] == 'p');
    EXPECT(wsio_pending(srv) > 0); /* auto pong */

    n = build_frame(frame, 1, WSIO_OP_CONT, 1, b, 3, KEY);
    EXPECT(feed(srv, frame, n, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_TEXT);
    EXPECT(evs[0].len == 5);
    EXPECT(memcmp(evs[0].data, "Hello", 5) == 0);

    wsio_destroy(srv);
}

static void test_utf8_split_and_invalid(void)
{
    wsio *srv;
    uint8_t frame[64];
    size_t n;
    const wsio_event *evs;
    size_t nev;
    /* U+00E9 is C3 A9; split across fragments */
    const uint8_t f0[] = {0xC3};
    const uint8_t f1[] = {0xA9};

    srv = wsio_create(WSIO_ROLE_SERVER);
    n = build_frame(frame, 0, WSIO_OP_TEXT, 1, f0, 1, KEY);
    EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_OK);
    n = build_frame(frame, 1, WSIO_OP_CONT, 1, f1, 1, KEY);
    EXPECT(feed(srv, frame, n, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_TEXT);
    EXPECT(evs[0].len == 2);
    wsio_destroy(srv);

    srv = wsio_create(WSIO_ROLE_SERVER);
    {
        const uint8_t bad[] = {0x80}; /* continuation as start */
        n = build_frame(frame, 1, WSIO_OP_TEXT, 1, bad, 1, KEY);
        EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_UTF8);
        EXPECT(wsio_last_close(srv) == WSIO_CLOSE_INVALID_DATA);
        EXPECT(wsio_pending(srv) > 0);
    }
    wsio_destroy(srv);

    srv = wsio_create(WSIO_ROLE_SERVER);
    {
        const uint8_t overlong[] = {0xC0, 0x80};
        n = build_frame(frame, 1, WSIO_OP_TEXT, 1, overlong, 2, KEY);
        EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_UTF8);
    }
    wsio_destroy(srv);

    srv = wsio_create(WSIO_ROLE_SERVER);
    {
        /* invalid in first fragment must fail before FIN */
        const uint8_t bad[] = {0xFF};
        n = build_frame(frame, 0, WSIO_OP_TEXT, 1, bad, 1, KEY);
        EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_UTF8);
    }
    wsio_destroy(srv);
}

static void test_protocol_errors(void)
{
    wsio *srv;
    uint8_t frame[64];
    size_t n;
    const uint8_t hi[] = {'x'};

    /* unmasked to server */
    srv = wsio_create(WSIO_ROLE_SERVER);
    n = build_frame(frame, 1, WSIO_OP_TEXT, 0, hi, 1, KEY);
    EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_PROTOCOL);
    EXPECT(wsio_last_close(srv) == WSIO_CLOSE_PROTOCOL);
    wsio_destroy(srv);

    /* RSV bit */
    srv = wsio_create(WSIO_ROLE_SERVER);
    n = build_frame(frame, 1, WSIO_OP_TEXT, 1, hi, 1, KEY);
    frame[0] |= 0x40;
    EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_PROTOCOL);
    wsio_destroy(srv);

    /* reserved opcode */
    srv = wsio_create(WSIO_ROLE_SERVER);
    n = build_frame(frame, 1, 0x3, 1, hi, 1, KEY);
    EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_PROTOCOL);
    wsio_destroy(srv);

    /* fragmented ping */
    srv = wsio_create(WSIO_ROLE_SERVER);
    n = build_frame(frame, 0, WSIO_OP_PING, 1, hi, 1, KEY);
    EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_PROTOCOL);
    wsio_destroy(srv);

    /* orphan continuation */
    srv = wsio_create(WSIO_ROLE_SERVER);
    n = build_frame(frame, 1, WSIO_OP_CONT, 1, hi, 1, KEY);
    EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_PROTOCOL);
    wsio_destroy(srv);

    /* masked to client */
    {
        wsio *cli = wsio_create(WSIO_ROLE_CLIENT);
        n = build_frame(frame, 1, WSIO_OP_TEXT, 1, hi, 1, KEY);
        EXPECT(feed(cli, frame, n, NULL, NULL) == WSIO_ERR_PROTOCOL);
        wsio_destroy(cli);
    }
}

static void test_close(void)
{
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    uint8_t frame[64];
    uint8_t payload[8];
    size_t n;
    const wsio_event *evs;
    size_t nev;

    wr16(payload, 1000);
    memcpy(payload + 2, "bye", 3);
    n = build_frame(frame, 1, WSIO_OP_CLOSE, 1, payload, 5, KEY);
    EXPECT(feed(srv, frame, n, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_CLOSE);
    EXPECT(evs[0].close_code == 1000);
    EXPECT(evs[0].len == 3);
    EXPECT(wsio_closed(srv));
    EXPECT(wsio_pending(srv) > 0); /* auto close reply */
    wsio_destroy(srv);

    srv = wsio_create(WSIO_ROLE_SERVER);
    n = build_frame(frame, 1, WSIO_OP_CLOSE, 1, NULL, 0, KEY);
    EXPECT(feed(srv, frame, n, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_CLOSE);
    EXPECT(evs[0].close_code == WSIO_CLOSE_NO_STATUS);
    wsio_destroy(srv);

    srv = wsio_create(WSIO_ROLE_SERVER);
    wr16(payload, 1005); /* reserved, must not appear on the wire */
    n = build_frame(frame, 1, WSIO_OP_CLOSE, 1, payload, 2, KEY);
    EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_PROTOCOL);
    EXPECT(wsio_last_close(srv) == WSIO_CLOSE_PROTOCOL);
    wsio_destroy(srv);

    srv = wsio_create(WSIO_ROLE_SERVER);
    payload[0] = 0x00; /* 1-byte close payload */
    n = build_frame(frame, 1, WSIO_OP_CLOSE, 1, payload, 1, KEY);
    EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_PROTOCOL);
    wsio_destroy(srv);
}

static void test_byte_at_a_time(void)
{
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    uint8_t frame[64];
    size_t n, i;
    const wsio_event *evs = NULL;
    size_t nev = 0;
    const uint8_t msg[] = "abc";

    n = build_frame(frame, 1, WSIO_OP_TEXT, 1, msg, 3, KEY);
    for (i = 0; i < n; i++) {
        int rc = feed(srv, frame + i, 1, &evs, &nev);
        EXPECT(rc == WSIO_OK);
    }
    EXPECT(nev == 1);
    EXPECT(evs[0].kind == WSIO_EV_TEXT);
    EXPECT(evs[0].len == 3);
    EXPECT(memcmp(evs[0].data, "abc", 3) == 0);
    wsio_destroy(srv);
}

static void test_too_big(void)
{
    wsio_config cfg;
    wsio *srv;
    uint8_t frame[32];
    uint8_t payload[8] = {0};
    size_t n;

    memset(&cfg, 0, sizeof cfg);
    cfg.role = WSIO_ROLE_SERVER;
    cfg.max_message_size = 4;
    cfg.auto_pong = true;
    cfg.auto_close = true;
    srv = wsio_create_cfg(&cfg);
    n = build_frame(frame, 1, WSIO_OP_BIN, 1, payload, 8, KEY);
    EXPECT(feed(srv, frame, n, NULL, NULL) == WSIO_ERR_TOO_BIG);
    EXPECT(wsio_last_close(srv) == WSIO_CLOSE_TOO_BIG);
    wsio_destroy(srv);
}

static void test_non_minimal_length(void)
{
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    uint8_t frame[16];
    /* 2-byte length encoding for 1-byte payload (illegal). */
    frame[0] = 0x82;
    frame[1] = 0xFE; /* masked, len=126 */
    frame[2] = 0x00;
    frame[3] = 0x01;
    frame[4] = KEY[0];
    frame[5] = KEY[1];
    frame[6] = KEY[2];
    frame[7] = KEY[3];
    frame[8] = (uint8_t)('x' ^ KEY[0]);
    EXPECT(feed(srv, frame, 9, NULL, NULL) == WSIO_ERR_PROTOCOL);
    wsio_destroy(srv);
}

static void test_two_messages_one_feed(void)
{
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    uint8_t frame[128];
    uint8_t both[128];
    size_t n1, n2;
    const wsio_event *evs;
    size_t nev;
    const uint8_t a[] = "one";
    const uint8_t b[] = "two!";

    n1 = build_frame(frame, 1, WSIO_OP_TEXT, 1, a, 3, KEY);
    memcpy(both, frame, n1);
    n2 = build_frame(frame, 1, WSIO_OP_TEXT, 1, b, 4, KEY);
    memcpy(both + n1, frame, n2);
    EXPECT(feed(srv, both, n1 + n2, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 2);
    EXPECT(evs[0].kind == WSIO_EV_TEXT);
    EXPECT(evs[0].len == 3);
    EXPECT(memcmp(evs[0].data, "one", 3) == 0);
    EXPECT(evs[1].kind == WSIO_EV_TEXT);
    EXPECT(evs[1].len == 4);
    EXPECT(memcmp(evs[1].data, "two!", 4) == 0);

    wsio_destroy(srv);
}

static void test_ping_and_text_one_feed(void)
{
    wsio *srv = wsio_create(WSIO_ROLE_SERVER);
    uint8_t frame[128];
    uint8_t both[128];
    size_t n1, n2;
    const wsio_event *evs;
    size_t nev;
    const uint8_t ping[] = {'p'};
    const uint8_t a[] = {'A'};
    const uint8_t b[] = {'B'};

    n1 = build_frame(frame, 0, WSIO_OP_TEXT, 1, a, 1, KEY);
    EXPECT(feed(srv, frame, n1, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 0);

    n1 = build_frame(frame, 1, WSIO_OP_PING, 1, ping, 1, KEY);
    memcpy(both, frame, n1);
    n2 = build_frame(frame, 1, WSIO_OP_CONT, 1, b, 1, KEY);
    memcpy(both + n1, frame, n2);
    EXPECT(feed(srv, both, n1 + n2, &evs, &nev) == WSIO_OK);
    EXPECT(nev == 2);
    EXPECT(evs[0].kind == WSIO_EV_PING);
    EXPECT(evs[1].kind == WSIO_EV_TEXT);
    EXPECT(evs[1].len == 2);
    EXPECT(memcmp(evs[1].data, "AB", 2) == 0);
    wsio_destroy(srv);
}

static void test_close_codes(void)
{
    EXPECT(wsio_close_code_valid(1000));
    EXPECT(wsio_close_code_valid(1011));
    EXPECT(wsio_close_code_valid(1014));
    EXPECT(wsio_close_code_valid(3000));
    EXPECT(wsio_close_code_valid(4999));
    EXPECT(!wsio_close_code_valid(999));
    EXPECT(!wsio_close_code_valid(1004));
    EXPECT(!wsio_close_code_valid(1005));
    EXPECT(!wsio_close_code_valid(1006));
    EXPECT(!wsio_close_code_valid(1015));
    EXPECT(!wsio_close_code_valid(2999));
    EXPECT(!wsio_close_code_valid(5000));
}

static void test_send_close_and_client_mask(void)
{
    wsio *cli = wsio_create(WSIO_ROLE_CLIENT);
    size_t n;
    const uint8_t *p;

    EXPECT(wsio_send_text(cli, (const uint8_t *)"a", 1) == WSIO_OK);
    p = wsio_peek(cli, &n);
    EXPECT(p && n >= 7);
    if (p && n >= 7) {
        EXPECT((p[1] & 0x80) != 0); /* masked */
    }

    EXPECT(wsio_send_close(cli, 1000, (const uint8_t *)"done", 4) == WSIO_OK);
    EXPECT(wsio_closing(cli));
    wsio_destroy(cli);
}

int main(void)
{
    test_64k_binary();
    test_incomplete_utf8_at_fin();
    test_roundtrip_text();
    test_binary_and_empty();
    test_extended_lengths();
    test_fragmentation_and_ping();
    test_utf8_split_and_invalid();
    test_protocol_errors();
    test_close();
    test_byte_at_a_time();
    test_too_big();
    test_non_minimal_length();
    test_two_messages_one_feed();
    test_ping_and_text_one_feed();
    test_close_codes();
    test_send_close_and_client_mask();
    if (g_fail) {
        fprintf(stderr, "some tests failed\n");
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
