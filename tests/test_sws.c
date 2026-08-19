#include <cgreen/cgreen.h>

#include "sws.h"

#include <stdlib.h>
#include <string.h>

/* Peer-illegal frames only. send_* will not emit these (programming errors abort). */
static const uint8_t KEY[4] = {0x01, 0x02, 0x03, 0x04};

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static size_t peer_frame(uint8_t *out, bool fin, int opcode, bool mask, int rsv,
                         const uint8_t *payload, size_t len)
{
    size_t h = 2;
    size_t i;

    out[0] = (uint8_t)((fin ? 0x80u : 0u) | ((rsv & 7) << 4) | (opcode & 0x0Fu));
    if (len <= 125) {
        out[1] = (uint8_t)len;
    } else if (len <= 0xFFFFu) {
        out[1] = 126;
        wr16(out + 2, (uint16_t)len);
        h = 4;
    } else {
        return 0;
    }
    if (mask) {
        out[1] |= 0x80u;
        memcpy(out + h, KEY, 4);
        h += 4;
    }
    if (len) {
        memcpy(out + h, payload, len);
        if (mask) {
            for (i = 0; i < len; i++) {
                out[h + i] ^= KEY[i & 3];
            }
        }
    }
    return h + len;
}

static sws_result xfer(sws *from, sws *to)
{
    size_t n;
    const uint8_t *p = sws_peek(from, &n);
    sws_result r;

    r.err = SWS_OK;
    r.evs = NULL;
    r.n = 0;
    if (!n) {
        return r;
    }
    r = sws_feed(to, p, n);
    sws_consume(from, n);
    return r;
}

static void assert_payload(const sws_event *e, sws_event_kind kind, const void *bytes,
                           size_t len)
{
    assert_that(e->kind, is_equal_to(kind));
    assert_that(e->len, is_equal_to(len));
    if (len) {
        assert_that(e->data, is_equal_to_contents_of(bytes, len));
    }
}

Describe(sws);

static sws *client;
static sws *server;

BeforeEach(sws)
{
    client = sws_create(SWS_ROLE_CLIENT);
    server = sws_create(SWS_ROLE_SERVER);
}

AfterEach(sws)
{
    sws_destroy(client);
    sws_destroy(server);
    client = NULL;
    server = NULL;
}

Ensure(sws, exchanges_text)
{
    sws_result r;

    assert_that(client, is_non_null);
    assert_that(server, is_non_null);
    assert_that(sws_send_text(client, (const uint8_t *)"hello", 5), is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_TEXT, "hello", 5);

    assert_that(sws_send_text(server, r.evs[0].data, r.evs[0].len), is_equal_to(SWS_OK));
    r = xfer(server, client);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_TEXT, "hello", 5);
}

Ensure(sws, exchanges_binary_and_empty_text)
{
    const uint8_t payload[] = {0, 1, 255};
    sws_result r;

    assert_that(sws_send_bin(client, payload, sizeof payload), is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_BIN, payload, sizeof payload);

    assert_that(sws_send_text(client, NULL, 0), is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_TEXT, NULL, 0);
}

Ensure(sws, exchanges_extended_and_64k_binary)
{
    const size_t mid = 200;
    const size_t big = 65536;
    uint8_t *payload = (uint8_t *)malloc(big);
    sws_result r;
    size_t i;

    assert_that(payload, is_non_null);
    for (i = 0; i < big; i++) {
        payload[i] = (uint8_t)i;
    }

    assert_that(sws_send_bin(client, payload, mid), is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_BIN, payload, mid);

    for (i = 0; i < big; i++) {
        payload[i] = (uint8_t)(i * 3);
    }
    assert_that(sws_send_bin(client, payload, big), is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_BIN, payload, big);
    free(payload);
}

Ensure(sws, fragments_text_and_interleaves_ping)
{
    const uint8_t a[] = {'H', 'e'};
    const uint8_t b[] = {'l', 'l', 'o'};
    const uint8_t ping[] = {'p', 'i'};
    sws_result r;

    assert_that(sws_send(client, SWS_OP_TEXT, a, sizeof a, false), is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(0));

    assert_that(sws_send_ping(client, ping, sizeof ping), is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_PING, ping, sizeof ping);
    assert_that(sws_pending(server) > 0, is_true); /* auto pong */

    assert_that(sws_send(client, SWS_OP_CONT, b, sizeof b, true), is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_TEXT, "Hello", 5);
}

Ensure(sws, reconstructs_utf8_split_across_fragments)
{
    const uint8_t f0[] = {0xC3};
    const uint8_t f1[] = {0xA9};
    sws_result r;

    assert_that(sws_send(client, SWS_OP_TEXT, f0, 1, false), is_equal_to(SWS_OK));
    assert_that(xfer(client, server).err, is_equal_to(SWS_OK));
    assert_that(sws_send(client, SWS_OP_CONT, f1, 1, true), is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    {
        const uint8_t expected[] = {0xC3, 0xA9};
        assert_payload(&r.evs[0], SWS_EV_TEXT, expected, 2);
    }
}

Ensure(sws, rejects_invalid_utf8_from_peer)
{
    uint8_t frame[64];
    size_t n;
    const uint8_t bad[] = {0x80};
    const uint8_t overlong[] = {0xC0, 0x80};
    const uint8_t incomplete[] = {0xC3};
    const uint8_t early[] = {0xFF};

    n = peer_frame(frame, true, SWS_OP_TEXT, true, 0, bad, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_UTF8));
    assert_that(sws_last_close(server), is_equal_to(SWS_CLOSE_INVALID_DATA));
    assert_that(sws_pending(server) > 0, is_true);
    sws_destroy(server);
    server = sws_create(SWS_ROLE_SERVER);

    n = peer_frame(frame, true, SWS_OP_TEXT, true, 0, overlong, 2);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_UTF8));
    sws_destroy(server);
    server = sws_create(SWS_ROLE_SERVER);

    n = peer_frame(frame, true, SWS_OP_TEXT, true, 0, incomplete, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_UTF8));
    assert_that(sws_last_close(server), is_equal_to(SWS_CLOSE_INVALID_DATA));
    sws_destroy(server);
    server = sws_create(SWS_ROLE_SERVER);

    n = peer_frame(frame, false, SWS_OP_TEXT, true, 0, early, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_UTF8));
}

Ensure(sws, close_handshake_echoes_reason_and_empty)
{
    sws_result r;

    assert_that(sws_send_close(client, 1000, (const uint8_t *)"bye", 3), is_equal_to(SWS_OK));
    assert_that(sws_closing(client), is_true);
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_that(r.evs[0].kind, is_equal_to(SWS_EV_CLOSE));
    assert_that(r.evs[0].close_code, is_equal_to(1000));
    assert_payload(&r.evs[0], SWS_EV_CLOSE, "bye", 3);
    assert_that(sws_pending(server) > 0, is_true); /* auto close reply */
    r = xfer(server, client);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_that(r.evs[0].kind, is_equal_to(SWS_EV_CLOSE));
    assert_that(sws_closed(client), is_true);
    assert_that(sws_closed(server), is_true);

    sws_destroy(client);
    sws_destroy(server);
    client = sws_create(SWS_ROLE_CLIENT);
    server = sws_create(SWS_ROLE_SERVER);
    assert_that(sws_send_close(client, 0, NULL, 0), is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_that(r.evs[0].kind, is_equal_to(SWS_EV_CLOSE));
    assert_that(r.evs[0].close_code, is_equal_to(SWS_CLOSE_NO_STATUS));
}

Ensure(sws, feeds_a_valid_stream_one_byte_at_a_time)
{
    size_t n, i;
    const uint8_t *p;
    sws_result r;

    assert_that(sws_send_text(client, (const uint8_t *)"abc", 3), is_equal_to(SWS_OK));
    p = sws_peek(client, &n);
    assert_that(n > 0, is_true);
    r.err = SWS_OK;
    r.n = 0;
    r.evs = NULL;
    for (i = 0; i < n; i++) {
        r = sws_feed(server, p + i, 1);
        assert_that(r.err, is_equal_to(SWS_OK));
    }
    sws_consume(client, n);
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_TEXT, "abc", 3);
}

Ensure(sws, rejects_message_over_configured_max)
{
    sws_config cfg;
    sws *small;
    uint8_t payload[8] = {0};
    sws_result r;

    sws_config_default(&cfg);
    cfg.role = SWS_ROLE_SERVER;
    cfg.max_message_size = 4;
    small = sws_create_cfg(&cfg);
    assert_that(small, is_non_null);
    assert_that(sws_send_bin(client, payload, sizeof payload), is_equal_to(SWS_OK));
    r = xfer(client, small);
    assert_that(r.err, is_equal_to(SWS_ERR_TOO_BIG));
    assert_that(sws_last_close(small), is_equal_to(SWS_CLOSE_TOO_BIG));
    sws_destroy(small);
}

Ensure(sws, delivers_two_messages_from_one_feed)
{
    size_t n;
    const uint8_t *p;
    sws_result r;

    assert_that(sws_send_text(client, (const uint8_t *)"one", 3), is_equal_to(SWS_OK));
    assert_that(sws_send_text(client, (const uint8_t *)"two!", 4), is_equal_to(SWS_OK));
    p = sws_peek(client, &n);
    r = sws_feed(server, p, n);
    sws_consume(client, n);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(2));
    assert_payload(&r.evs[0], SWS_EV_TEXT, "one", 3);
    assert_payload(&r.evs[1], SWS_EV_TEXT, "two!", 4);
}

Ensure(sws, delivers_ping_and_completed_text_from_one_feed)
{
    size_t n;
    const uint8_t *p;
    sws_result r;
    const uint8_t ping[] = {'p'};

    assert_that(sws_send(client, SWS_OP_TEXT, (const uint8_t *)"A", 1, false),
                is_equal_to(SWS_OK));
    r = xfer(client, server);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(0));

    assert_that(sws_send_ping(client, ping, 1), is_equal_to(SWS_OK));
    assert_that(sws_send(client, SWS_OP_CONT, (const uint8_t *)"B", 1, true),
                is_equal_to(SWS_OK));
    p = sws_peek(client, &n);
    r = sws_feed(server, p, n);
    sws_consume(client, n);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(2));
    assert_that(r.evs[0].kind, is_equal_to(SWS_EV_PING));
    assert_payload(&r.evs[1], SWS_EV_TEXT, "AB", 2);
}

Ensure(sws, close_code_valid_matches_rfc)
{
    assert_that(sws_close_code_valid(1000), is_true);
    assert_that(sws_close_code_valid(1011), is_true);
    assert_that(sws_close_code_valid(1014), is_true);
    assert_that(sws_close_code_valid(3000), is_true);
    assert_that(sws_close_code_valid(4999), is_true);
    assert_that(sws_close_code_valid(999), is_false);
    assert_that(sws_close_code_valid(1004), is_false);
    assert_that(sws_close_code_valid(1005), is_false);
    assert_that(sws_close_code_valid(1006), is_false);
    assert_that(sws_close_code_valid(1015), is_false);
    assert_that(sws_close_code_valid(2999), is_false);
    assert_that(sws_close_code_valid(5000), is_false);
}

Ensure(sws, rejects_illegal_peer_frames)
{
    uint8_t frame[64];
    uint8_t payload[8];
    size_t n;
    const uint8_t hi[] = {'x'};
    sws *cli;

    n = peer_frame(frame, true, SWS_OP_TEXT, false, 0, hi, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    assert_that(sws_last_close(server), is_equal_to(SWS_CLOSE_PROTOCOL));
    sws_destroy(server);
    server = sws_create(SWS_ROLE_SERVER);

    n = peer_frame(frame, true, SWS_OP_TEXT, true, 1, hi, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(server);
    server = sws_create(SWS_ROLE_SERVER);

    n = peer_frame(frame, true, 0x3, true, 0, hi, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(server);
    server = sws_create(SWS_ROLE_SERVER);

    n = peer_frame(frame, false, SWS_OP_PING, true, 0, hi, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(server);
    server = sws_create(SWS_ROLE_SERVER);

    n = peer_frame(frame, true, SWS_OP_CONT, true, 0, hi, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(server);
    server = sws_create(SWS_ROLE_SERVER);

    cli = sws_create(SWS_ROLE_CLIENT);
    n = peer_frame(frame, true, SWS_OP_TEXT, true, 0, hi, 1);
    assert_that(sws_feed(cli, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(cli);

    wr16(payload, 1005);
    n = peer_frame(frame, true, SWS_OP_CLOSE, true, 0, payload, 2);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    assert_that(sws_last_close(server), is_equal_to(SWS_CLOSE_PROTOCOL));
    sws_destroy(server);
    server = sws_create(SWS_ROLE_SERVER);

    payload[0] = 0x00;
    n = peer_frame(frame, true, SWS_OP_CLOSE, true, 0, payload, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(server);
    server = sws_create(SWS_ROLE_SERVER);

    /* 2-byte length encoding for a 1-byte payload (non-minimal). */
    frame[0] = 0x82;
    frame[1] = 0xFE;
    frame[2] = 0x00;
    frame[3] = 0x01;
    frame[4] = KEY[0];
    frame[5] = KEY[1];
    frame[6] = KEY[2];
    frame[7] = KEY[3];
    frame[8] = (uint8_t)('x' ^ KEY[0]);
    assert_that(sws_feed(server, frame, 9).err, is_equal_to(SWS_ERR_PROTOCOL));
}

int main(int argc, char **argv)
{
    TestSuite *suite;
    (void)argc;
    (void)argv;
    suite = create_test_suite();
    add_test_with_context(suite, sws, exchanges_text);
    add_test_with_context(suite, sws, exchanges_binary_and_empty_text);
    add_test_with_context(suite, sws, exchanges_extended_and_64k_binary);
    add_test_with_context(suite, sws, fragments_text_and_interleaves_ping);
    add_test_with_context(suite, sws, reconstructs_utf8_split_across_fragments);
    add_test_with_context(suite, sws, rejects_invalid_utf8_from_peer);
    add_test_with_context(suite, sws, close_handshake_echoes_reason_and_empty);
    add_test_with_context(suite, sws, feeds_a_valid_stream_one_byte_at_a_time);
    add_test_with_context(suite, sws, rejects_message_over_configured_max);
    add_test_with_context(suite, sws, delivers_two_messages_from_one_feed);
    add_test_with_context(suite, sws, delivers_ping_and_completed_text_from_one_feed);
    add_test_with_context(suite, sws, close_code_valid_matches_rfc);
    add_test_with_context(suite, sws, rejects_illegal_peer_frames);
    return run_test_suite(suite, create_text_reporter());
}
