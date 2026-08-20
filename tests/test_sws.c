#include <cgreen/cgreen.h>

#include "sws.h"

#include <stdlib.h>
#include <string.h>

/* Peer-illegal frames only. Frame helpers will not emit these (programming errors abort). */
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

static sws_bytes must_encode(sws_bytes b)
{
    assert_that(b.p, is_non_null);
    assert_that(b.n > 0, is_true);
    return b;
}

static sws_result feed_bytes(sws *to, sws_bytes b)
{
    b = must_encode(b);
    return sws_feed(to, b.p, b.n);
}

static size_t cat_bytes(uint8_t *dst, size_t cap, size_t off, sws_bytes b)
{
    b = must_encode(b);
    assert_that(off + b.n <= cap, is_true);
    memcpy(dst + off, b.p, b.n);
    return off + b.n;
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
    client = sws_create_client(NULL, NULL);
    server = sws_create_server();
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
    r = feed_bytes(server, sws_text_frame(client, (const uint8_t *)"hello", 5));
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_TEXT, "hello", 5);

    r = feed_bytes(client, sws_text_frame(server, r.evs[0].data, r.evs[0].len));
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_TEXT, "hello", 5);
}

Ensure(sws, exchanges_binary_and_empty_text)
{
    const uint8_t payload[] = {0, 1, 255};
    sws_result r;

    r = feed_bytes(server, sws_bin_frame(client, payload, sizeof payload));
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_BIN, payload, sizeof payload);

    r = feed_bytes(server, sws_text_frame(client, NULL, 0));
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

    r = feed_bytes(server, sws_bin_frame(client, payload, mid));
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_BIN, payload, mid);

    for (i = 0; i < big; i++) {
        payload[i] = (uint8_t)(i * 3);
    }
    r = feed_bytes(server, sws_bin_frame(client, payload, big));
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

    r = feed_bytes(server, sws_fragment(client, SWS_OP_TEXT, a, sizeof a));
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(0));
    assert_that(r.out.n, is_equal_to(0));

    r = feed_bytes(server, sws_ping_frame(client, ping, sizeof ping));
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_PING, ping, sizeof ping);
    assert_that(r.out.n > 0, is_true);
    r = sws_feed(client, r.out.p, r.out.n);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_PONG, ping, sizeof ping);

    r = feed_bytes(server, sws_fragment_end(client, b, sizeof b));
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_TEXT, "Hello", 5);
}

Ensure(sws, reconstructs_utf8_split_across_fragments)
{
    const uint8_t f0[] = {0xC3};
    const uint8_t f1[] = {0xA9};
    sws_result r;

    assert_that(feed_bytes(server, sws_fragment(client, SWS_OP_TEXT, f0, 1)).err,
                is_equal_to(SWS_OK));
    r = feed_bytes(server, sws_fragment_end(client, f1, 1));
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
    sws_result r;

    n = peer_frame(frame, true, SWS_OP_TEXT, true, 0, bad, 1);
    r = sws_feed(server, frame, n);
    assert_that(r.err, is_equal_to(SWS_ERR_UTF8));
    assert_that(sws_last_close(server), is_equal_to(SWS_CLOSE_INVALID_DATA));
    assert_that(r.out.n > 0, is_true);
    sws_destroy(server);
    server = sws_create_server();

    n = peer_frame(frame, true, SWS_OP_TEXT, true, 0, overlong, 2);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_UTF8));
    sws_destroy(server);
    server = sws_create_server();

    n = peer_frame(frame, true, SWS_OP_TEXT, true, 0, incomplete, 1);
    r = sws_feed(server, frame, n);
    assert_that(r.err, is_equal_to(SWS_ERR_UTF8));
    assert_that(sws_last_close(server), is_equal_to(SWS_CLOSE_INVALID_DATA));
    sws_destroy(server);
    server = sws_create_server();

    n = peer_frame(frame, false, SWS_OP_TEXT, true, 0, early, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_UTF8));
}

Ensure(sws, close_handshake_echoes_reason_and_empty)
{
    sws_result r;

    r = feed_bytes(server, sws_close_frame(client, 1000, (const uint8_t *)"bye", 3));
    assert_that(sws_closing(client), is_true);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_that(r.evs[0].kind, is_equal_to(SWS_EV_CLOSE));
    assert_that(r.evs[0].close_code, is_equal_to(1000));
    assert_payload(&r.evs[0], SWS_EV_CLOSE, "bye", 3);
    assert_that(r.out.n > 0, is_true);
    r = sws_feed(client, r.out.p, r.out.n);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_that(r.evs[0].kind, is_equal_to(SWS_EV_CLOSE));
    assert_that(sws_closed(client), is_true);
    assert_that(sws_closed(server), is_true);

    sws_destroy(client);
    sws_destroy(server);
    client = sws_create_client(NULL, NULL);
    server = sws_create_server();
    r = feed_bytes(server, sws_close_frame(client, 0, NULL, 0));
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(1));
    assert_that(r.evs[0].kind, is_equal_to(SWS_EV_CLOSE));
    assert_that(r.evs[0].close_code, is_equal_to(SWS_CLOSE_NO_STATUS));
    assert_that(r.out.n > 0, is_true);
}

Ensure(sws, feeds_a_valid_stream_one_byte_at_a_time)
{
    sws_bytes b;
    size_t i;
    sws_result r;

    b = must_encode(sws_text_frame(client, (const uint8_t *)"abc", 3));
    r.err = SWS_OK;
    r.n = 0;
    r.evs = NULL;
    r.out.p = NULL;
    r.out.n = 0;
    for (i = 0; i < b.n; i++) {
        r = sws_feed(server, b.p + i, 1);
        assert_that(r.err, is_equal_to(SWS_OK));
    }
    assert_that(r.n, is_equal_to(1));
    assert_payload(&r.evs[0], SWS_EV_TEXT, "abc", 3);
}

Ensure(sws, delivers_two_messages_from_one_feed)
{
    uint8_t buf[256];
    size_t n = 0;
    sws_result r;

    n = cat_bytes(buf, sizeof buf, n, sws_text_frame(client, (const uint8_t *)"one", 3));
    n = cat_bytes(buf, sizeof buf, n, sws_text_frame(client, (const uint8_t *)"two!", 4));
    r = sws_feed(server, buf, n);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(2));
    assert_payload(&r.evs[0], SWS_EV_TEXT, "one", 3);
    assert_payload(&r.evs[1], SWS_EV_TEXT, "two!", 4);
}

Ensure(sws, delivers_ping_and_completed_text_from_one_feed)
{
    uint8_t buf[256];
    size_t n = 0;
    sws_result r;
    const uint8_t ping[] = {'p'};

    r = feed_bytes(server, sws_fragment(client, SWS_OP_TEXT, (const uint8_t *)"A", 1));
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(0));

    n = cat_bytes(buf, sizeof buf, n, sws_ping_frame(client, ping, 1));
    n = cat_bytes(buf, sizeof buf, n, sws_fragment_end(client, (const uint8_t *)"B", 1));
    r = sws_feed(server, buf, n);
    assert_that(r.err, is_equal_to(SWS_OK));
    assert_that(r.n, is_equal_to(2));
    assert_that(r.evs[0].kind, is_equal_to(SWS_EV_PING));
    assert_payload(&r.evs[1], SWS_EV_TEXT, "AB", 2);
    assert_that(r.out.n > 0, is_true);
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
    server = sws_create_server();

    n = peer_frame(frame, true, SWS_OP_TEXT, true, 1, hi, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(server);
    server = sws_create_server();

    n = peer_frame(frame, true, 0x3, true, 0, hi, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(server);
    server = sws_create_server();

    n = peer_frame(frame, false, SWS_OP_PING, true, 0, hi, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(server);
    server = sws_create_server();

    n = peer_frame(frame, true, SWS_OP_CONT, true, 0, hi, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(server);
    server = sws_create_server();

    cli = sws_create_client(NULL, NULL);
    n = peer_frame(frame, true, SWS_OP_TEXT, true, 0, hi, 1);
    assert_that(sws_feed(cli, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(cli);

    wr16(payload, 1005);
    n = peer_frame(frame, true, SWS_OP_CLOSE, true, 0, payload, 2);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    assert_that(sws_last_close(server), is_equal_to(SWS_CLOSE_PROTOCOL));
    sws_destroy(server);
    server = sws_create_server();

    payload[0] = 0x00;
    n = peer_frame(frame, true, SWS_OP_CLOSE, true, 0, payload, 1);
    assert_that(sws_feed(server, frame, n).err, is_equal_to(SWS_ERR_PROTOCOL));
    sws_destroy(server);
    server = sws_create_server();

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
    add_test_with_context(suite, sws, delivers_two_messages_from_one_feed);
    add_test_with_context(suite, sws, delivers_ping_and_completed_text_from_one_feed);
    add_test_with_context(suite, sws, close_code_valid_matches_rfc);
    add_test_with_context(suite, sws, rejects_illegal_peer_frames);
    return run_test_suite(suite, create_text_reporter());
}
