/**
 * Two sws sessions talking in memory. No sockets or HTTP.
 */

#include "sws.h"

#include <stdio.h>
#include <stdlib.h>

static void show(const char *who, sws_result r)
{
    size_t i;

    if (r.err != SWS_OK) {
        fprintf(stderr, "%s: err %d\n", who, (int)r.err);
        exit(1);
    }
    for (i = 0; i < r.n; i++) {
        const sws_event *e = &r.evs[i];
        if (e->kind == SWS_EV_TEXT) {
            printf("%s text: %.*s\n", who, (int)e->len, (const char *)e->data);
        } else if (e->kind == SWS_EV_CLOSE) {
            printf("%s close: %u\n", who, (unsigned)e->close_code);
        }
    }
}

static sws_result pump(sws_bytes b, sws *to)
{
    if (!b.p || !b.n) {
        fprintf(stderr, "encode failed\n");
        exit(1);
    }
    return sws_feed(to, b.p, b.n);
}

int main(void)
{
    sws *cli = sws_create(SWS_ROLE_CLIENT);
    sws *srv = sws_create(SWS_ROLE_SERVER);
    const uint8_t hi[] = "hello";
    sws_result r;

    if (!cli || !srv) {
        return 1;
    }

    show("server", pump(sws_text_frame(cli, hi, sizeof hi - 1), srv));

    show("client", pump(sws_text_frame(srv, (const uint8_t *)"hi", 2), cli));

    r = pump(sws_close_frame(cli, SWS_CLOSE_NORMAL, NULL, 0), srv);
    show("server", r);
    show("client", sws_feed(cli, r.out.p, r.out.n));

    sws_destroy(cli);
    sws_destroy(srv);
    return 0;
}
