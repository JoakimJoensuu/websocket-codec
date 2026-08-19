/**
 * Two sws sessions talking in memory. No sockets or HTTP.
 */

#include "sws.h"

#include <stdio.h>
#include <stdlib.h>

static sws_result pump(sws *from, sws *to)
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

int main(void)
{
    sws *cli = sws_create(SWS_ROLE_CLIENT, 64 * 1024);
    sws *srv = sws_create(SWS_ROLE_SERVER, 64 * 1024);
    const uint8_t hi[] = "hello";

    if (!cli || !srv) {
        return 1;
    }

    sws_send_text(cli, hi, sizeof hi - 1);
    show("server", pump(cli, srv));

    sws_send_text(srv, (const uint8_t *)"hi", 2);
    show("client", pump(srv, cli));

    sws_send_close(cli, SWS_CLOSE_NORMAL, NULL, 0);
    show("server", pump(cli, srv));
    show("client", pump(srv, cli)); /* auto-close reply */

    sws_destroy(cli);
    sws_destroy(srv);
    return 0;
}
