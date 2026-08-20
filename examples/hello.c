/**
 * Two sws sessions talking in memory. No sockets or HTTP.
 */

#include "sws.h"

#include <stdio.h>

int main(void)
{
    sws *cli = sws_create_client(NULL, NULL);
    sws *srv = sws_create_server();
    sws_bytes b;
    sws_result r;

    if (!cli || !srv) {
        return 1;
    }

    b = sws_text_frame(cli, (const uint8_t *)"hello", 5);
    r = sws_feed(srv, b.p, b.n);
    printf("server text: %.*s\n", (int)r.evs[0].len, (const char *)r.evs[0].data);

    b = sws_text_frame(srv, (const uint8_t *)"hi", 2);
    r = sws_feed(cli, b.p, b.n);
    printf("client text: %.*s\n", (int)r.evs[0].len, (const char *)r.evs[0].data);

    b = sws_close_frame(cli, SWS_CLOSE_NORMAL, NULL, 0);
    r = sws_feed(srv, b.p, b.n);
    printf("server close: %u\n", (unsigned)r.evs[0].close_code);

    r = sws_feed(cli, r.out.p, r.out.n);
    printf("client close: %u\n", (unsigned)r.evs[0].close_code);

    sws_destroy(cli);
    sws_destroy(srv);
    return 0;
}
