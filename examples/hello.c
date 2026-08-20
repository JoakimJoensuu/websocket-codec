/**
 * Two swsf sessions talking in memory. No sockets or HTTP.
 */

#include "swsf.h"

#include <stdio.h>

int main(void)
{
    swsf *cli = swsf_create_client(NULL, NULL);
    swsf *srv = swsf_create_server();
    swsf_bytes b;
    swsf_result r;

    if (!cli || !srv) {
        return 1;
    }

    b = swsf_text_frame(cli, (const uint8_t *)"hello", 5);
    r = swsf_feed(srv, b.p, b.n);
    printf("server text: %.*s\n", (int)r.evs[0].len, (const char *)r.evs[0].data);

    b = swsf_text_frame(srv, (const uint8_t *)"hi", 2);
    r = swsf_feed(cli, b.p, b.n);
    printf("client text: %.*s\n", (int)r.evs[0].len, (const char *)r.evs[0].data);

    b = swsf_close_frame(cli, SWSF_CLOSE_NORMAL, NULL, 0);
    r = swsf_feed(srv, b.p, b.n);
    printf("server close: %u\n", (unsigned)r.evs[0].close_code);

    r = swsf_feed(cli, r.out.p, r.out.n);
    printf("client close: %u\n", (unsigned)r.evs[0].close_code);

    swsf_destroy(cli);
    swsf_destroy(srv);
    return 0;
}
