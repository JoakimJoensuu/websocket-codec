/**
 * Two swsc sessions talking in memory. No sockets or HTTP.
 */

#include "swsc.h"

#include <stdint.h>
#include <stdio.h>

int main(void) {
  swsc *cli = swsc_create_client(NULL, NULL);
  swsc *srv = swsc_create_server();
  swsc_bytes b;
  swsc_result r;

  if (!cli || !srv) {
    return 1;
  }

  b = swsc_text_frame(cli, (const uint8_t *)"hello", 5);
  r = swsc_feed(srv, b.p, b.n);
  printf("server text: %.*s\n", (int)r.evs[0].len, (const char *)r.evs[0].data);

  b = swsc_text_frame(srv, (const uint8_t *)"hi", 2);
  r = swsc_feed(cli, b.p, b.n);
  printf("client text: %.*s\n", (int)r.evs[0].len, (const char *)r.evs[0].data);

  b = swsc_close_frame(cli, SWSC_CLOSE_NORMAL, NULL, 0);
  r = swsc_feed(srv, b.p, b.n);
  printf("server close: %u\n", (unsigned)r.evs[0].close_code);

  r = swsc_feed(cli, r.out.p, r.out.n);
  printf("client close: %u\n", (unsigned)r.evs[0].close_code);

  swsc_destroy(cli);
  swsc_destroy(srv);
  return 0;
}
