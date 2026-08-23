/**
 * Two swsc sessions talking in memory. No sockets or HTTP.
 */

#include "swsc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  swsc *cli = swsc_create_client(nullptr, nullptr);
  swsc *srv = swsc_create_server();
  swsc_bytes frame;
  swsc_result result;

  if (!cli || !srv) {
    return 1;
  }

  frame = swsc_text_frame(cli, (const uint8_t *)"hello", strlen("hello"));
  result = swsc_feed(srv, frame.p, frame.n);
  printf("server text: %.*s\n", (int)result.evs[0].len,
         (const char *)result.evs[0].data);

  frame = swsc_text_frame(srv, (const uint8_t *)"hi", strlen("hi"));
  result = swsc_feed(cli, frame.p, frame.n);
  printf("client text: %.*s\n", (int)result.evs[0].len,
         (const char *)result.evs[0].data);

  frame = swsc_close_frame(cli, SWSC_CLOSE_NORMAL, nullptr, 0);
  result = swsc_feed(srv, frame.p, frame.n);
  printf("server close: %u\n", (unsigned)result.evs[0].close_code);

  result = swsc_feed(cli, result.out.p, result.out.n);
  printf("client close: %u\n", (unsigned)result.evs[0].close_code);

  swsc_destroy(cli);
  swsc_destroy(srv);
  return 0;
}
