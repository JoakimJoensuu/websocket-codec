/**
 * Two swsc sessions talking in memory. No sockets or HTTP.
 */

#include "swsc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void print_result(const char *who, struct swsc_result result) {
  if (result.err != SWSC_OK) {
    printf("%s err %d\n", who, (int)result.err);
  }
  for (size_t i = 0; i < result.events_cnt; i++) {
    const struct swsc_event *event = &result.events[i];
    switch (event->kind) {
    case SWSC_EV_TEXT:
      printf("%s text: %.*s\n", who, (int)event->length, (const char *)event->data);
      break;
    case SWSC_EV_CLOSE:
      printf("%s close: %u\n", who, (unsigned)event->close_code);
      break;
    default:
      printf("%s event %d (%zu bytes)\n", who, (int)event->kind, event->length);
      break;
    }
  }
}

int main() {
  struct swsc *cli = swsc_create_client(nullptr, nullptr);
  struct swsc *srv = swsc_create_server();
  struct swsc_enc enc;
  struct swsc_result result;

  if (cli == nullptr || srv == nullptr) {
    return 1;
  }

  enc = swsc_text_frame(cli, (const uint8_t *)"hello", strlen("hello"));
  result = swsc_feed(srv, enc.bytes.data, enc.bytes.length);
  print_result("server", result);

  enc = swsc_text_frame(srv, (const uint8_t *)"hi", strlen("hi"));
  result = swsc_feed(cli, enc.bytes.data, enc.bytes.length);
  print_result("client", result);

  enc = swsc_close_frame(cli, SWSC_CLOSE_NORMAL, nullptr, 0);
  result = swsc_feed(srv, enc.bytes.data, enc.bytes.length);
  print_result("server", result);

  enc = swsc_close_frame(srv, result.events[0].close_code, result.events[0].data,
                         result.events[0].length);
  result = swsc_feed(cli, enc.bytes.data, enc.bytes.length);
  print_result("client", result);

  swsc_destroy(cli);
  swsc_destroy(srv);
  return 0;
}
