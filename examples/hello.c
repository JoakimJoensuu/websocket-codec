/**
 * Encode one frame and parse those bytes back.
 */

#include "wsc.h"

#include <stdint.h>
#include <stdio.h>

int main() {
  const uint8_t hello[] = "hello";
  enum : unsigned { BUF_CAP = 64 };
  uint8_t buf[BUF_CAP];
  struct wsc_frame frame = {
      .payload = hello,
      .payload_len = sizeof hello - 1,
      .opcode = WSC_OP_TEXT,
      .fin = true,
  };
  struct wsc_dec *dec = wsc_dec_create();
  size_t wire_len = 0;
  struct wsc_result result;

  if (dec == nullptr) {
    return 1;
  }
  wire_len = wsc_encode(buf, sizeof buf, &frame);
  result = wsc_dec_feed(dec, buf, wire_len);
  if (result.err != WSC_OK || result.frames_cnt != 1) {
    wsc_dec_destroy(dec);
    return 1;
  }
  printf("%.*s\n", (int)result.frames[0].payload_len, (const char *)result.frames[0].payload);
  wsc_dec_destroy(dec);
  return 0;
}
