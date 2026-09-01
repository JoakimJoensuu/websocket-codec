#include <wsc.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  const uint8_t hello[] = "hello";
  struct wsc_frame frame = {
      .payload = hello,
      .payload_len = sizeof(hello) - 1,
      .opcode = WSC_OP_TEXT,
      .fin = true,
  };
  struct wsc_decoder *dec = wsc_decoder_create();
  struct wsc_encoding_result encoded;
  struct wsc_decoding_result result;

  if (dec == nullptr) {
    return 1;
  }
  encoded = wsc_encode(&frame);
  if (encoded.err != WSC_OK) {
    wsc_decoder_destroy(dec);
    return 1;
  }
  result = wsc_decoder_feed(dec, encoded.data, encoded.data_len);
  if (result.err != WSC_OK || result.frames_cnt != 1) {
    free(encoded.data);
    wsc_decoder_destroy(dec);
    return 1;
  }
  printf("%.*s\n", (int)result.frames[0].payload_len, (const char *)result.frames[0].payload);
  free(encoded.data);
  wsc_decoder_destroy(dec);
  return 0;
}
