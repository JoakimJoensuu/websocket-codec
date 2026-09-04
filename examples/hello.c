#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wsc.h>

int main() {
  const uint8_t hello[] = "hello";
  struct wsc_frame frame = {
      .payload = hello,
      .payload_length = sizeof(hello) - 1,
      .opcode = WSC_OPCODE_TEXT,
      .fin = true,
  };
  struct wsc_decoder *decoder = wsc_decoder_create();

  if (decoder == nullptr) {
    return 1;
  }
  struct wsc_encoding_result encoded = wsc_encode(&frame);
  if (encoded.err != WSC_OK) {
    wsc_decoder_destroy(decoder);
    return 1;
  }
  struct wsc_decoding_result result = wsc_decoder_feed(decoder, encoded.data, encoded.data_length);
  if (result.err != WSC_OK || result.frames_count != 1) {
    free(encoded.data);
    wsc_decoder_destroy(decoder);
    return 1;
  }
  printf("%.*s\n", (int)result.frames[0].payload_length, (const char *)result.frames[0].payload);
  free(encoded.data);
  wsc_decoder_destroy(decoder);
  return 0;
}
