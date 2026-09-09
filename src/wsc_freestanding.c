#include "wsc_freestanding.h"
#include "wsc.h"
#include "wsc_common.h"

#include <ringalloc.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct wsc_decoder *wsc_decoder_create(unsigned char *arena, size_t capacity) {
  if (arena == nullptr) {
    wsc_trap();
  }
  size_t align = alignof(struct wsc_decoder_data);
  size_t skip = ((uintptr_t)arena % align == 0) ? 0 : align - ((uintptr_t)arena % align);
  if (skip > capacity || sizeof(struct wsc_decoder_data) > capacity - skip) {
    return nullptr;
  }
  unsigned char *slot = arena + skip;
  size_t after = skip + sizeof(struct wsc_decoder_data);
  struct wsc_decoder_data data = {};
  data.ringalloc = ra_create(arena + after, capacity - after);
  if (data.ringalloc == nullptr) {
    return nullptr;
  }
  wsc_decoder_state_init(&data);
  memcpy(slot, &data, sizeof(data));
  return (struct wsc_decoder *)slot;
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t length) {
  if (decoder == nullptr) {
    wsc_trap();
  }
  struct wsc_decoder_data data;
  memcpy(&data, decoder, sizeof(data));
  struct wsc_decoding_result result = wsc_decoder_feed_data(&data, source, length);
  memcpy(decoder, &data, sizeof(data));
  return result;
}

size_t wsc_encode(uint8_t *destination, size_t destination_capacity,
                  const struct wsc_frame *frame) {
  return wsc_encode_buffer(destination, destination_capacity, frame);
}
