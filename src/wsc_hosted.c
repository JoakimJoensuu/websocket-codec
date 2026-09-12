#include "wsc.h"
#include "wsc_common.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <stdbool.h>

struct wsc_decoder {
  uint64_t payload_length;
  uint64_t payload_received;
  struct wsc_buffer payload;
  struct wsc_frame *frames;
  size_t frames_count;
  size_t frames_capacity;
  size_t header_received;
  size_t header_total;
  enum wsc_parse_state state;
  unsigned mask_offset;
  enum wsc_status last_status;
  bool fin;
  bool rsv1;
  bool rsv2;
  bool rsv3;
  bool masked;
  uint8_t opcode;
  uint8_t masking_key[WSC_MASKING_KEY_LENGTH];
  uint8_t header[WSC_HEADER_MAX];
};

[[noreturn]] void wsc_trap() {
  abort();
}

static int wsc_buffer_reserve(struct wsc_decoder *decoder, struct wsc_buffer *buffer,
                              size_t minimum_capacity) {
  (void)decoder;
  if (minimum_capacity <= buffer->capacity) {
    return 0;
  }
  size_t capacity = buffer->capacity ? buffer->capacity : WSC_BUFFER_INIT;
  while (capacity < minimum_capacity) {
    if (capacity > ((size_t)-1) / 2) {
      capacity = minimum_capacity;
      break;
    }
    capacity *= 2;
  }
  uint8_t *new_buffer = realloc(buffer->data, capacity);
  if (new_buffer == nullptr) {
    return -1;
  }
  buffer->data = new_buffer;
  buffer->capacity = capacity;
  return 0;
}

static void wsc_clear_frames(struct wsc_decoder *decoder) {
  for (size_t i = 0; i < decoder->frames_count; i++) {
    free((void *)decoder->frames[i].payload);
    decoder->frames[i].payload = nullptr;
  }
  decoder->frames_count = 0;
}

static int wsc_frames_reserve(struct wsc_decoder *decoder, size_t capacity) {
  if (capacity <= decoder->frames_capacity) {
    return -1;
  }
  if (capacity > ((size_t)-1) / sizeof(struct wsc_frame)) {
    return -1;
  }
  size_t bytes = capacity * sizeof(struct wsc_frame);
  struct wsc_frame *new_buffer = realloc(decoder->frames, bytes);
  if (new_buffer == nullptr) {
    return -1;
  }
  decoder->frames = new_buffer;
  decoder->frames_capacity = capacity;
  return 0;
}

static enum wsc_status wsc_attach_payload(struct wsc_decoder *decoder, struct wsc_frame *frame) {
  if (decoder->payload.data == nullptr) {
    wsc_trap();
  }
  uint8_t *copy = malloc(frame->payload_length);
  if (copy == nullptr) {
    return WSC_ERR_NO_MEMORY;
  }
  memcpy(copy, decoder->payload.data, frame->payload_length);
  frame->payload = copy;
  return WSC_OK;
}

static void wsc_discard_payload(struct wsc_frame *frame) {
  free((void *)frame->payload);
  frame->payload = nullptr;
}

static void wsc_payload_emitted(struct wsc_decoder *decoder) {
  (void)decoder;
}

static struct wsc_decoding_result make_result(struct wsc_decoder *decoder, size_t source_consumed,
                                              enum wsc_status status) {
  return (struct wsc_decoding_result){
      .status = status,
      .frames = decoder->frames_count ? decoder->frames : nullptr,
      .frames_count = decoder->frames_count,
      .source_consumed = source_consumed,
  };
}

static enum wsc_status fail(struct wsc_decoder *decoder, enum wsc_status status) {
  decoder->last_status = status;
  decoder->state = WSC_STATE_DEAD;
  return status;
}

static bool header_ready(const struct wsc_decoder *decoder) {
  return decoder->state == WSC_STATE_HEADER && decoder->header_received >= decoder->header_total &&
         decoder->header_total >= WSC_HEADER_BASE;
}

static bool payload_ready(const struct wsc_decoder *decoder) {
  return decoder->state == WSC_STATE_PAYLOAD &&
         decoder->payload_received >= decoder->payload_length;
}

static int frames_push(struct wsc_decoder *decoder, struct wsc_frame frame) {
  if (decoder->frames_count == decoder->frames_capacity) {
    size_t capacity = decoder->frames_capacity ? decoder->frames_capacity * 2 : WSC_FRAMES_INIT;
    if (wsc_frames_reserve(decoder, capacity) != 0) {
      return -1;
    }
  }
  decoder->frames[decoder->frames_count] = frame;
  decoder->frames_count++;
  return 0;
}

static enum wsc_status emit(struct wsc_decoder *decoder) {
  struct wsc_frame frame = {
      .payload = nullptr,
      .payload_length = (size_t)decoder->payload_length,
      .opcode = decoder->opcode,
      .fin = decoder->fin,
      .rsv1 = decoder->rsv1,
      .rsv2 = decoder->rsv2,
      .rsv3 = decoder->rsv3,
      .masked = decoder->masked,
  };
  memcpy(frame.masking_key, decoder->masking_key, WSC_MASKING_KEY_LENGTH);

  if (frame.payload_length > 0) {
    enum wsc_status status = wsc_attach_payload(decoder, &frame);
    if (status != WSC_OK) {
      return status;
    }
  }
  if (frames_push(decoder, frame) != 0) {
    wsc_discard_payload(&frame);
    return WSC_ERR_NO_MEMORY;
  }
  wsc_payload_emitted(decoder);
  decoder->payload.length = 0;
  return WSC_OK;
}

static void reset_header(struct wsc_decoder *decoder) {
  decoder->state = WSC_STATE_HEADER;
  decoder->header_received = 0;
  decoder->header_total = WSC_HEADER_BASE;
  decoder->payload_received = 0;
  decoder->mask_offset = 0;
}

static enum wsc_status on_header(struct wsc_decoder *decoder) {
  unsigned byte0 = decoder->header[0];
  unsigned byte1 = decoder->header[1];
  unsigned length7 = byte1 & WSC_LENGTH7_MASK;
  size_t offset = WSC_HEADER_BASE;
  uint64_t payload_length = 0;

  decoder->fin = (byte0 & WSC_FIN_BIT) != 0;
  decoder->rsv1 = (byte0 & WSC_RSV1_BIT) != 0;
  decoder->rsv2 = (byte0 & WSC_RSV2_BIT) != 0;
  decoder->rsv3 = (byte0 & WSC_RSV3_BIT) != 0;
  decoder->opcode = (uint8_t)(byte0 & WSC_OPCODE_MASK);
  decoder->masked = (byte1 & WSC_MASK_BIT) != 0;

  if (length7 == WSC_LENGTH16) {
    payload_length = read_uint16(decoder->header + WSC_HEADER_BASE);
    offset = WSC_HEADER_BASE + WSC_LENGTH16_EXT;
    if (payload_length <= WSC_LENGTH7_MAX) {
      return fail(decoder, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else if (length7 == WSC_LENGTH64) {
    payload_length = read_uint64(decoder->header + WSC_HEADER_BASE);
    offset = WSC_HEADER_BASE + WSC_LENGTH64_EXT;
    if ((payload_length & WSC_LENGTH64_MSB) != 0) {
      return fail(decoder, WSC_ERR_LENGTH64_MSB);
    }
    if (payload_length <= UINT16_MAX) {
      return fail(decoder, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else {
    payload_length = (uint64_t)length7;
  }

  if (decoder->masked) {
    memcpy(decoder->masking_key, decoder->header + offset, WSC_MASKING_KEY_LENGTH);
  } else {
    memset(decoder->masking_key, 0, WSC_MASKING_KEY_LENGTH);
  }

  if (payload_length > (uint64_t)(size_t)-1) {
    return WSC_ERR_NO_MEMORY;
  }

  decoder->payload_length = payload_length;
  decoder->payload_received = 0;
  decoder->mask_offset = 0;
  decoder->payload.length = 0;

  if (payload_length == 0) {
    enum wsc_status status = emit(decoder);
    if (status != WSC_OK) {
      return status;
    }
    reset_header(decoder);
    return WSC_OK;
  }

  if (wsc_buffer_reserve(decoder, &decoder->payload, (size_t)payload_length) != 0) {
    return WSC_ERR_NO_MEMORY;
  }
  decoder->state = WSC_STATE_PAYLOAD;
  return WSC_OK;
}

static enum wsc_status on_payload_done(struct wsc_decoder *decoder) {
  enum wsc_status status = emit(decoder);
  if (status != WSC_OK) {
    return status;
  }
  reset_header(decoder);
  return WSC_OK;
}

static enum wsc_status feed_header(struct wsc_decoder *decoder, const uint8_t *source,
                                   size_t length, size_t *used) {
  *used = 0;
  if (decoder->header_received < WSC_HEADER_BASE) {
    decoder->header_total = WSC_HEADER_BASE;
  }
  size_t take = decoder->header_total - decoder->header_received;
  if (take > length) {
    take = length;
  }
  memcpy(decoder->header + decoder->header_received, source, take);
  decoder->header_received += take;
  *used = take;
  if (decoder->header_received >= WSC_HEADER_BASE) {
    decoder->header_total = header_length(decoder->header[1]);
  }
  if (decoder->header_received < decoder->header_total) {
    return WSC_OK;
  }
  return on_header(decoder);
}

static enum wsc_status feed_payload(struct wsc_decoder *decoder, const uint8_t *source,
                                    size_t length, size_t *used) {
  uint64_t left = decoder->payload_length - decoder->payload_received;
  size_t take = length;
  if ((uint64_t)take > left) {
    take = (size_t)left;
  }
  if (take == 0) {
    *used = 0;
    return WSC_OK;
  }
  if (decoder->payload.data == nullptr) {
    wsc_trap();
  }
  memcpy(decoder->payload.data + decoder->payload.length, source, take);
  if (decoder->masked) {
    apply_mask(decoder->payload.data + decoder->payload.length, take, decoder->masking_key,
               decoder->mask_offset);
  }
  decoder->mask_offset = (decoder->mask_offset + (unsigned)take) & (WSC_MASKING_KEY_LENGTH - 1U);
  decoder->payload.length += take;
  decoder->payload_received += take;
  *used = take;
  if (decoder->payload_received >= decoder->payload_length) {
    return on_payload_done(decoder);
  }
  return WSC_OK;
}

static void wsc_decoder_state_init(struct wsc_decoder *decoder) {
  decoder->state = WSC_STATE_HEADER;
  decoder->header_total = WSC_HEADER_BASE;
}

static struct wsc_decoding_result wsc_decoder_feed_data(struct wsc_decoder *decoder,
                                                        const uint8_t *source, size_t length) {
  if (length > 0 && source == nullptr) {
    wsc_trap();
  }
  wsc_clear_frames(decoder);
  if (decoder->state == WSC_STATE_DEAD) {
    return make_result(decoder, 0, decoder->last_status);
  }

  enum wsc_status status = WSC_OK;
  if (payload_ready(decoder)) {
    status = on_payload_done(decoder);
    if (status != WSC_OK) {
      return make_result(decoder, 0, status);
    }
  } else if (header_ready(decoder)) {
    status = on_header(decoder);
    if (status != WSC_OK) {
      return make_result(decoder, 0, status);
    }
  }

  size_t offset = 0;
  while (offset < length && decoder->state != WSC_STATE_DEAD) {
    size_t used = 0;
    if (decoder->state == WSC_STATE_HEADER) {
      status = feed_header(decoder, source + offset, length - offset, &used);
    } else {
      status = feed_payload(decoder, source + offset, length - offset, &used);
    }
    offset += used;
    if (status != WSC_OK) {
      break;
    }
    if (used == 0) {
      break;
    }
  }
  return make_result(decoder, offset, status);
}

static void wsc_decoder_free(struct wsc_decoder *decoder) {
  wsc_clear_frames(decoder);
  free(decoder->frames);
  free(decoder->payload.data);
  decoder->frames = nullptr;
  decoder->payload.data = nullptr;
  decoder->payload.length = 0;
  decoder->payload.capacity = 0;
}

struct wsc_decoder *wsc_decoder_create() {
  struct wsc_decoder *decoder = calloc(1, sizeof(*decoder));
  if (decoder == nullptr) {
    return nullptr;
  }
  wsc_decoder_state_init(decoder);
  return decoder;
}

struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame) {
  struct wsc_encoding_result result = {.status = WSC_OK};
  size_t total = wsc_encoded_frame_length(frame);

  result.data_length = total;
  result.data = malloc(total);
  if (result.data == nullptr) {
    result.status = WSC_ERR_NO_MEMORY;
    result.data_length = 0;
    return result;
  }
  wsc_encode_buffer(result.data, total, frame);
  return result;
}

void wsc_decoder_destroy(struct wsc_decoder *decoder) {
  if (decoder == nullptr) {
    return;
  }
  wsc_decoder_free(decoder);
  free(decoder);
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t length) {
  if (decoder == nullptr) {
    wsc_trap();
  }
  struct wsc_decoding_result result = wsc_decoder_feed_data(decoder, source, length);
  decoder->frames = nullptr;
  decoder->frames_count = 0;
  decoder->frames_capacity = 0;
  return result;
}

void wsc_decoding_result_free(struct wsc_decoding_result result) {
  if (result.frames == nullptr) {
    return;
  }
  for (size_t i = 0; i < result.frames_count; i++) {
    free((void *)result.frames[i].payload);
  }
  free((void *)result.frames);
}
