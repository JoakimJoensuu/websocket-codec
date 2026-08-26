#ifndef WSC_H
#define WSC_H

/**
 * Encode and decode one WebSocket frame (RFC 6455 sections 5.2-5.3).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum : int {
  WSC_VERSION_MAJOR = 0,
  WSC_VERSION_MINOR = 1,
  WSC_VERSION_PATCH = 0,
};

enum : unsigned { WSC_MASK_LEN = 4 };

enum wsc_opcode : uint8_t {
  WSC_OP_CONT  = 0x0,
  WSC_OP_TEXT  = 0x1,
  WSC_OP_BIN   = 0x2,
  WSC_OP_CLOSE = 0x8,
  WSC_OP_PING  = 0x9,
  WSC_OP_PONG  = 0xA,
};

enum wsc_err {
  WSC_OK             = 0,
  WSC_ERR_NOMEM      = -1,
  WSC_ERR_NONMINIMAL = -2,
  WSC_ERR_LEN64_MSB  = -3,
};

struct wsc_frame {
  const uint8_t *payload;
  size_t payload_len;
  uint8_t mask_key[WSC_MASK_LEN];
  uint8_t opcode;
  bool fin;
  bool rsv1;
  bool rsv2;
  bool rsv3;
  bool masked;
};

struct wsc_result {
  enum wsc_err err;
  const struct wsc_frame *frames;
  size_t frames_cnt;
};

struct wsc_dec;

/** @return Heap decoder, or nullptr on OOM. */
struct wsc_dec *wsc_dec_create();

/**
 * @param dec May be nullptr.
 */
void wsc_dec_destroy(struct wsc_dec *dec);

size_t wsc_encoded_len(const struct wsc_frame *frame);

/**
 * Write one frame into @p dst.
 *
 * @p dst_cap must be at least wsc_encoded_len(@p frame). If @c frame->masked,
 * the payload is masked with @c frame->mask_key; otherwise it is not masked.
 */
size_t wsc_encode(uint8_t *dst, size_t dst_cap, const struct wsc_frame *frame);

/**
 * Parse @p src. Incomplete frames stay in the decoder.
 *
 * Completed frames are copied and unmasked. They are valid until the next
 * wsc_dec_feed or wsc_dec_destroy.
 */
struct wsc_result wsc_dec_feed(struct wsc_dec *dec, const uint8_t *src, size_t length);

#endif /* WSC_H */
