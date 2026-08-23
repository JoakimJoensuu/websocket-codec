#include "utf8.h"

#include <stddef.h>
#include <stdint.h>

/* RFC 3629 §3 well-formed UTF-8 byte sequences. */
enum : uint8_t {
  U0000_U007F_MAX = 0x7F,

  U0080_U07FF_FIRST_MIN = 0xC2,
  U0080_U07FF_FIRST_MAX = 0xDF,

  U0800_U0FFF_FIRST = 0xE0,
  U0800_U0FFF_SECOND_MIN = 0xA0,

  U1000_UCFFF_FIRST_MIN = 0xE1,
  U1000_UCFFF_FIRST_MAX = 0xEC,

  UD000_UD7FF_FIRST = 0xED,
  UD000_UD7FF_SECOND_MAX = 0x9F,

  UE000_UFFFF_FIRST_MIN = 0xEE,
  UE000_UFFFF_FIRST_MAX = 0xEF,

  U10000_U3FFFF_FIRST = 0xF0,
  U10000_U3FFFF_SECOND_MIN = 0x90,

  U40000_UFFFFF_FIRST_MIN = 0xF1,
  U40000_UFFFFF_FIRST_MAX = 0xF3,

  U100000_U10FFFF_FIRST = 0xF4,
  U100000_U10FFFF_SECOND_MAX = 0x8F,

  CONT_MIN = 0x80,
  CONT_MAX = 0xBF,
};

enum : int {
  REST_U0080_U07FF = 1,
  REST_U0800_UFFFF = 2,
  REST_U10000_U10FFFF = 3,
};

static const struct {
  uint8_t first_min;
  uint8_t first_max;
  uint8_t second_min;
  uint8_t second_max;
  int rest;
} well_formed[] = {
    {U0080_U07FF_FIRST_MIN, U0080_U07FF_FIRST_MAX, CONT_MIN, CONT_MAX,
     REST_U0080_U07FF,
    },
    {U0800_U0FFF_FIRST, U0800_U0FFF_FIRST, U0800_U0FFF_SECOND_MIN, CONT_MAX,
     REST_U0800_UFFFF,
    },
    {U1000_UCFFF_FIRST_MIN, U1000_UCFFF_FIRST_MAX, CONT_MIN, CONT_MAX,
     REST_U0800_UFFFF,
    },
    {UD000_UD7FF_FIRST, UD000_UD7FF_FIRST, CONT_MIN, UD000_UD7FF_SECOND_MAX,
     REST_U0800_UFFFF,
    },
    {UE000_UFFFF_FIRST_MIN, UE000_UFFFF_FIRST_MAX, CONT_MIN, CONT_MAX,
     REST_U0800_UFFFF,
    },
    {U10000_U3FFFF_FIRST, U10000_U3FFFF_FIRST, U10000_U3FFFF_SECOND_MIN,
     CONT_MAX, REST_U10000_U10FFFF,
    },
    {U40000_UFFFFF_FIRST_MIN, U40000_UFFFFF_FIRST_MAX, CONT_MIN, CONT_MAX,
     REST_U10000_U10FFFF,
    },
    {U100000_U10FFFF_FIRST, U100000_U10FFFF_FIRST, CONT_MIN,
     U100000_U10FFFF_SECOND_MAX, REST_U10000_U10FFFF,
    },
};

void utf8_init(utf8 *state) {
  state->need = 0;
  state->next_min = 0;
  state->next_max = 0;
}

static int feed_byte(utf8 *state, unsigned byte) {
  if (state->need == 0) {
    if (byte <= U0000_U007F_MAX) {
      return 0;
    }
    for (size_t row = 0; row < sizeof well_formed / sizeof well_formed[0];
         row++) {
      if (byte >= well_formed[row].first_min &&
          byte <= well_formed[row].first_max) {
        state->need = well_formed[row].rest;
        state->next_min = well_formed[row].second_min;
        state->next_max = well_formed[row].second_max;
        return 0;
      }
    }
    return -1;
  }

  if (byte < state->next_min || byte > state->next_max) {
    return -1;
  }
  state->need--;
  if (state->need > 0) {
    state->next_min = CONT_MIN;
    state->next_max = CONT_MAX;
  }
  return 0;
}

int utf8_feed(utf8 *state, const uint8_t *src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (feed_byte(state, src[i]) != 0) {
      return -1;
    }
  }
  return 0;
}

int utf8_finish(const utf8 *state) { return state->need == 0 ? 0 : -1; }
