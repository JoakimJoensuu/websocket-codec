#ifndef BUG_H
#define BUG_H

/**
 * Abort unless @p ok.
 */

#include <stdbool.h>
#include <stdlib.h>

#define bug(ok)                                                                \
  do {                                                                         \
    if ((bool)(ok) == false) {                                                 \
      abort();                                                                 \
    }                                                                          \
  } while (0)

#endif
