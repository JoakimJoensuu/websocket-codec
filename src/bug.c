#include "bug.h"

#include <stdlib.h>

void bug(bool valid) {
  if (valid) {
    return;
  }
  abort();
}
