#include <cstring>

#include "explore_me.h"
#include "utils.h"

static long insecureEncrypt(long input);
static void trigger_global_buffer_overflow(const std::string &c);
static void trigger_use_after_free();

void ExploreSimpleChecks(int a, int b, std::string c) {
  if (a >= 20000) {
    if (b >= 2000000) {
      if (b - a < 100000) {
        if (c == "Attacker") {
          trigger_global_buffer_overflow(c);
        }
      }
    }
  }
}

void ExploreComplexChecks(long a, long b, std::string c) {
  if (EncodeBase64(c) == "SGV5LCB3ZWw=") {
    if (insecureEncrypt(a) == 0x4e9e91e6677cfff3L) {
      if (insecureEncrypt(b) == 0x4f8b9fb34431d9d3L) {
        trigger_use_after_free();
      }
    }
  }
}

static long insecureEncrypt(long input) {
  long key = 0xefe4eb93215cb6b0L;
  return input ^ key;
}

char gBuffer[5] = {0};

/*
 * Complete replacement of the provided snippet with a production-safe implementation.
 * Assumptions:
 *  - gBuffer is a global fixed-size character buffer declared elsewhere.
 *  - We can determine its capacity at compile time if it is an array in this TU.
 * If gBuffer is a pointer (e.g., char*), you must also provide/track its allocated size.
 */

#include &lt;algorithm>
#include &lt;cstdio>
#include &lt;cstring>
#include &lt;string>

// FIX: Safely copy into gBuffer with bounds checking and guaranteed NUL termination.
// NOTE: This requires gBuffer to be a real array in this translation unit.
extern char gBuffer[]; // declared elsewhere

static void trigger_global_buffer_overflow(const std::string &c) {
  // FIX: Determine buffer capacity safely.
  // If gBuffer is not an array in this TU, sizeof(gBuffer) will be wrong.
  // In that case, refactor to pass the buffer size explicitly.
  const std::size_t cap = sizeof(gBuffer);

  if (cap == 0) {
    // Nothing we can do safely.
    return;
  }

  // FIX: Copy at most cap-1 bytes and NUL-terminate.
  const std::size_t n = std::min(c.size(), cap - 1);
  if (n > 0) {
    std::memcpy(gBuffer, c.data(), n);
  }
  gBuffer[n] = '\0';

  // FIX: Safe because gBuffer is guaranteed NUL-terminated.
  std::printf("%s\n", gBuffer);
}

/*
Why this fix is secure/correct:
- Prevents write out-of-bounds by limiting the copy to the destination capacity (cap-1).
- Ensures NUL termination so printf("%s") cannot read past the buffer.
- Uses c.data()/c.size() (safe for binary data) and explicit termination.
*/

static void trigger_use_after_free() {
  auto *buffer = static_cast<char *>(malloc(6));
  memcpy(buffer, "hello", 5);
  buffer[5] = '\0';
  free(buffer);
  printf("%s\n", buffer);
}