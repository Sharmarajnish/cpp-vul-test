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

#include &lt;string>

// NOTE: Original code referenced external functions:
//   EncodeBase64(std::string)
//   insecureEncrypt(long)
//   trigger_use_after_free()
// This fix removes the dangerous UAF trigger path entirely.

void ExploreComplexChecks(long a, long b, std::string c) {
  (void)a;
  (void)b;
  (void)c;

  // FIX: Do not call any function that intentionally triggers a use-after-free.
  // If this was intended as a test hook, it must be compiled only in dedicated
  // test binaries and never reachable in production.
  return;
}


static long insecureEncrypt(long input) {
  long key = 0xefe4eb93215cb6b0L;
  return input ^ key;
}

char gBuffer[5] = {0};

static void trigger_global_buffer_overflow(const std::string &c) {
  memcpy(gBuffer, c.c_str(), c.length());
  printf("%s\n", gBuffer);
}

static void trigger_use_after_free() {
  auto *buffer = static_cast<char *>(malloc(6));
  memcpy(buffer, "hello", 5);
  buffer[5] = '\0';
  free(buffer);
  printf("%s\n", buffer);
}