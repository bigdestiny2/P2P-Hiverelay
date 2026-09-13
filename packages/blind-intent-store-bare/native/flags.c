// Compile and run on the target. Never substitute literal platform flag values.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stdio.h>

#if defined(__APPLE__)
#define PLATFORM "darwin"
#elif defined(__linux__)
#define PLATFORM "linux"
#else
#error Unsupported platform
#endif
#if defined(__aarch64__) || defined(__arm64__)
#define ARCH "arm64"
#elif defined(__x86_64__)
#define ARCH "x64"
#else
#error Unsupported architecture
#endif
#if !defined(O_EXCL) || !defined(O_NOFOLLOW) || !defined(O_DIRECTORY) || !defined(O_NONBLOCK)
#error Required file custody flags unavailable
#endif
_Static_assert(O_EXCL != 0 && O_NOFOLLOW != 0 && O_DIRECTORY != 0 && O_NONBLOCK != 0, "Safety flags must be nonzero");

int main(void) {
  printf("{\"platform\":\"%s\",\"arch\":\"%s\",\"constants\":{\"O_RDONLY\":%d,\"O_WRONLY\":%d,\"O_RDWR\":%d,\"O_CREAT\":%d,\"O_EXCL\":%d,\"O_NOFOLLOW\":%d,\"O_DIRECTORY\":%d,\"O_NONBLOCK\":%d}}\n",
    PLATFORM, ARCH, O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK);
  return 0;
}
