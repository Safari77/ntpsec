/*
 * Copyright the NTPsec project contributors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#if !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<features.h>)
#include <features.h>
#endif
#endif

/* getrandom() needs both a Linux kernel and a libc that ships
 * <sys/random.h> (glibc >= 2.25; musl and others expose it too, detected
 * via __has_include). Old kernels are still handled at runtime via ENOSYS. */
#if defined(__linux__)
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
#include <sys/random.h>
#define USE_SYS_GETRANDOM 1
#endif
#elif defined(__has_include)
#if __has_include(<sys/random.h>)
#include <sys/random.h>
#define USE_SYS_GETRANDOM 1
#endif
#endif
#endif

#include "config.h"
#include "ntp.h"
#include "ntp_stdlib.h"
#include "ntp_syslog.h"

/** Fill a buffer with random data
 * \param buf a buffer to fill
 * \param buflen the number of bytes to fill; must not exceed SSIZE_MAX
 * \return the number of bytes filled (always == \a buflen)
 *
 * Fill \a buf with \a buflen random bytes.
 *
 * On any failure to obtain randomness (or if \a buflen > SSIZE_MAX) this
 * function calls abort() rather than returning an error, so a successful
 * return always means the buffer is fully filled.
 */
void
ntp_random_buf (void* buf, size_t buflen)
{
    size_t total_read = 0;
    char* ptr = (char*)buf;

    // Reject requests whose success value would not fit in ssize_t; reads
    // larger than SSIZE_MAX are implementation-defined in POSIX anyway.
    if (buflen > (size_t)SSIZE_MAX) {
        msyslog(LOG_ERR, "ERR: ntp_random_buf request for %zu bytes\n", buflen);
        exit(1);
    }
#ifdef USE_SYS_GETRANDOM
    // Cache the "kernel too old" result so we do not pay a failing syscall
    // on every call.
    static int getrandom_unsupported = 0;
    if (!__atomic_load_n(&getrandom_unsupported, __ATOMIC_RELAXED)) {
        while (total_read < buflen) {
            ssize_t res = getrandom(ptr + total_read, buflen - total_read, 0);
            if (res < 0) {
                if (errno == EINTR) continue;
                if (errno == ENOSYS && total_read == 0) {
                    // System kernel too old, remember that and fall back to
                    // /dev/urandom
                    __atomic_store_n(&getrandom_unsupported, 1,
                                     __ATOMIC_RELAXED);
                    break;
                }
                msyslog(LOG_ERR, "ERR: getrandom returned %s\n", strerror(errno));
                exit(1);
            }
            total_read += res;
        }
        if (total_read == buflen) return;
    }
#endif
    // Fallback: Lazy-load and cache the /dev/urandom file descriptor.
    // Note: the cached descriptor is not fork-safe in the sense that a child
    // which closes "all" descriptors (daemonization) will leave it stale.
    static int cached_fd = -1;
    int fd = __atomic_load_n(&cached_fd, __ATOMIC_RELAXED);
    if (fd < 0) {
        int new_fd = open("/dev/urandom", O_RDONLY | O_NOCTTY | O_CLOEXEC);
        if (new_fd < 0) {
            msyslog(LOG_ERR, "ERR: failed to open /dev/urandom: %s\n", strerror(errno));
            exit(1);
        }
        int expected = -1;
        // Use atomic swap to prevent descriptor leaks if multiple threads hit
        // this at once
        if (__atomic_compare_exchange_n(&cached_fd, &expected, new_fd, 0,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            fd = new_fd;
        } else {
            // Another thread initialized it first
            close(new_fd);
            fd = expected;
        }
    }
    while (total_read < buflen) {
        ssize_t res = read(fd, ptr + total_read, buflen - total_read);
        if (res < 0) {
            if (errno == EINTR) continue;
            msyslog(LOG_ERR, "ERR: failed to read /dev/urandom: %s\n", strerror(errno));
            exit(1);
        }
        if (res == 0) {
            msyslog(LOG_ERR, "ERR: /dev/urandom read returned 0\n");
            exit(1);
        }
        total_read += res;
    }
    return;
}

uint32_t ntp_random_u32(void)
{
	uint32_t ret;

	ntp_random_buf(&ret, sizeof(ret));
	return ret;
}

uint64_t ntp_random_u64(void)
{
	uint64_t ret;

	ntp_random_buf(&ret, sizeof(ret));
	return ret;
}
