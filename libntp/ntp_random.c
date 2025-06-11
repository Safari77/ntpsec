/*
 * Copyright the NTPsec project contributors
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <string.h>

#if !defined(__linux__) || !defined(__NR_getrandom)
#  error required linux and getrandom
#endif

#include "config.h"
#include "ntp.h"
#include "ntp_stdlib.h"
#include "ntp_syslog.h"

void
ntp_random_buf (void* out, size_t len)
{
        if (len > 256) {
                msyslog(LOG_ERR, "ERR: ntp_random_buf requested for %zu bytes\n", len);
                exit(1);
        }
        if (getrandom(out, len, 0) != (ssize_t)len) {
                msyslog(LOG_ERR, "ERR: ntp_random_buf failed: %s\n", strerror(errno));
                exit(1);
        }
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
