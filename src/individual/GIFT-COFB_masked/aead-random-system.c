/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * This file obtains random seed data (or entropy) from the underlying
 * system to seed application PRNG implementations.
 *
 * Each time aead_random_get_system_seed() is called, it should provide
 * 256 bits / 32 bytes of seed data.  The PRNG will then expand that
 * seed into an arbitrary amount of random output.
 *
 * If your operating system has an equivalent to Linux's /dev/urandom,
 * then add support for it to aead_random_get_system_seed() below.
 *
 * If your CPU has a special instruction or peripheral register that
 * generates TRNG output, then define the macros aead_system_random() and
 * aead_system_random_init() below to access your TRNG source.
 */

#define _GNU_SOURCE
#include "aead-random.h"
#include "internal-util.h"
#include <string.h>
#if defined(ARDUINO)
#include <Arduino.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__MACH__) || \
    defined(__FreeBSD__) || defined(__unix__) || defined(__ANDROID__)
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define AEAD_TRNG_UNIX_LIKE 1
#endif

/* Determine if we have a CPU random number generator that can generate
 * raw 32-bit or 64-bit values.  Modify this to add support for new CPU's */
#if defined(__x86_64) || defined(__x86_64__)
/* Assume that we have the RDRAND instruction on x86-64 platforms */
#define aead_system_random_init() do { ; } while (0)
#define aead_system_random(var, ready) \
    do { \
        uint64_t temp = 0; \
        uint8_t ok = 0; \
        do { \
            __asm__ __volatile__ ( \
                ".byte 0x48,0x0f,0xc7,0xf0 ; setc %1" \
                : "=a"(temp), "=q"(ok) :: "cc" \
            ); \
        } while (!ok); \
        (var) = temp; \
    } while (0)
#define aead_system_type uint64_t
#endif
#if defined (__arm__) && defined (__SAM3X8E__) && defined(ARDUINO)
/* Arduino Due */
#define aead_system_random_init() \
    do { \
        static int done = 0; \
        if (!done) { \
            pmc_enable_periph_clk(ID_TRNG); \
            REG_TRNG_CR = TRNG_CR_KEY(0x524E47) | TRNG_CR_ENABLE; \
            REG_TRNG_IDR = TRNG_IDR_DATRDY; \
            done = 1; \
        } \
    } while (0)
/* SAM3X8E's TRNG returns a new random word every 84 clock cycles.
 * If the TRNG is not ready after 100 iterations, assume it has failed. */
#define aead_system_random(var, ready) \
    do { \
        int count = 100; \
        while ((REG_TRNG_ISR & TRNG_ISR_DATRDY) == 0) { \
            if ((--count) <= 0) { \
                (ready) = 0;  \
                break; \
            } \
        } \
        (var) = REG_TRNG_ODATA; \
    } while (0)
#endif
#if defined(ESP8266)
#define aead_system_random_init() do { ; } while (0)
#define aead_system_random(var, ready) ((var) = *((volatile int *)0x3FF20E44))
#endif
#if defined(ESP32)
extern uint32_t esp_random(void);
#define aead_system_random_init() do { ; } while (0)
#define aead_system_random(var, ready) ((var) = esp_random())
#endif
#if !defined(aead_system_type) && defined(aead_system_random)
#define aead_system_type uint32_t
#endif

/* Determine if we have /dev/urandom, /dev/random, or a similar device */
#if defined(AEAD_TRNG_UNIX_LIKE)
#define aead_random_device "/dev/urandom"
#define aead_random_device_backup "/dev/random"
#endif

int aead_random_get_system_seed(unsigned char seed[AEAD_SYSTEM_SEED_SIZE])
{
#if defined(aead_random_device)
    /* We prefer to use getrandom() or /dev/urandom because it will have
     * access to more entropy sources than just RDRAND or similar */
#if defined(SYS_getrandom)
    /* Use the getrandom() system call to seed the PRNG if we have it.
     * Keep looping until we get some data or a permanent error. */
    for (;;) {
        int ret = syscall(SYS_getrandom, seed, 32, 0);
        if (ret == 32) {
            return 1;
        } else if (ret < 0) {
            if (errno != EINTR && errno != EAGAIN)
                break;
        }
    }
#endif
    {
        /* Use /dev/urandom to seed the PRNG.  If for some reason that fails,
         * then fall back to RDRAND or the current system time. */
        int fd = open(aead_random_device, O_RDONLY);
#if defined(aead_random_device_backup)
        if (fd < 0)
            fd = open(aead_random_device_backup, O_RDONLY);
#endif
        if (fd >= 0) {
            for (;;) {
                int ret = read(fd, seed, 32);
                if (ret == 32) {
                    close(fd);
                    return 1;
                } else if (ret < 0) {
                    if (errno != EINTR && errno != EAGAIN)
                        break;
                }
            }
            close(fd);
        }
#if defined(aead_system_random)
        /* We have RDRAND or similar, so try using that to seed the PRNG */
        {
            aead_system_type x;
            int index;
            int ready = 1;
            aead_system_random_init();
            for (index = 0; index < AEAD_SYSTEM_SEED_SIZE; index += sizeof(x)) {
                aead_system_random(x, ready);
                memcpy(seed + index, &x, sizeof(x));
            }
            return ready;
        }
#endif
        /* Last ditch is to use the system time.  This is not ideal */
        {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            if (sizeof(tv) <= AEAD_SYSTEM_SEED_SIZE) {
                memcpy(seed, &tv, sizeof(tv));
                memset(seed + sizeof(tv), 0,
                       AEAD_SYSTEM_SEED_SIZE - sizeof(tv));
            } else {
                memcpy(seed, &tv, AEAD_SYSTEM_SEED_SIZE);
            }
        }
        return 0; /* Not properly seeded */
    }
#elif defined(aead_system_random)
    aead_system_type x;
    int index;
    int ready = 1;
    aead_system_random_init();
    for (index = 0; index < AEAD_SYSTEM_SEED_SIZE; index += sizeof(x)) {
        aead_system_random(x, ready);
        memcpy(seed + index, &x, sizeof(x));
    }
    return ready;
#else
    #warning "No system random number source found"

    /* No random source.  Try to be safe and return something that is
     * different every time this function is called.  The sequence will
     * repeat upon the next restart, but it will generate unique values
     * each time as long as the code is running.  This may be OK for
     * generating password salts, but not session key material. */
    static uint64_t counter = 0;
    ++counter;
    memcpy(seed, &counter, sizeof(counter));
    memset(seed + sizeof(counter), 0, AEAD_SYSTEM_SEED_SIZE - sizeof(counter));

#if defined(ARDUINO)
    /* Add the current Arduino time as a seed to provide some extra jitter */
    {
        unsigned long x = millis();
        memcpy(seed + AEAD_SYSTEM_SEED_SIZE - sizeof(x), &x, sizeof(x));
        x = micros();
        memcpy(seed + AEAD_SYSTEM_SEED_SIZE - sizeof(x) * 2, &x, sizeof(x));
    }
#endif

    /* We don't know how to obtain system seed data on this platform */
    return 0;
#endif
}
