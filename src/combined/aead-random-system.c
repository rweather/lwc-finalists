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
#elif defined(_WIN32) || defined(__WIN32__) || defined(_WIN64) || \
    defined(__CYGWIN__) || defined(__CYGWIN32__)
#include <windows.h>
#include <wincrypt.h>
#define AEAD_TRNG_WINDOWS 1
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
#elif defined(USE_HAL_DRIVER)
/* STM32 platform with the HAL libraries.  Try to detect the chip family.
 * Unfortunately there is no single define for "STM32 with an RNG".
 * Patches welcome to extend this list to new STM32 platforms.
 *
 * For each chip family we link to the .h file that contains the
 * up to date list of #define's for that family.  Some of them
 * don't have an RNG which will be caught later when we check for
 * the HAL_RNG_MODULE_ENABLED define.  It is easier to list
 * everything and not risk missing one.
 *
 * The list of defines for each family will need to be updated periodically. */
/* https://github.com/STMicroelectronics/STM32CubeF2/blob/master/Drivers/CMSIS/Device/ST/STM32F2xx/Include/stm32f2xx.h */
#if defined(STM32F205xx) || defined(STM32F215xx) || defined(STM32F207xx) || \
    defined(STM32F217xx)
#include "stm32f2xx_hal.h"
#define AEAD_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeF4/blob/master/Drivers/CMSIS/Device/ST/STM32F4xx/Include/stm32f4xx.h */
#elif defined(STM32F405xx) || defined(STM32F415xx) || defined(STM32F415xx) || \
      defined(STM32F417xx) || defined(STM32F427xx) || defined(STM32F437xx) || \
      defined(STM32F429xx) || defined(STM32F439xx) || defined(STM32F401xC) || \
      defined(STM32F401xE) || defined(STM32F410Tx) || defined(STM32F410Cx) || \
      defined(STM32F410Rx) || defined(STM32F411xE) || defined(STM32F446xx) || \
      defined(STM32F469xx) || defined(STM32F479xx) || defined(STM32F412Cx) || \
      defined(STM32F412Zx) || defined(STM32F412Rx) || defined(STM32F412Vx) || \
      defined(STM32F413xx) || defined(STM32F413xx)
#include "stm32f4xx_hal.h"
#define AEAD_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeF7/blob/master/Drivers/CMSIS/Device/ST/STM32F7xx/Include/stm32f7xx.h */
#elif defined(STM32F722xx) || defined(STM32F723xx) || defined(STM32F732xx) || \
      defined(STM32F733xx) || defined(STM32F756xx) || defined(STM32F746xx) || \
      defined(STM32F745xx) || defined(STM32F765xx) || defined(STM32F767xx) || \
      defined(STM32F769xx) || defined(STM32F777xx) || defined(STM32F779xx) || \
      defined(STM32F730xx) || defined(STM32F750xx)
#include "stm32f7xx_hal.h"
#define AEAD_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeG0/blob/master/Drivers/CMSIS/Device/ST/STM32G0xx/Include/stm32g0xx.h */
#elif defined(STM32G0B1xx) || defined(STM32G0C1xx) || defined(STM32G0B0xx) || \
      defined(STM32G071xx) || defined(STM32G081xx) || defined(STM32G070xx) || \
      defined(STM32G031xx) || defined(STM32G041xx) || defined(STM32G030xx) || \
      defined(STM32G051xx) || defined(STM32G061xx) || defined(STM32G050xx)
#include "stm32g0xx_hal.h"
#define AEAD_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeG4/blob/master/Drivers/CMSIS/Device/ST/STM32G4xx/Include/stm32g4xx.h */
#elif defined(STM32G431xx) || defined(STM32G441xx) || defined(STM32G471xx) || \
      defined(STM32G473xx) || defined(STM32G483xx) || defined(STM32G474xx) || \
      defined(STM32G484xx) || defined(STM32G491xx) || defined(STM32G4A1xx) || \
      defined(STM32GBK1CB)
#include "stm32g4xx_hal.h"
#define AEAD_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeH7/blob/master/Drivers/CMSIS/Device/ST/STM32H7xx/Include/stm32h7xx.h */
#elif defined(STM32H743xx) || defined(STM32H753xx) || defined(STM32H750xx) || \
      defined(STM32H742xx) || defined(STM32H745xx) || defined(STM32H755xx) || \
      defined(STM32H747xx) || defined(STM32H757xx) || defined(STM32H7B0xx) || \
      defined(STM32H7B0xxQ) || defined(STM32H7A3xx) || defined(STM32H7B3xx) || \
      defined(STM32H7A3xxQ) || defined(STM32H7B3xxQ) || defined(STM32H735xx) || \
      defined(STM32H733xx) || defined(STM32H730xx) || defined(STM32H730xxQ) || \
      defined(STM32H725xx) || defined(STM32H723xx)
#include "stm32h7xx_hal.h"
#define AEAD_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeL0/blob/master/Drivers/CMSIS/Device/ST/STM32L0xx/Include/stm32l0xx.h */
#elif defined(STM32L010xB) || defined(STM32L010x8) || defined(STM32L010x6) || \
      defined(STM32L010x4) || defined(STM32L011xx) || defined(STM32L021xx) || \
      defined(STM32L031xx) || defined(STM32L041xx) || defined(STM32L051xx) || \
      defined(STM32L052xx) || defined(STM32L053xx) || defined(STM32L062xx) || \
      defined(STM32L063xx) || defined(STM32L071xx) || defined(STM32L072xx) || \
      defined(STM32L073xx) || defined(STM32L082xx) || defined(STM32L083xx) || \
      defined(STM32L081xx)
#include "stm32l0xx_hal.h"
#define AEAD_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeL4/blob/master/Drivers/CMSIS/Device/ST/STM32L4xx/Include/stm32l4xx.h */
#elif defined(STM32L412xx) || defined(STM32L422xx) || defined(STM32L431xx) || \
      defined(STM32L432xx) || defined(STM32L433xx) || defined(STM32L442xx) || \
      defined(STM32L443xx) || defined(STM32L451xx) || defined(STM32L452xx) || \
      defined(STM32L462xx) || defined(STM32L471xx) || defined(STM32L475xx) || \
      defined(STM32L476xx) || defined(STM32L485xx) || defined(STM32L486xx) || \
      defined(STM32L496xx) || defined(STM32L4A6xx) || defined(STM32L4P5xx) || \
      defined(STM32L4Q5xx) || defined(STM32L4R5xx) || defined(STM32L4R7xx) || \
      defined(STM32L4R9xx) || defined(STM32L4S5xx) || defined(STM32L4S7xx) || \
      defined(STM32L4S9xx)
#include "stm32l4xx_hal.h"
#define AEAD_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeL5/blob/master/Drivers/CMSIS/Device/ST/STM32L5xx/Include/stm32l5xx.h */
#elif defined(STM32L552xx) || defined(STM32L562xx)
#include "stm32l5xx_hal.h"
#define AEAD_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeWB/blob/master/Drivers/CMSIS/Device/ST/STM32WBxx/Include/stm32wbxx.h */
#elif defined(STM32WB55xx) || defined(STM32WB5Mxx) || defined(STM32WB50xx) || \
      defined(STM32WB35xx) || defined(STM32WB30xx) || defined(STM32WB15xx) || \
      defined(STM32WB10xx)
#include "stm32wbxx_hal.h"
/* https://github.com/STMicroelectronics/STM32CubeWL/blob/main/Drivers/CMSIS/Device/ST/STM32WLxx/Include/stm32wlxx.h */
#elif defined(STM32WL55xx) || defined(STM32WLE5xx) || defined(STM32WL54xx) || \
      defined(STM32WLE4xx)
#include "stm32wlxx_hal.h"
#define AEAD_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeMP1/blob/master/Drivers/CMSIS/Device/ST/STM32MP1xx/Include/stm32mp1xx.h */
#elif defined(STM32MP15xx) || defined(STM32MP157Axx) || \
      defined(STM32MP157Cxx) || defined(STM32MP157Dxx) || \
      defined(STM32MP157Fxx) || defined(STM32MP153Axx) || \
      defined(STM32MP153Cxx) || defined(STM32MP153Dxx) || \
      defined(STM32MP153Fxx) || defined(STM32MP151Axx) || \
      defined(STM32MP151Cxx) || defined(STM32MP151Dxx) || \
      defined(STM32MP151Fxx)
#include "stm32mp1xx_hal.h"
#define AEAD_TRNG_STM32 hrng1 /* MP1 series has two RNG's, use the first one */
#endif
#if defined(HAL_RNG_MODULE_ENABLED)
/* Declare the object that STM32Cube created for us to hold the RNG state */
extern RNG_HandleTypeDef AEAD_TRNG_STM32;
#else
/* Using HAL libraries on STM32, but the RNG has not been selected
 * in the configuration.  Use STM32Cube to fix this and recompile. */
#warning "STM32 HAL configuration has not enabled the RNG"
#undef AEAD_TRNG_STM32
#endif /* End of STM32 RNG detection */
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
#if defined(AEAD_TRNG_STM32)
#define aead_system_random_init() do { ; } while (0)
#define aead_system_random(var, ready) \
    do { \
        if (HAL_RNG_GenerateRandomNumber(&AEAD_TRNG_STM32, &(var)) != HAL_OK) \
            (ready) = 0; \
    } while (0)
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
#elif defined(AEAD_TRNG_WINDOWS)
    /* Microsoft documentation recommends using RtlGenRandom() rather
     * than CryptGenRandom() as it is more efficient than creating a
     * cryptography service provider.  But it is harder to access as
     * there is no import library.  Fix this later to dynamically load
     * "Advapi32.dll" and resolve the entry point for RtlGenRandom(). */
    HCRYPTPROV provider = 0;
    memset(seed, 0, AEAD_SYSTEM_SEED_SIZE);
    if (CryptAcquireContextW
            (&provider, 0, 0, PROV_RSA_FULL,
             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        BOOL result = CryptGenRandom(provider, AEAD_SYSTEM_SEED_SIZE, seed);
        CryptReleaseContext(provider, 0);
        return result;
    }
    return 0;
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
#if defined(USE_HAL_DRIVER)
    /* Mix in the STM32 millisecond tick counter for some extra jitter */
    {
        uint32_t x = HAL_GetTick();
        memcpy(seed + AEAD_SYSTEM_SEED_SIZE - sizeof(x), &x, sizeof(x));
    }
#endif

    /* We don't know how to obtain system seed data on this platform */
    return 0;
#endif
}
