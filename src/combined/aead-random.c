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
#if (defined(__x86_64) || defined(__x86_64__)) && defined(__RDRND__)
/* Assume that we have the RDRAND instruction on x86-64 platforms */
#include <immintrin.h> /* For _rdrand64_step() */
#define aead_system_random_init() do { ; } while (0)
#define aead_system_random(var, ready) \
    do { \
        unsigned long long temp = 0; \
        int count = 20; \
        do { \
            if (_rdrand64_step(&temp)) \
                break; \
        } while ((--count) > 0); \
        (var) = temp; \
    } while (0)
#define aead_system_type uint64_t
#endif
#if defined (__arm__) && defined (__SAM3X8E__) && defined(ARDUINO)
/* Arduino Due */
static int aead_system_random_init_done = 0;
#define aead_system_random_init() \
    do { \
        if (!aead_system_random_init_done) { \
            pmc_enable_periph_clk(ID_TRNG); \
            REG_TRNG_CR = TRNG_CR_KEY(0x524E47) | TRNG_CR_ENABLE; \
            REG_TRNG_IDR = TRNG_IDR_DATRDY; \
            aead_system_random_init_done = 1; \
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

#if !defined(aead_system_random)

/* We don't have a single-word system TRNG to generate random masking
 * words for us, so we need to fall back to a PRNG based on a system seed.
 * Note that this implementation isn't thread-safe. */

/* Perform a ChaCha quarter round operation */
#define quarterRound(a, b, c, d)    \
    do { \
        uint32_t _b = (b); \
        uint32_t _a = (a) + _b; \
        uint32_t _d = leftRotate16((d) ^ _a); \
        uint32_t _c = (c) + _d; \
        _b = leftRotate12(_b ^ _c); \
        _a += _b; \
        (d) = _d = leftRotate8(_d ^ _a); \
        _c += _d; \
        (a) = _a; \
        (b) = leftRotate7(_b ^ _c); \
        (c) = _c; \
    } while (0)

/**
 * \brief Executes the ChaCha20 hash core on a block.
 *
 * \param output Output block, must not overlap with \a input.
 * \param input Input block.
 *
 * Both blocks are assumed to be in host byte order.
 */
static void aead_chacha_core(uint32_t output[16], const uint32_t input[16])
{
    uint8_t round;
    uint8_t posn;

    /* Copy the input buffer to the output prior to the first round */
    for (posn = 0; posn < 16; ++posn)
        output[posn] = input[posn];

    /* Perform the ChaCha rounds in sets of two */
    for (round = 20; round >= 2; round -= 2) {
        /* Column round */
        quarterRound(output[0], output[4], output[8],  output[12]);
        quarterRound(output[1], output[5], output[9],  output[13]);
        quarterRound(output[2], output[6], output[10], output[14]);
        quarterRound(output[3], output[7], output[11], output[15]);

        /* Diagonal round */
        quarterRound(output[0], output[5], output[10], output[15]);
        quarterRound(output[1], output[6], output[11], output[12]);
        quarterRound(output[2], output[7], output[8],  output[13]);
        quarterRound(output[3], output[4], output[9],  output[14]);
    }

    /* Add the original input to the final output */
    for (posn = 0; posn < 16; ++posn)
        output[posn] += input[posn];
}

/**
 * \brief Global PRNG state.
 *
 * The starting value is the string "expand 32-byte k" followed by zeroes.
 * It will not stay in this state for long as aead_random_init() will
 * reseed and re-key the PRNG when it is called.
 *
 * The last word is used as a block counter when multiple output blocks
 * are required.  The PRNG is reseeded every AEAD_PRNG_RESEED_BLOCKS.
 */
static uint32_t aead_chacha_state[16] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * \brief Temporary output for the generation of data between re-keying.
 */
static uint32_t aead_chacha_output[16];

/**
 * \brief Position of the next word to return from the PRNG.
 */
static uint8_t aead_chacha_posn = 16;

/**
 * \brief Number of blocks that have been generated since the last re-key.
 */
static uint16_t aead_chacha_blocks = 0;

/**
 * \brief Automatically re-key every 16K of output data.  This can be adjusted.
 */
#define AEAD_PRNG_REKEY_BLOCKS 256

/**
 * \brief Automatically re-seed every 64K of output data.  This can be adjusted.
 */
#define AEAD_PRNG_RESEED_BLOCKS 1024

/**
 * \brief Re-keys the PRNG state to enforce forward secrecy.
 *
 * This function generates a new output block and then copies the first
 * 384 bits of the output to the last 384 bits of aead_chacha_state,
 * which will destroy any chance of going backwards.
 */
static void aead_chacha_rekey(void)
{
    ++(aead_chacha_state[15]);
    aead_chacha_core(aead_chacha_output, aead_chacha_state);
    memcpy(aead_chacha_state + 4, aead_chacha_output, 48);
    aead_chacha_posn = 16;
}

#endif

void aead_random_init(void)
{
#if defined(aead_system_random)
    aead_system_random_init();
#else
    /* Reseed the PRNG state from the system TRNG */
    aead_random_get_system_seed((unsigned char *)(aead_chacha_state + 4));

    /* Re-key the PRNG to enforce forward secrecy */
    aead_chacha_rekey();

    /* Restart the periodic re-key/re-seed block counter */
    aead_chacha_blocks = 0;
#endif
}

void aead_random_finish(void)
{
#if !defined(aead_system_random)
    aead_chacha_rekey();
#endif
}

uint32_t aead_random_generate_32(void)
{
#if defined(aead_system_random)
    aead_system_type x;
    int ready = 1;
    aead_system_random(x, ready);
    (void)ready;
    return (uint32_t)x;
#else
    if (aead_chacha_posn < 16) {
        /* We still have data in the previous block */
        return aead_chacha_output[aead_chacha_posn++];
    } else {
        /* Re-seed or re-key if we have generated too many blocks */
        ++aead_chacha_blocks;
        if (aead_chacha_blocks >= AEAD_PRNG_RESEED_BLOCKS)
            aead_random_init();
        else if ((aead_chacha_blocks % AEAD_PRNG_REKEY_BLOCKS) == 0)
            aead_chacha_rekey();

        /* Increment the block counter and generate a new output block */
        ++(aead_chacha_state[15]);
        aead_chacha_core(aead_chacha_output, aead_chacha_state);
        aead_chacha_posn = 1;
        return aead_chacha_output[0];
    }
#endif
}

uint64_t aead_random_generate_64(void)
{
#if defined(aead_system_random)
    aead_system_type x, y;
    int ready = 1;
    aead_system_random(x, ready);
    if (sizeof(aead_system_type) == 8)
        return x;
    aead_system_random(y, ready);
    (void)ready;
    return (((uint64_t)y) << 32) | x;
#else
    uint32_t x, y;
    x = aead_random_generate_32();
    y = aead_random_generate_32();
    return x | (((uint64_t)y) << 32);
#endif
}

void aead_random_generate_32_multiple(uint32_t *out, unsigned count)
{
#if defined(aead_system_random)
    aead_system_type x;
    int ready = 1;
    while (sizeof(aead_system_type) == 8 && count >= 2) {
        aead_system_random(x, ready);
        out[0] = (uint32_t)x;
        out[1] = (uint32_t)(x >> 32);
        out += 2;
        count -= 2;
    }
    while (count > 0) {
        aead_system_random(x, ready);
        *out++ = (uint32_t)x;
        --count;
    }
    (void)ready;
#else
    while (count > 0) {
        *out++ = aead_random_generate_32();
        --count;
    }
#endif
}

void aead_random_generate_64_multiple(uint64_t *out, unsigned count)
{
#if defined(aead_system_random)
    aead_system_type x;
    int ready = 1;
    if (sizeof(aead_system_type) == 8) {
        while (count > 0) {
            aead_system_random(x, ready);
            *out++ = x;
            --count;
        }
    } else {
        aead_system_type y;
        while (count > 0) {
            aead_system_random(x, ready);
            aead_system_random(y, ready);
            *out++ = (((uint64_t)y) << 32) | x;
            --count;
        }
    }
    (void)ready;
#else
    while (count > 0) {
        *out++ = aead_random_generate_64();
        --count;
    }
#endif
}
