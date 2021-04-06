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

#include "benchmark.h"
#include "internal-chachapoly.h"
#include <Arduino.h>

#if defined(ESP8266)
extern "C" void system_soft_wdt_feed(void);
#define crypto_feed_watchdog() system_soft_wdt_feed()
#else
#define crypto_feed_watchdog() do { ; } while (0)
#endif

#define DEFAULT_PERF_LOOPS 1000
#define DEFAULT_PERF_LOOPS_16 3000

static int PERF_LOOPS = DEFAULT_PERF_LOOPS;
static int PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16;

#define MAX_DATA_SIZE 128
#define MAX_TAG_SIZE 32

static unsigned char const key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char const nonce[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static unsigned char plaintext[MAX_DATA_SIZE];
static unsigned char ciphertext[MAX_DATA_SIZE + MAX_TAG_SIZE];

static unsigned long encrypt_128_time = 0;
static unsigned long encrypt_16_time = 0;
static unsigned long decrypt_128_time = 0;
static unsigned long decrypt_16_time = 0;
static unsigned long encrypt_128_ref = 0;
static unsigned long encrypt_16_ref = 0;
static unsigned long decrypt_128_ref = 0;
static unsigned long decrypt_16_ref = 0;

static void print_x(double value)
{
    if (value < 0.005)
        Serial.print(value, 4);
    else
        Serial.print(value);
}

void perfCipherEncrypt128(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt 128 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, 128, 0, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    encrypt_128_time = elapsed;

    if (encrypt_128_ref != 0 && elapsed != 0) {
        print_x(((double)encrypt_128_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (128.0 * PERF_LOOPS));
    Serial.print("us per byte, ");
    Serial.print((128.0 * PERF_LOOPS * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt128(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long clen;
    unsigned long long plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, 128, 0, 0, 0, nonce, key);

    Serial.print("   decrypt 128 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        cipher->decrypt
            (plaintext, &plen, 0, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    decrypt_128_time = elapsed;

    if (decrypt_128_ref != 0 && elapsed != 0) {
        print_x(((double)decrypt_128_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (128.0 * PERF_LOOPS));
    Serial.print("us per byte, ");
    Serial.print((128.0 * PERF_LOOPS * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherEncrypt16(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt  16 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, 16, 0, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    encrypt_16_time = elapsed;

    if (encrypt_16_ref != 0 && elapsed != 0) {
        print_x(((double)encrypt_16_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (16.0 * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((16.0 * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt16(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long clen;
    unsigned long long plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, 16, 0, 0, 0, nonce, key);

    Serial.print("   decrypt  16 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->decrypt
            (plaintext, &plen, 0, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    decrypt_16_time = elapsed;

    if (decrypt_16_ref != 0 && elapsed != 0) {
        print_x(((double)decrypt_16_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (16.0 * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((16.0 * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipher(const aead_cipher_t *cipher)
{
    crypto_feed_watchdog();
    Serial.print(cipher->name);
    Serial.print(':');
    Serial.println();

    perfCipherEncrypt128(cipher);
    perfCipherDecrypt128(cipher);
    perfCipherEncrypt16(cipher);
    perfCipherDecrypt16(cipher);

    if (encrypt_128_ref != 0) {
        unsigned long ref_avg = encrypt_128_ref + decrypt_128_ref +
                                encrypt_16_ref  + decrypt_16_ref;
        unsigned long time_avg = encrypt_128_time + decrypt_128_time +
                                 encrypt_16_time  + decrypt_16_time;
        Serial.print("   average ... ");
        print_x(((double)ref_avg) / time_avg);
        Serial.print("x");
        Serial.println();
    }

    Serial.println();
}

void perfSetup()
{
    // Test ChaChaPoly first to get the reference time for other algorithms.
    perfCipher(&internal_chachapoly_cipher);
    encrypt_128_ref = encrypt_128_time;
    decrypt_128_ref = decrypt_128_time;
    encrypt_16_ref = encrypt_16_time;
    decrypt_16_ref = decrypt_16_time;
}
