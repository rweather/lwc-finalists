/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
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
This example runs lightweight cryptography tests on Arduino platforms.

Because this example links in the entire library and all algorithms,
it is only suitable for use on Arduino platforms with large amounts
of flash memory.
*/

#include "aead-common.h"
#include "ascon128.h"
#include "ascon128-masked.h"
#include "elephant-delirium.h"
#include "elephant-dumbo.h"
#include "elephant-jumbo.h"
#include "gift-cofb.h"
#include "gift-cofb-masked.h"
#include "grain128.h"
#include "isap.h"
#include "photon-beetle.h"
#include "romulus.h"
#include "sparkle.h"
#include "tinyjambu.h"
#include "tinyjambu-masked.h"
#include "xoodyak.h"
#include "xoodyak-masked.h"
#include "internal-blake2s.h"
#include "internal-chachapoly.h"
#include "internal-masking.h"

#if defined(ESP8266)
extern "C" void system_soft_wdt_feed(void);
#define crypto_feed_watchdog() system_soft_wdt_feed()
#else
#define crypto_feed_watchdog() do { ; } while (0)
#endif

#if defined(__AVR__)
#define DEFAULT_PERF_LOOPS 200
#define DEFAULT_PERF_LOOPS_16 200
#define DEFAULT_PERF_HASH_LOOPS 100
#else
#define DEFAULT_PERF_LOOPS 1000
#define DEFAULT_PERF_LOOPS_16 3000
#define DEFAULT_PERF_HASH_LOOPS 1000
#endif

static int PERF_LOOPS = DEFAULT_PERF_LOOPS;
static int PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16;
static int PERF_HASH_LOOPS = DEFAULT_PERF_HASH_LOOPS;
static bool PERF_MASKING = false;

#define MAX_DATA_SIZE 128
#define MAX_TAG_SIZE 32

static unsigned char const key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char const nonce[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
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
static unsigned long hash_1024_time = 0;
static unsigned long hash_128_time = 0;
static unsigned long hash_16_time = 0;
static unsigned long hash_1024_ref = 0;
static unsigned long hash_128_ref = 0;
static unsigned long hash_16_ref = 0;

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

bool equal_hex(const char *expected, const unsigned char *actual, unsigned len)
{
    int ch, value;
    while (len > 0) {
        if (expected[0] == '\0' || expected[1] == '\0')
            return false;
        ch = *expected++;
        if (ch >= '0' && ch <= '9')
            value = (ch - '0') * 16;
        else if (ch >= 'A' && ch <= 'F')
            value = (ch - 'A' + 10) * 16;
        else if (ch >= 'a' && ch <= 'f')
            value = (ch - 'a' + 10) * 16;
        else
            return false;
        ch = *expected++;
        if (ch >= '0' && ch <= '9')
            value += (ch - '0');
        else if (ch >= 'A' && ch <= 'F')
            value += (ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f')
            value += (ch - 'a' + 10);
        else
            return false;
        if (actual[0] != value)
            return false;
        ++actual;
        --len;
    }
    return len == 0;
}

void perfCipherSanityCheck(const aead_cipher_t *cipher, const char *sanity_vec)
{
    unsigned count;
    unsigned long long clen;

    Serial.print("   sanity check ... ");

    for (count = 0; count < 23; ++count)
        plaintext[count] = (unsigned char)count;
    for (count = 0; count < 11; ++count)
        plaintext[32 + count] = (unsigned char)count;

    cipher->encrypt
        (ciphertext, &clen, plaintext, 23, plaintext + 32, 11, 0, nonce, key);

    if (equal_hex(sanity_vec, ciphertext, clen))
        Serial.println("ok");
    else
        Serial.println("FAILED");
}

void perfCipher(const aead_cipher_t *cipher, const char *sanity_vec)
{
    crypto_feed_watchdog();
    Serial.print(cipher->name);
    Serial.print(':');
    Serial.println();

    if (sanity_vec)
        perfCipherSanityCheck(cipher, sanity_vec);

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
        if (PERF_MASKING) {
            Serial.print(" = 1 / ");
            print_x(((double)time_avg) / ref_avg);
            Serial.print("x");
        }
        Serial.println();
    }

    Serial.println();
}

static unsigned char hash_buffer[1024];

unsigned long perfHash_N
    (const aead_hash_algorithm_t *hash_alg, int size, unsigned long ref)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long len;
    int count, loops;

    for (count = 0; count < size; ++count)
        hash_buffer[count] = (unsigned char)count;

    Serial.print("   hash ");
    if (size < 1000) {
        if (size < 100)
            Serial.print("  ");
        else
            Serial.print(" ");
    }
    Serial.print(size);
    Serial.print(" bytes ... ");

    // Adjust the number of loops to do more loops on smaller sizes.
    if (size < 1024)
        loops = PERF_HASH_LOOPS * 4;
    else
        loops = PERF_HASH_LOOPS;

    start = micros();
    for (count = 0; count < loops; ++count) {
        hash_alg->hash(ciphertext, hash_buffer, size);
    }
    elapsed = micros() - start;

    if (ref != 0 && elapsed != 0) {
        print_x(((double)ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (((double)size) * loops));
    Serial.print("us per byte, ");
    Serial.print((1000000.0 * size * loops) / elapsed);
    Serial.println(" bytes per second");

    return elapsed;
}

void perfHashSanityCheck
    (const aead_hash_algorithm_t *hash_alg, const char *sanity_vec)
{
    unsigned count;

    Serial.print("   sanity check ... ");

    for (count = 0; count < 23; ++count)
        plaintext[count] = (unsigned char)count;

    hash_alg->hash(ciphertext, plaintext, 23);

    if (equal_hex(sanity_vec, ciphertext, hash_alg->hash_len))
        Serial.println("ok");
    else
        Serial.println("FAILED");
}

void perfHash(const aead_hash_algorithm_t *hash_alg, const char *sanity_vec)
{
    crypto_feed_watchdog();
    Serial.print(hash_alg->name);
    Serial.print(':');
    Serial.println();

    if (sanity_vec)
        perfHashSanityCheck(hash_alg, sanity_vec);

    hash_1024_time = perfHash_N(hash_alg, 1024, hash_1024_ref);
    hash_128_time = perfHash_N(hash_alg, 128, hash_128_ref);
    hash_16_time = perfHash_N(hash_alg, 16, hash_16_ref);

    if (hash_16_ref != 0) {
        double avg = ((double)hash_1024_ref) / hash_1024_time;
        avg += ((double)hash_128_ref) / hash_128_time;
        avg += ((double)hash_16_ref) / hash_16_time;
        avg /= 3.0;
        Serial.print("   average ... ");
        print_x(avg);
        Serial.print("x");
        Serial.println();
    }

    Serial.println();
}

void perfMasked(const aead_cipher_t *ref_cipher,
                const aead_cipher_t *masked_cipher)
{
    encrypt_128_ref = 0;
    decrypt_128_ref = 0;
    encrypt_16_ref = 0;
    decrypt_16_ref = 0;
    perfCipher(ref_cipher, 0);
    encrypt_128_ref = encrypt_128_time;
    decrypt_128_ref = decrypt_128_time;
    encrypt_16_ref = encrypt_16_time;
    decrypt_16_ref = decrypt_16_time;
    Serial.print("[");
    Serial.print(AEAD_MASKING_SHARES);
    Serial.print("] ");
    perfCipher(masked_cipher, 0);
}

void setup()
{
    Serial.begin(9600);
    Serial.println();
    // Test ChaChaPoly and BLAKE2s first to get the reference time
    // for other algorithms.
    perfCipher(&internal_chachapoly_cipher, 0);
    encrypt_128_ref = encrypt_128_time;
    decrypt_128_ref = decrypt_128_time;
    encrypt_16_ref = encrypt_16_time;
    decrypt_16_ref = decrypt_16_time;
    perfHash(&internal_blake2s_hash_algorithm, 0);
    hash_1024_ref = hash_1024_time;
    hash_128_ref = hash_128_time;
    hash_16_ref = hash_16_time;

    // Run performance tests on the NIST AEAD algorithms.
    //
    // The test vectors are for doing a quick sanity check that the
    // algorithm appears to be working correctly.  The test vector is:
    //      Key = 0001020304...    (up to the key length)
    //      Nonce = 0001020304...  (up to the nonce length)
    //      PT = 000102030405060708090A0B0C0D0E0F10111213141516  (size = 23)
    //      AD = 000102030405060708090A                          (size = 11)
    // Usually this is "Count = 771" in the standard NIST KAT vectors.
    perfCipher(&ascon128_cipher, "76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD69901F988A337A7239C411A18313622FC");
    perfCipher(&ascon128a_cipher, "C52E4E39F5EF9F8461912AED7ABBA1B8EB8AD7ACD54637D193C5371279753F2177BFC76E5FC300");
    perfCipher(&ascon80pq_cipher, "368D3F1F3BA75BA929D4A5327E8DE42A55383F238CCC04F75BF026EF5BE70D67741B339B908B04");
    perfCipher(&delirium_cipher, "75F8BD7F4702EA535A1CE23E2D079F7B629979A2403D9F96320DA4F7CB37C5D5FA45BF918EFAD3");
    perfCipher(&gift_cofb_cipher, "ABC3924173986D9EAA16CE0D01E923E5B6B26DC70E2190FB0E95FF754FF1A6943770CA3C04958A");
    perfCipher(&grain128_aead_cipher, "51D23B440D625047559E5F00B08E22E4CB9524CB178A40EB5A23002C1BF3AD");
    perfCipher(&photon_beetle_128_cipher, "687B6BFD3807B447E418C8006C87A375AD55CEC555FA154A73EE361B62BBDA16875EDE631F445D");
    perfCipher(&photon_beetle_32_cipher, "05780949CD88CDC5940C408DD9ED28DD912386D437484DE5D4F65D10397CCE9E19F203840ACF2D");
    perfCipher(&romulus_np_cipher, "B0C179AC69E8583FD66B5C00368D4DBD93157CF52B93769A1EC2DF4019DE6D26A2FF2D31063F28");
    perfCipher(&romulus_mp_cipher, "C21701C35E0E5FB450C66BD785B5E8A35426198531AD9BF1B30BB9ACC229A49C7C247BD28887DC");
    perfCipher(&schwaemm_256_128_cipher, "FA127C39BB1AB15429F59EF32F2742DB80A7F7A26939101E42502D7FB82673CF4977F6C6E12658");
    perfCipher(&schwaemm_192_192_cipher, "AED467CB67699D64AB5CE6AC4D578AA6C11AA962F639491095FD7DA7C3FE384B748518E9EEF24A4FF088466D3BE83B");
    perfCipher(&schwaemm_128_128_cipher, "8FC6A5B02165D2B9FF5838B24C7CFFC89F1A4BCB0AE9D1BEBBDAF0E435EF3D3B1E88283A992ADC");
    perfCipher(&schwaemm_256_256_cipher, "208CC82C35AF6227C7CF5C96A71BFBF10227D457DBD613F816C7704BA4AFF2E520BB179DAA1883D94212C18FD70EDDA2341E6058738F28");
    perfCipher(&tiny_jambu_128_cipher, "047C0593AEB843CDD8997C32EE458A4ACB97FAC40C8427DD276A82B8BFB211");
    perfCipher(&tiny_jambu_192_cipher, "A088BC716A6D73F023CE31307FADDD2DC67EAF906DA7432D51F8A2630FCA9B");
    perfCipher(&tiny_jambu_256_cipher, "C701B9E9E02D31286575F8F8B3C957D67A9C2B2F26FD2894887023B3EEA1D9");
    perfCipher(&xoodyak_cipher, "9FC1D0E6E3555CC09565CF91CA413233DD67C945B2D0E69B3ECF260B86BBBEB626E78A9EC14125");

    // Performance of masked ciphers on their own.
    perfCipher(&ascon128_masked_cipher, "76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD69901F988A337A7239C411A18313622FC");
    perfCipher(&ascon128a_masked_cipher, "C52E4E39F5EF9F8461912AED7ABBA1B8EB8AD7ACD54637D193C5371279753F2177BFC76E5FC300");
    perfCipher(&ascon80pq_masked_cipher, "368D3F1F3BA75BA929D4A5327E8DE42A55383F238CCC04F75BF026EF5BE70D67741B339B908B04");
    perfCipher(&gift_cofb_masked_cipher, "ABC3924173986D9EAA16CE0D01E923E5B6B26DC70E2190FB0E95FF754FF1A6943770CA3C04958A");
    perfCipher(&tiny_jambu_128_masked_cipher, "047C0593AEB843CDD8997C32EE458A4ACB97FAC40C8427DD276A82B8BFB211");
    perfCipher(&tiny_jambu_192_masked_cipher, "A088BC716A6D73F023CE31307FADDD2DC67EAF906DA7432D51F8A2630FCA9B");
    perfCipher(&tiny_jambu_256_masked_cipher, "C701B9E9E02D31286575F8F8B3C957D67A9C2B2F26FD2894887023B3EEA1D9");
    perfCipher(&xoodyak_masked_cipher, "9FC1D0E6E3555CC09565CF91CA413233DD67C945B2D0E69B3ECF260B86BBBEB626E78A9EC14125");

    // Run performance tests on the NIST hash algorithms.
    // Sanity vector is the hash of the "Count = 24" NIST KAT vector:
    //      000102030405060708090A0B0C0D0E0F10111213141516
    perfHash(&ascon_hash_algorithm, "7876669F23C98AE89E6F98CACEF141E05BA6CC954E5787E6EE0D8385D7F93F55");
    perfHash(&esch_256_hash_algorithm, "E1F292177A096547DFDE7F1E2E33EFB6A7C4C6DAAA6AFC95C9521E5D13168AC3");
    perfHash(&esch_384_hash_algorithm, "DCAD7D7394C64CB59BE79EE06A42FE5A420C5718156C6D3CC44ED07E699DDBE79BB2919D65EC4A24B5ECE4AFB11DFF54");
    perfHash(&photon_beetle_hash_algorithm, "9DB4465229E011100FFA49C0500C3A7B2B154F29AFFD0291CA3EFF69A74DBA9E");
    perfHash(&xoodyak_hash_algorithm, "511AD3AA185ACC22EB141A81C1EBDA05EADA4E0C07BFBAD3A4855DB3E96C2164");

    // Algorithms that are very slow.  Adjust loop counters and do them last.
    encrypt_128_ref /= 10;
    decrypt_128_ref /= 10;
    encrypt_16_ref /= 10;
    decrypt_16_ref /= 10;
    PERF_LOOPS = DEFAULT_PERF_LOOPS / 10;
    PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16 / 10;
    perfCipher(&dumbo_cipher, "C9034A2F7F9698DCB41ACCCFBF549BF747D246A868FA0EB002548F45DBD832");
    perfCipher(&jumbo_cipher, "FEC941470CB859D735255B80663E807A63D52A71829F0B647C79509EDF8135");
    perfCipher(&isap_ascon_128a_cipher, "2CDE28DBBBD9131EBC568D77725B25937CF8EDB8A8F50A51312527CC6AEA52AED910035253C093");
    perfCipher(&isap_ascon_128_cipher, "B8529BCE1B3F9D0DB7A9C8DD43DD35D18E41801A814A2946E3500BD4A77E3EFF16EFABD6CCA575");
    perfCipher(&isap_keccak_128a_cipher, "01BC9CCB186E4A3732E86B9FAC4ABF3E6C4A8274A185FF1F7A1B9A98C623F126568CBADA74FAB5");
    perfCipher(&isap_keccak_128_cipher, "59D5A45BCBCB332311869B73F633D29606056B791F8A68F20CA7C894D7CDE7A06B357814696787");

    // Comparison of masked and unmasked versions of ciphers.
    PERF_LOOPS = DEFAULT_PERF_LOOPS / 10;
    PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16 / 10;
    PERF_MASKING = true;
    perfMasked(&ascon128_cipher, &ascon128_masked_cipher);
    perfMasked(&ascon128a_cipher, &ascon128a_masked_cipher);
    perfMasked(&ascon80pq_cipher, &ascon80pq_masked_cipher);
    perfMasked(&gift_cofb_cipher, &gift_cofb_masked_cipher);
    perfMasked(&tiny_jambu_128_cipher, &tiny_jambu_128_masked_cipher);
    perfMasked(&tiny_jambu_192_cipher, &tiny_jambu_192_masked_cipher);
    perfMasked(&tiny_jambu_256_cipher, &tiny_jambu_256_masked_cipher);
    perfMasked(&xoodyak_cipher, &xoodyak_masked_cipher);
}

void loop()
{
}
