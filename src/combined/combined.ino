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
This example runs lightweight cryptography tests on Arduino platforms.

Because this example links in the entire library and all algorithms,
it is only suitable for use on Arduino platforms with large amounts
of flash memory.
*/

#include "aead-metadata.h"
#include "internal-blake2s.h"
#include "internal-chachapoly.h"
#include "internal-sha256.h"
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
    size_t len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt 128 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, 128, 0, 0, nonce, key);
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
    size_t clen;
    size_t plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, 128, 0, 0, nonce, key);

    Serial.print("   decrypt 128 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        cipher->decrypt
            (plaintext, &plen, ciphertext, clen, 0, 0, nonce, key);
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
    size_t len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt  16 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, 16, 0, 0, nonce, key);
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
    size_t clen;
    size_t plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, 16, 0, 0, nonce, key);

    Serial.print("   decrypt  16 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->decrypt
            (plaintext, &plen, ciphertext, clen, 0, 0, nonce, key);
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
    size_t clen;

    Serial.print("   sanity check ... ");

    for (count = 0; count < 23; ++count)
        plaintext[count] = (unsigned char)count;
    for (count = 0; count < 11; ++count)
        plaintext[32 + count] = (unsigned char)count;

    cipher->encrypt
        (ciphertext, &clen, plaintext, 23, plaintext + 32, 11, nonce, key);

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
    perfCipher(&delirium_cipher, "1EBBE29D3EC4D574840905EFCEBFB40D02E1AB1B8B9994B8E19B5C7E461C77D276842CF6BEE6EA");
    perfCipher(&gift_cofb_cipher, "ABC3924173986D9EAA16CE0D01E923E5B6B26DC70E2190FB0E95FF754FF1A6943770CA3C04958A");
    perfCipher(&grain128_aead_cipher, "A4AB16F5B985B23EE9839C86A573B149D64EA150FEC21A81FD32406809DD51");
    perfCipher(&photon_beetle_128_cipher, "687B6BFD3807B447E418C8006C87A375AD55CEC555FA154A73EE361B62BBDA16875EDE631F445D");
    perfCipher(&photon_beetle_32_cipher, "05780949CD88CDC5940C408DD9ED28DD912386D437484DE5D4F65D10397CCE9E19F203840ACF2D");
    perfCipher(&romulus_n_cipher, "B0C179AC69E8583FD66B5C00368D4DBD93157CF52B93769A1EC2DF4019DE6D26A2FF2D31063F28");
    perfCipher(&romulus_m_cipher, "C21701C35E0E5FB450C66BD785B5E8A35426198531AD9BF1B30BB9ACC229A49C7C247BD28887DC");
    perfCipher(&romulus_t_cipher, "14431457C1B573058A16B8A10880FE96EF6ACAE8259E14523291D603D3A0066229A670554E094C");
    perfCipher(&schwaemm_256_128_cipher, "FA127C39BB1AB15429F59EF32F2742DB80A7F7A26939101E42502D7FB82673CF4977F6C6E12658");
    perfCipher(&schwaemm_192_192_cipher, "AED467CB67699D64AB5CE6AC4D578AA6C11AA962F639491095FD7DA7C3FE384B748518E9EEF24A4FF088466D3BE83B");
    perfCipher(&schwaemm_128_128_cipher, "8FC6A5B02165D2B9FF5838B24C7CFFC89F1A4BCB0AE9D1BEBBDAF0E435EF3D3B1E88283A992ADC");
    perfCipher(&schwaemm_256_256_cipher, "208CC82C35AF6227C7CF5C96A71BFBF10227D457DBD613F816C7704BA4AFF2E520BB179DAA1883D94212C18FD70EDDA2341E6058738F28");
    perfCipher(&tiny_jambu_128_cipher, "E30F24BBFC434EB18B92A3A4742BBAE61383F62BC9104E976569195FE559BC");
    perfCipher(&tiny_jambu_192_cipher, "317B8563AFA9B731FDF1F29FA688D0B0280422844CFEBAEE75CCE206898F65");
    perfCipher(&tiny_jambu_256_cipher, "D38B7389554B9C5DD8CA961C42CBE0017B102D0E01B82E91EAB122742F58F9");
    perfCipher(&xoodyak_cipher, "0E193FA578653462B128754C9CE9E5E4BB0910CA40C91A247E4EDCF2EC35E9098AF34EDF147366");

    // Performance of masked ciphers on their own.
    perfCipher(&ascon128_masked_cipher, "76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD69901F988A337A7239C411A18313622FC");
    perfCipher(&ascon128a_masked_cipher, "C52E4E39F5EF9F8461912AED7ABBA1B8EB8AD7ACD54637D193C5371279753F2177BFC76E5FC300");
    perfCipher(&ascon80pq_masked_cipher, "368D3F1F3BA75BA929D4A5327E8DE42A55383F238CCC04F75BF026EF5BE70D67741B339B908B04");
    perfCipher(&gift_cofb_masked_cipher, "ABC3924173986D9EAA16CE0D01E923E5B6B26DC70E2190FB0E95FF754FF1A6943770CA3C04958A");
    perfCipher(&tiny_jambu_128_masked_cipher, "E30F24BBFC434EB18B92A3A4742BBAE61383F62BC9104E976569195FE559BC");
    perfCipher(&tiny_jambu_192_masked_cipher, "317B8563AFA9B731FDF1F29FA688D0B0280422844CFEBAEE75CCE206898F65");
    perfCipher(&tiny_jambu_256_masked_cipher, "D38B7389554B9C5DD8CA961C42CBE0017B102D0E01B82E91EAB122742F58F9");
    perfCipher(&xoodyak_masked_cipher, "0E193FA578653462B128754C9CE9E5E4BB0910CA40C91A247E4EDCF2EC35E9098AF34EDF147366");

    // Run performance tests on the NIST hash algorithms.
    // Sanity vector is the hash of the "Count = 24" NIST KAT vector:
    //      000102030405060708090A0B0C0D0E0F10111213141516
    perfHash(&ascon_hash_algorithm, "7876669F23C98AE89E6F98CACEF141E05BA6CC954E5787E6EE0D8385D7F93F55");
    perfHash(&ascon_hasha_algorithm, "628F10DC588CE8F67F08DD21B2A8C994E2D9F0D96968A5F7CE97E48A936D9A5C");
    perfHash(&esch_256_hash_algorithm, "E1F292177A096547DFDE7F1E2E33EFB6A7C4C6DAAA6AFC95C9521E5D13168AC3");
    perfHash(&esch_384_hash_algorithm, "DCAD7D7394C64CB59BE79EE06A42FE5A420C5718156C6D3CC44ED07E699DDBE79BB2919D65EC4A24B5ECE4AFB11DFF54");
    perfHash(&photon_beetle_hash_algorithm, "9DB4465229E011100FFA49C0500C3A7B2B154F29AFFD0291CA3EFF69A74DBA9E");
    perfHash(&romulus_hash_algorithm, "40055D86525079F0DB65F9DA46C6282D63B571C1DEE72BB3B5FB2C7319AB30EC");
    perfHash(&xoodyak_hash_algorithm, "511AD3AA185ACC22EB141A81C1EBDA05EADA4E0C07BFBAD3A4855DB3E96C2164");

    // AES-GCM for comparison purposes.
    perfCipher(&aesgcm128_cipher, "936DA5CD621EF15343DB6B813AAE7E07A33708F547F8EB0B765EB53DA457F27E10BC0EA5FFB012");
    perfCipher(&aesgcm192_cipher, "E6F820989DBCCF09D83AD689F3A4D27F1E8E21182CB44015E3A161D7178FA543913F0659733BE7");
    perfCipher(&aesgcm256_cipher, "4703D418C1E0C41C85489D80BDE4766293C79527E46E4935C2431AA67EE0AFD558E563B09E1B8C");

    // SHA256 for comparison purposes.
    perfHash(&internal_sha256_hash_algorithm, 0);

    // Algorithms that are very slow.  Adjust loop counters and do them last.
    encrypt_128_ref /= 10;
    decrypt_128_ref /= 10;
    encrypt_16_ref /= 10;
    decrypt_16_ref /= 10;
    PERF_LOOPS = DEFAULT_PERF_LOOPS / 10;
    PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16 / 10;
    perfCipher(&dumbo_cipher, "0867290AD29D219C4BF3BF0BD652099B499B5B9CD7401BB862073E167E6543");
    perfCipher(&jumbo_cipher, "AE5D4F2BFAE6D432A1B6E92EB8955A7F2FD61692B269CDB16F7CA74F04CFE1");
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
