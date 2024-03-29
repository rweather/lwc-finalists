
include ../../options.mak

LIBSRC_DIR = ../../src/combined

.PHONY: all clean check perf

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I$(LIBSRC_DIR) -g
LDFLAGS += $(COMMON_LDFLAGS) -L$(LIBSRC_DIR) -lcryptolw

TARGET1 = unit-tests

OBJS1 = \
    test-cipher.o \
    test-main.o \
    test-aes.o \
    test-aesgcm.o \
    test-ascon.o \
    test-blake2s.o \
    test-chachapoly.o \
    test-ghash.o \
    test-gift128.o \
    test-grain128.o \
    test-hkdf.o \
    test-hmac.o \
    test-keccak.o \
    test-kmac.o \
    test-masking.o \
    test-pbkdf2.o \
    test-photon256.o \
    test-romulus-xof.o \
    test-sha256.o \
    test-sha3.o \
    test-skinny-plus.o \
    test-sparkle.o \
    test-spongent.o \
    test-tinyjambu.o \
    test-xoodoo.o

DEPS = $(LIBSRC_DIR)/libcryptolw.a

all: $(TARGET1)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

check: $(TARGET1)
	./$(TARGET1)

TEST_CIPHER_INC = test-cipher.h $(LIBSRC_DIR)/aead-metadata.h
TEST_CIPHER_MASKING_INC = test-cipher.h $(LIBSRC_DIR)/aead-metadata.h $(LIBSRC_DIR)/aead-random.h $(LIBSRC_DIR)/internal-masking.h

test-aes.o: $(LIBSRC_DIR)/internal-aes.h $(LIBSRC_DIR)/internal-util.h $(TEST_CIPHER_INC)
test-aesgcm.o: $(LIBSRC_DIR)/aesgcm-aead.h $(LIBSRC_DIR)/internal-util.h $(TEST_CIPHER_INC)
test-ascon.o: $(LIBSRC_DIR)/ascon-aead.h $(LIBSRC_DIR)/ascon-permutation.h $(LIBSRC_DIR)/internal-ascon.h $(LIBSRC_DIR)/internal-ascon-m2.h $(LIBSRC_DIR)/aead-random.h $(TEST_CIPHER_INC)
test-blake2s.o: $(LIBSRC_DIR)/internal-blake2s.h $(TEST_CIPHER_INC)
test-chachapoly.o: $(LIBSRC_DIR)/internal-chachapoly.h $(TEST_CIPHER_INC)
test-ghash.o: $(LIBSRC_DIR)/internal-ghash.h $(LIBSRC_DIR)/internal-util.h $(TEST_CIPHER_INC)
test-gift128.o: $(LIBSRC_DIR)/internal-gift128.h $(LIBSRC_DIR)/internal-gift128-m.h $(LIBSRC_DIR)/internal-gift128-config.h $(LIBSRC_DIR)/gift-bc.h $(TEST_CIPHER_MASKING_INC)
test-grain128.o: $(LIBSRC_DIR)/internal-grain128.h $(TEST_CIPHER_INC)
test-hkdf.o: $(LIBSRC_DIR)/internal-sha256.h $(LIBSRC_DIR)/internal-hkdf.h $(LIBSRC_DIR)/internal-util.h $(TEST_CIPHER_INC)
test-hmac.o: $(LIBSRC_DIR)/aead-metadata.h $(LIBSRC_DIR)/ascon-hmac.h $(LIBSRC_DIR)/photon-beetle-hmac.h $(LIBSRC_DIR)/romulus-hmac.h $(LIBSRC_DIR)/sparkle-hmac.h $(LIBSRC_DIR)/xoodyak-hmac.h $(TEST_CIPHER_INC)
test-keccak.o: $(LIBSRC_DIR)/internal-keccakp-200.h $(LIBSRC_DIR)/internal-keccakp-400.h $(TEST_CIPHER_INC)
test-kmac.o: test-sha3.h $(LIBSRC_DIR)/internal-kmac.h $(LIBSRC_DIR)/ascon-kmac.h $(LIBSRC_DIR)/ascon-xof.h $(LIBSRC_DIR)/sparkle-hash.h $(LIBSRC_DIR)/sparkle-kmac.h $(LIBSRC_DIR)/xoodyak-hash.h $(LIBSRC_DIR)/xoodyak-kmac.h $(LIBSRC_DIR)/romulus-hash.h $(LIBSRC_DIR)/romulus-kmac.h $(TEST_CIPHER_INC)
test-masking.o: $(LIBSRC_DIR)/aead-random.h $(LIBSRC_DIR)/internal-masking.h $(TEST_CIPHER_INC) test-masking-common.c
test-pbkdf2.o: $(LIBSRC_DIR)/internal-sha256.h $(LIBSRC_DIR)/internal-pbkdf2.h $(LIBSRC_DIR)/internal-util.h $(LIBSRC_DIR)/ascon-hmac.h $(LIBSRC_DIR)/photon-beetle-hmac.h $(LIBSRC_DIR)/romulus-hmac.h $(LIBSRC_DIR)/sparkle-hmac.h $(LIBSRC_DIR)/xoodyak-hmac.h $(LIBSRC_DIR)/ascon-pbkdf2.h $(LIBSRC_DIR)/photon-beetle-pbkdf2.h $(LIBSRC_DIR)/romulus-pbkdf2.h $(LIBSRC_DIR)/sparkle-pbkdf2.h $(LIBSRC_DIR)/xoodyak-pbkdf2.h $(TEST_CIPHER_INC)
test-photon256.o: $(LIBSRC_DIR)/internal-photon256.h $(TEST_CIPHER_INC)
test-romulus-xof.o: $(LIBSRC_DIR)/romulus-xof.h $(LIBSRC_DIR)/romulus-hash.h $(TEST_CIPHER_INC)
test-sha256.o: $(LIBSRC_DIR)/internal-sha256.h $(LIBSRC_DIR)/aead-metadata.h $(TEST_CIPHER_INC)
test-sha3.o: test-sha3.h $(LIBSRC_DIR)/internal-util.h $(TEST_CIPHER_INC)
test-skinny-plus.o: $(LIBSRC_DIR)/skinny-plus-bc.h $(LIBSRC_DIR)/internal-skinny-plus.h $(LIBSRC_DIR)/internal-skinny-plus-config.h $(TEST_CIPHER_INC)
test-sparkle.o: $(LIBSRC_DIR)/internal-sparkle.h $(TEST_CIPHER_INC)
test-spongent.o: $(LIBSRC_DIR)/internal-spongent.h $(TEST_CIPHER_INC)
test-tinyjambu.o: $(LIBSRC_DIR)/internal-tinyjambu.h $(LIBSRC_DIR)/internal-tinyjambu-m.h $(LIBSRC_DIR)/internal-util.h $(TEST_CIPHER_MASKING_INC)
test-xoodoo.o: $(LIBSRC_DIR)/internal-xoodoo.h $(LIBSRC_DIR)/internal-xoodoo-m.h $(TEST_CIPHER_MASKING_INC)
test-cipher.o: $(TEST_CIPHER_INC)
test-main.o: $(TEST_CIPHER_MASKING_INC)
