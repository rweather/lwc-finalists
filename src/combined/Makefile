
include ../../options.mak

.PHONY: all clean check individual

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)

LIBRARY = libcryptolw.a

OBJS = \
	aead-metadata.o \
	aead-random.o \
	aead-random-system.o \
	aesgcm-aead.o \
        ascon-aead.o \
        ascon-aead-masked.o \
        ascon-hash.o \
        ascon-hkdf.o \
        ascon-hmac.o \
        ascon-kmac.o \
        ascon-pbkdf2.o \
        ascon-permutation.o \
        ascon-prng.o \
        ascon-siv.o \
        ascon-xof.o \
        elephant-delirium.o \
        elephant-dumbo.o \
        elephant-jumbo.o \
        elephant-prng.o \
        gift-bc.o \
        gift-cofb-aead.o \
        gift-cofb-aead-masked.o \
	gift-prng.o \
	grain-aead.o \
	grain-prng.o \
        isap-a-aead.o \
        isap-a-aead-pk.o \
        isap-k-aead.o \
        isap-k-aead-pk.o \
        photon-beetle-aead.o \
        photon-beetle-hash.o \
        photon-beetle-hkdf.o \
        photon-beetle-hmac.o \
        photon-beetle-pbkdf2.o \
        photon-beetle-prng.o \
        romulus-m-aead.o \
        romulus-n-aead.o \
        romulus-t-aead.o \
        romulus-hash.o \
        romulus-hkdf.o \
        romulus-hmac.o \
        romulus-kmac.o \
        romulus-pbkdf2.o \
        romulus-prng.o \
        romulus-xof.o \
        sparkle-aead.o \
        sparkle-hash.o \
        sparkle-hkdf.o \
        sparkle-hmac.o \
        sparkle-kmac.o \
        sparkle-pbkdf2.o \
        sparkle-prng.o \
        tinyjambu-aead.o \
        tinyjambu-aead-masked.o \
        tinyjambu-prng.o \
        xoodyak-aead.o \
        xoodyak-hash.o \
        xoodyak-hkdf.o \
        xoodyak-hmac.o \
        xoodyak-kmac.o \
        xoodyak-pbkdf2.o \
        xoodyak-masked.o \
        xoodyak-prng.o \
	internal-aes.o \
	internal-aes-avr.o \
	internal-ascon.o \
	internal-ascon-m.o \
	internal-ascon-armv7m.o \
	internal-ascon-avr.o \
	internal-blake2s.o \
	internal-chachapoly.o \
	internal-ghash.o \
	internal-ghash-avr.o \
	internal-gift128.o \
	internal-gift128-m.o \
	internal-gift128b-full-armv7m.o \
	internal-gift128b-full-avr.o \
	internal-gift128b-small-armv7m.o \
	internal-gift128b-small-avr.o \
	internal-gift128b-tiny-armv7m.o \
	internal-gift128b-tiny-avr.o \
	internal-grain128.o \
	internal-grain128-armv7m.o \
	internal-grain128-avr.o \
	internal-keccakp-200.o \
	internal-keccakp-200-armv7m.o \
	internal-keccakp-200-avr.o \
	internal-keccakp-400.o \
	internal-keccakp-400-armv7m.o \
	internal-keccakp-400-avr.o \
	internal-photon256.o \
	internal-photon256-armv7m.o \
	internal-photon256-avr.o \
	internal-romulus.o \
	internal-sha256.o \
	internal-sha256-armv7m.o \
	internal-sha256-avr.o \
	internal-skinny-plus.o \
	internal-skinny-full-armv7m.o \
	internal-skinny-small-armv7m.o \
	internal-skinny-tiny-armv7m.o \
	internal-skinny-tiny-avr.o \
        internal-sparkle.o \
	internal-sparkle-armv7m.o \
	internal-sparkle-avr.o \
        internal-spongent.o \
	internal-spongent-armv7m.o \
	internal-spongent-avr.o \
        internal-tinyjambu.o \
        internal-tinyjambu-m.o \
	internal-tinyjambu-armv7m.o \
	internal-tinyjambu-avr.o \
        internal-xoodoo.o \
        internal-xoodoo-m.o \
	internal-util.o \
	internal-xoodoo-armv7m.o \
	internal-xoodoo-avr.o

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	rm -f $(LIBRARY)
	$(AR) rc $(LIBRARY) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBRARY)

check: all

individual:
	(cd ../individual ; $(MAKE) all)

aead-metadata.o: \
	aead-metadata.h aead-random.h internal-masking.h internal-util.h \
	aesgcm-aead.h ascon-aead.h ascon-aead-masked.h ascon-hash.h \
        ascon-xof.h ascon-siv.h \
	elephant-delirium.h elephant-dumbo.h elephant-jumbo.h \
	gift-cofb-aead.h gift-cofb-aead-masked.h \
	grain-aead.h \
	isap-a-aead.h isap-k-aead.h isap-a-aead-pk.h isap-k-aead-pk.h \
	photon-beetle-aead.h photon-beetle-hash.h \
	romulus-n-aead.h romulus-m-aead.h romulus-t-aead.h \
        romulus-hash.h romulus-xof.h \
	sparkle-aead.h sparkle-hash.h \
	tinyjambu-aead.h tinyjambu-aead-masked.h \
	xoodyak-aead.h xoodyak-hash.h xoodyak-masked.h
aead-random.o: aead-random.h
aead-random-system.o: aead-random.h internal-util.h
aesgcm-aead.o: aesgcm-aead.h internal-aes.h internal-util.h internal-ghash.h aead-metadata.h
ascon-aead.o: ascon-aead.h internal-ascon.h internal-util.h
ascon-aead-masked.o: ascon-aead-masked.h internal-ascon.h internal-ascon-m.h aead-random.h internal-masking.h internal-util.h
ascon-hash.o: ascon-hash.h ascon-xof.h
ascon-hkdf.o: ascon-hkdf.h ascon-hmac.h ascon-hash.h ascon-xof.h internal-hkdf.h internal-util.h
ascon-hmac.o: ascon-hmac.h ascon-hash.h ascon-xof.h internal-hmac.h internal-util.h
ascon-kmac.o: ascon-kmac.h ascon-xof.h internal-kmac.h internal-util.h
ascon-pbkdf2.o: ascon-pbkdf2.h ascon-hmac.h ascon-hash.h ascon-xof.h internal-pbkdf2.h internal-util.h
ascon-permutation.o: ascon-permutation.h internal-ascon.h internal-util.h
ascon-prng.o: ascon-prng.h ascon-xof.h ascon-hash.h internal-ascon.h internal-util.h
ascon-siv.o: ascon-siv.h ascon-aead.h internal-ascon.h internal-util.h
ascon-xof.o: ascon-xof.h internal-ascon.h internal-util.h
elephant-delirium.o: elephant-delirium.h internal-keccakp-200.h internal-util.h
elephant-dumbo.o: elephant-dumbo.h internal-elephant.h internal-spongent.h internal-util.h
elephant-jumbo.o: elephant-jumbo.h internal-elephant.h internal-spongent.h internal-util.h
elephant-prng.o: elephant-prng.h internal-elephant.h internal-keccakp-200.h internal-util.h
gift-bc.o: gift-bc.h internal-gift128.h internal-gift128-config.h internal-util.h
gift-cofb-aead.o: gift-cofb-aead.h internal-gift128.h internal-gift128-config.h internal-util.h
gift-cofb-aead-masked.o: gift-cofb-aead-masked.h internal-gift128-m.h internal-gift128-config.h internal-util.h aead-random.h internal-masking.h
gift-prng.o: gift-prng.h internal-gift128.h internal-gift128-config.h internal-util.h
grain-aead.o: grain-aead.h internal-grain128.h internal-util.h
grain-prng.o: grain-prng.h internal-grain128.h internal-util.h
isap-aead.o: isap-aead.h internal-isap.h internal-ascon.h internal-keccakp-400.h internal-util.h
isap-a-aead.o: isap-a-aead.h internal-isap.h internal-ascon.h internal-util.h
isap-k-aead.o: isap-k-aead.h internal-isap.h internal-keccakp-400.h internal-util.h
isap-a-aead-pk.o: isap-a-aead-pk.h internal-isap-pk.h internal-ascon.h internal-util.h
isap-k-aead-pk.o: isap-k-aead-pk.h internal-isap-pk.h internal-keccakp-400.h internal-util.h
photon-beetle-aead.o: photon-beetle-aead.h internal-photon256.h internal-util.h
photon-beetle-hash.o: photon-beetle-hash.h internal-photon256.h internal-util.h
photon-beetle-hkdf.o: photon-beetle-hkdf.h photon-beetle-hmac.h photon-beetle-hash.h internal-hkdf.h internal-util.h
photon-beetle-hmac.o: photon-beetle-hmac.h photon-beetle-hash.h internal-hmac.h internal-util.h
photon-beetle-pbkdf2.o: photon-beetle-pbkdf2.h photon-beetle-hmac.h photon-beetle-hash.h internal-pbkdf2.h internal-util.h
photon-beetle-prng.o: photon-beetle-prng.h photon-beetle-hash.h internal-photon256.h internal-util.h
romulus-m-aead.o: romulus-m-aead.h internal-romulus.h internal-skinny-plus.h internal-skinny-plus-config.h internal-util.h
romulus-n-aead.o: romulus-n-aead.h internal-romulus.h internal-skinny-plus.h internal-skinny-plus-config.h internal-util.h
romulus-t-aead.o: romulus-t-aead.h romulus-hash.h internal-romulus.h internal-skinny-plus.h internal-skinny-plus-config.h internal-util.h
romulus-hash.o: romulus-hash.h internal-skinny-plus.h internal-skinny-plus-config.h internal-util.h
romulus-hkdf.o: romulus-hkdf.h romulus-hmac.h romulus-hash.h internal-util.h internal-hkdf.h
romulus-hmac.o: romulus-hmac.h romulus-hash.h internal-util.h internal-hmac.h
romulus-kmac.o: romulus-kmac.h romulus-xof.h romulus-hash.h internal-util.h internal-kmac.h
romulus-pbkdf2.o: romulus-pbkdf2.h romulus-hmac.h romulus-hash.h internal-util.h internal-pbkdf2.h
romulus-prng.o: romulus-prng.h romulus-hash.h internal-skinny-plus.h internal-skinny-plus-config.h internal-util.h
romulus-xof.o: romulus-xof.h romulus-hash.h internal-util.h
sparkle-aead.o: sparkle-aead.h internal-sparkle.h internal-util.h
sparkle-hash.o: sparkle-hash.h internal-sparkle.h internal-util.h
sparkle-hkdf.o: sparkle-hkdf.h sparkle-hmac.h sparkle-hash.h internal-hkdf.h internal-util.h
sparkle-hmac.o: sparkle-hmac.h sparkle-hash.h internal-hmac.h internal-util.h
sparkle-kmac.o: sparkle-kmac.h sparkle-hash.h internal-kmac.h internal-util.h
sparkle-pbkdf2.o: sparkle-pbkdf2.h sparkle-hmac.h sparkle-hash.h internal-pbkdf2.h internal-util.h
sparkle-prng.o: sparkle-prng.h sparkle-hash.h internal-sparkle.h internal-util.h
tinyjambu-aead.o: tinyjambu-aead.h internal-tinyjambu.h internal-util.h
tinyjambu-aead-masked.o: tinyjambu-aead-masked.h internal-tinyjambu-m.h aead-random.h internal-masking.h internal-util.h
tinyjambu-prng.o: tinyjambu-prng.h internal-tinyjambu.h internal-util.h
xoodyak-aead.o: xoodyak-aead.h internal-xoodoo.h internal-util.h
xoodyak-hash.o: xoodyak-hash.h internal-xoodoo.h internal-util.h
xoodyak-hkdf.o: xoodyak-hkdf.h xoodyak-hmac.h xoodyak-hash.h internal-hkdf.h internal-util.h
xoodyak-hmac.o: xoodyak-hmac.h xoodyak-hash.h internal-hmac.h internal-util.h
xoodyak-kmac.o: xoodyak-kmac.h xoodyak-hash.h internal-kmac.h internal-util.h
xoodyak-pbkdf2.o: xoodyak-pbkdf2.h xoodyak-hmac.h xoodyak-hash.h internal-pbkdf2.h internal-util.h
xoodyak-masked.o: xoodyak-masked.h internal-xoodoo.h internal-xoodoo-m.h aead-random.h internal-masking.h internal-util.h
xoodyak-prng.o: xoodyak-prng.h xoodyak-hash.h internal-xoodoo.h internal-util.h
internal-aes.o: internal-aes.h internal-util.h
internal-ascon.o: internal-ascon.h internal-util.h
internal-ascon-m.o: internal-ascon-m.h internal-ascon.h aead-random.h internal-masking.h internal-util.h
internal-blake2s.o: internal-blake2s.h internal-util.h aead-metadata.h
internal-chachapoly.o: internal-chachapoly.h internal-util.h aead-metadata.h
internal-ghash.o: internal-ghash.h internal-util.h
internal-gift128.o: internal-gift128.h internal-gift128-config.h internal-util.h
internal-gift128-m.o: internal-gift128-m.h internal-gift128-config.h aead-random.h internal-masking.h internal-util.h
internal-gift128b-full-armv7m.o: internal-gift128-config.h
internal-gift128b-full-avr.o: internal-gift128-config.h
internal-gift128b-small-armv7m.o: internal-gift128-config.h
internal-gift128b-small-avr.o: internal-gift128-config.h
internal-gift128b-tiny-armv7m.o: internal-gift128-config.h
internal-gift128b-tiny-avr.o: internal-gift128-config.h
internal-grain128.o: internal-grain128.h internal-util.h
internal-keccakp-200.o: internal-keccakp-200.h internal-util.h
internal-keccakp-400.o: internal-keccakp-400.h internal-util.h
internal-photon256.o: internal-photon256.h internal-photon256-mix.h internal-util.h
internal-romulus.o: internal-romulus.h internal-skinny-plus.h internal-skinny-plus-config.h internal-util.h
internal-sha256.o: internal-sha256.h internal-util.h aead-metadata.h internal-hmac.h
internal-skinny-plus.o: internal-skinny-plus.h internal-skinny-plus-config.h internal-util.h
internal-skinny-full-armv7m.o: internal-skinny-plus-config.h
internal-skinny-small-armv7m.o: internal-skinny-plus-config.h
internal-skinny-tiny-armv7m.o: internal-skinny-plus-config.h
internal-sparkle.o: internal-sparkle.h internal-util.h
internal-spongent.o: internal-spongent.h internal-util.h
internal-tinyjambu.o: internal-tinyjambu.h internal-util.h
internal-tinyjambu-m.o: internal-tinyjambu-m.h aead-random.h internal-masking.h internal-util.h
internal-xoodoo.o: internal-xoodoo.h internal-util.h
internal-xoodoo-m.o: internal-xoodoo-m.h aead-random.h internal-masking.h internal-util.h
internal-util.o: internal-util.h

.S.o:
	$(CC_ASM) -o $@ -c $<
