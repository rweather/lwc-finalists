
SRCDIR = ../combined

COMMON_FILES = \
	internal-util.h \
	internal-util.c
COMMON_MASKING_FILES = \
	aead-random.h \
	aead-random.c \
	aead-random-system.c \
	internal-masking.h \
	internal-util.h \
	internal-util.c

AESGCM_FILES = \
    aesgcm-aead.c \
    aesgcm-aead.h \
    internal-aes.c \
    internal-aes.h \
    internal-aes-avr.S \
    internal-ghash.c \
    internal-ghash.h \
    internal-ghash-avr.S \
    $(COMMON_FILES)
ASCON_FILES = \
    ascon-aead.c \
    ascon-aead.h \
    ascon-hash.c \
    ascon-hash.h \
    ascon-hkdf.c \
    ascon-hkdf.h \
    ascon-hmac.c \
    ascon-hmac.h \
    ascon-kmac.c \
    ascon-kmac.h \
    ascon-pbkdf2.c \
    ascon-pbkdf2.h \
    ascon-permutation.c \
    ascon-permutation.h \
    ascon-prng.c \
    ascon-prng.h \
    ascon-siv.c \
    ascon-siv.h \
    ascon-xof.c \
    ascon-xof.h \
    internal-ascon.c \
    internal-ascon.h \
    internal-ascon-armv7m.S \
    internal-ascon-avr.S \
    internal-hkdf.h \
    internal-hmac.h \
    internal-kmac.h \
    internal-pbkdf2.h \
    aead-random-system.c \
    $(COMMON_FILES)
ASCON_MASKED_FILES = \
    ascon-aead-masked.c \
    ascon-aead-masked.h \
    internal-ascon.c \
    internal-ascon.h \
    internal-ascon-m.c \
    internal-ascon-m.h \
    internal-ascon-armv7m.S \
    internal-ascon-avr.S \
    $(COMMON_MASKING_FILES)
ELEPHANT_DELIRIUM_FILES = \
    elephant-delirium.c \
    elephant-delirium.h \
    elephant-prng.c \
    elephant-prng.h \
    internal-elephant.h \
    internal-keccakp-200.c \
    internal-keccakp-200.h \
    internal-keccakp-200-armv7m.S \
    internal-keccakp-200-avr.S \
    aead-random-system.c \
    $(COMMON_FILES)
ELEPHANT_DUMBO_FILES = \
    elephant-dumbo.c \
    elephant-dumbo.h \
    internal-elephant.h \
    internal-spongent.c \
    internal-spongent.h \
    internal-spongent-armv7m.S \
    internal-spongent-avr.S \
    $(COMMON_FILES)
ELEPHANT_JUMBO_FILES = \
    elephant-jumbo.c \
    elephant-jumbo.h \
    internal-elephant.h \
    internal-spongent.c \
    internal-spongent.h \
    internal-spongent-armv7m.S \
    internal-spongent-avr.S \
    $(COMMON_FILES)
GIFT_COFB_FILES = \
    gift-cofb-aead.c \
    gift-cofb-aead.h \
    gift-bc.c \
    gift-bc.h \
    gift-prng.c \
    gift-prng.h \
    internal-gift128.c \
    internal-gift128.h \
    internal-gift128-config.h \
    internal-gift128b-full-armv7m.S \
    internal-gift128b-small-armv7m.S \
    internal-gift128b-tiny-armv7m.S \
    internal-gift128b-full-avr.S \
    internal-gift128b-small-avr.S \
    internal-gift128b-tiny-avr.S \
    aead-random-system.c \
    $(COMMON_FILES)
GIFT_COFB_MASKED_FILES = \
    gift-cofb-aead-masked.c \
    gift-cofb-aead-masked.h \
    internal-gift128-config.h \
    internal-gift128-m.c \
    internal-gift128-m.h \
    $(COMMON_MASKING_FILES)
GRAIN128_FILES = \
    grain-aead.c \
    grain-aead.h \
    grain-prng.c \
    grain-prng.h \
    internal-grain128.c \
    internal-grain128.h \
    internal-grain128-armv7m.S \
    internal-grain128-avr.S \
    aead-random-system.c \
    $(COMMON_FILES)
ISAP_A_FILES = \
    isap-a-aead.c \
    isap-a-aead.h \
    isap-a-aead-pk.c \
    isap-a-aead-pk.h \
    internal-ascon.c \
    internal-ascon.h \
    internal-ascon-armv7m.S \
    internal-ascon-avr.S \
    internal-isap.h \
    internal-isap-pk.h \
    $(COMMON_FILES)
ISAP_K_FILES = \
    isap-k-aead.c \
    isap-k-aead.h \
    isap-k-aead-pk.c \
    isap-k-aead-pk.h \
    internal-isap.h \
    internal-isap-pk.h \
    internal-keccakp-400.c \
    internal-keccakp-400.h \
    internal-keccakp-400-armv7m.S \
    internal-keccakp-400-avr.S \
    $(COMMON_FILES)
PHOTON_BEETLE_FILES = \
    photon-beetle-aead.c \
    photon-beetle-aead.h \
    photon-beetle-hash.c \
    photon-beetle-hash.h \
    photon-beetle-hkdf.c \
    photon-beetle-hkdf.h \
    photon-beetle-hmac.c \
    photon-beetle-hmac.h \
    photon-beetle-pbkdf2.c \
    photon-beetle-pbkdf2.h \
    photon-beetle-prng.c \
    photon-beetle-prng.h \
    internal-photon256.c \
    internal-photon256.h \
    internal-photon256-armv7m.S \
    internal-photon256-avr.S \
    internal-photon256-mix.h \
    internal-hkdf.h \
    internal-hmac.h \
    internal-pbkdf2.h \
    aead-random-system.c \
    $(COMMON_FILES)
ROMULUS_FILES = \
    romulus-m-aead.c \
    romulus-m-aead.h \
    romulus-n-aead.c \
    romulus-n-aead.h \
    romulus-t-aead.c \
    romulus-t-aead.h \
    romulus-hash.c \
    romulus-hash.h \
    romulus-hkdf.c \
    romulus-hkdf.h \
    romulus-hmac.c \
    romulus-hmac.h \
    romulus-kmac.c \
    romulus-kmac.h \
    romulus-pbkdf2.c \
    romulus-pbkdf2.h \
    romulus-prng.c \
    romulus-prng.h \
    romulus-xof.c \
    romulus-xof.h \
    skinny-plus-bc.c \
    skinny-plus-bc.h \
    internal-romulus.c \
    internal-romulus.h \
    internal-skinny-plus.c \
    internal-skinny-plus.h \
    internal-skinny-full-armv7m.S \
    internal-skinny-small-armv7m.S \
    internal-skinny-tiny-armv7m.S \
    internal-skinny-tiny-avr.S \
    internal-skinny-plus-config.h \
    internal-hkdf.h \
    internal-hmac.h \
    internal-kmac.h \
    internal-pbkdf2.h \
    aead-random-system.c \
    $(COMMON_FILES)
SPARKLE_FILES = \
    sparkle-aead.c \
    sparkle-aead.h \
    sparkle-hash.c \
    sparkle-hash.h \
    sparkle-hkdf.c \
    sparkle-hkdf.h \
    sparkle-hmac.c \
    sparkle-hmac.h \
    sparkle-kmac.c \
    sparkle-kmac.h \
    sparkle-pbkdf2.c \
    sparkle-pbkdf2.h \
    sparkle-prng.c \
    sparkle-prng.h \
    internal-sparkle.c \
    internal-sparkle.h \
    internal-sparkle-armv7m.S \
    internal-sparkle-avr.S \
    internal-hkdf.h \
    internal-hmac.h \
    internal-kmac.h \
    internal-pbkdf2.h \
    aead-random-system.c \
    $(COMMON_FILES)
TINYJAMBU_FILES = \
    tinyjambu-aead.c \
    tinyjambu-aead.h \
    tinyjambu-prng.c \
    tinyjambu-prng.h \
    internal-tinyjambu.c \
    internal-tinyjambu.h \
    internal-tinyjambu-armv7m.S \
    internal-tinyjambu-avr.S \
    aead-random-system.c \
    $(COMMON_FILES)
TINYJAMBU_MASKED_FILES = \
    tinyjambu-aead-masked.c \
    tinyjambu-aead-masked.h \
    internal-tinyjambu-m.c \
    internal-tinyjambu-m.h \
    $(COMMON_MASKING_FILES)
XOODYAK_FILES = \
    xoodyak-aead.c \
    xoodyak-aead.h \
    xoodyak-hash.c \
    xoodyak-hash.h \
    xoodyak-hkdf.c \
    xoodyak-hkdf.h \
    xoodyak-hmac.c \
    xoodyak-hmac.h \
    xoodyak-kmac.c \
    xoodyak-kmac.h \
    xoodyak-pbkdf2.c \
    xoodyak-pbkdf2.h \
    xoodyak-prng.c \
    xoodyak-prng.h \
    internal-xoodoo.c \
    internal-xoodoo.h \
    internal-xoodoo-armv7m.S \
    internal-xoodoo-avr.S \
    internal-hkdf.h \
    internal-hmac.h \
    internal-kmac.h \
    internal-pbkdf2.h \
    aead-random-system.c \
    $(COMMON_FILES)
XOODYAK_MASKED_FILES = \
    xoodyak-masked.c \
    xoodyak-masked.h \
    internal-xoodoo.c \
    internal-xoodoo.h \
    internal-xoodoo-m.c \
    internal-xoodoo-m.h \
    internal-xoodoo-armv7m.S \
    internal-xoodoo-avr.S \
    $(COMMON_MASKING_FILES)

ALL_ALGORITHMS = \
    aesgcm \
    ascon \
    ascon_masked \
    elephant_delirium \
    elephant_dumbo \
    elephant_jumbo \
    gift_cofb \
    gift_cofb_masked \
    grain128 \
    isap_a \
    isap_k \
    photon_beetle \
    romulus \
    sparkle \
    tinyjambu \
    tinyjambu_masked \
    xoodyak \
    xoodyak_masked

.PHONY: all $(ALL_ALGORITHMS)

all: $(ALL_ALGORITHMS)

aesgcm:
	cp $(foreach file,$(AESGCM_FILES),$(SRCDIR)/$(file)) AESGCM

ascon:
	cp $(foreach file,$(ASCON_FILES),$(SRCDIR)/$(file)) ASCON

ascon_masked:
	cp $(foreach file,$(ASCON_MASKED_FILES),$(SRCDIR)/$(file)) ASCON_masked

elephant_delirium:
	cp $(foreach file,$(ELEPHANT_DELIRIUM_FILES),$(SRCDIR)/$(file)) Elephant-Delirium

elephant_dumbo:
	cp $(foreach file,$(ELEPHANT_DUMBO_FILES),$(SRCDIR)/$(file)) Elephant-Dumbo

elephant_jumbo:
	cp $(foreach file,$(ELEPHANT_JUMBO_FILES),$(SRCDIR)/$(file)) Elephant-Jumbo

gift_cofb:
	cp $(foreach file,$(GIFT_COFB_FILES),$(SRCDIR)/$(file)) GIFT-COFB

gift_cofb_masked:
	cp $(foreach file,$(GIFT_COFB_MASKED_FILES),$(SRCDIR)/$(file)) GIFT-COFB_masked

grain128:
	cp $(foreach file,$(GRAIN128_FILES),$(SRCDIR)/$(file)) Grain-128AEAD

isap_a:
	cp $(foreach file,$(ISAP_A_FILES),$(SRCDIR)/$(file)) ISAP-A

isap_k:
	cp $(foreach file,$(ISAP_K_FILES),$(SRCDIR)/$(file)) ISAP-K

photon_beetle:
	cp $(foreach file,$(PHOTON_BEETLE_FILES),$(SRCDIR)/$(file)) PHOTON-Beetle

romulus:
	cp $(foreach file,$(ROMULUS_FILES),$(SRCDIR)/$(file)) Romulus

sparkle:
	cp $(foreach file,$(SPARKLE_FILES),$(SRCDIR)/$(file)) SPARKLE

tinyjambu:
	cp $(foreach file,$(TINYJAMBU_FILES),$(SRCDIR)/$(file)) TinyJAMBU

tinyjambu_masked:
	cp $(foreach file,$(TINYJAMBU_MASKED_FILES),$(SRCDIR)/$(file)) TinyJAMBU_masked

xoodyak:
	cp $(foreach file,$(XOODYAK_FILES),$(SRCDIR)/$(file)) Xoodyak

xoodyak_masked:
	cp $(foreach file,$(XOODYAK_MASKED_FILES),$(SRCDIR)/$(file)) Xoodyak_masked
