
SRCDIR = ../combined

COMMON_FILES = \
	aead-common.h \
	aead-common.c \
	internal-util.h
COMMON_MASKING_FILES = \
	aead-common.h \
	aead-common.c \
	aead-random.h \
	aead-random.c \
	internal-masking.h \
	internal-util.h

ASCON_FILES = \
    ascon128.c \
    ascon128.h \
    ascon-hash.c \
    ascon-xof.c \
    internal-ascon.c \
    internal-ascon.h \
    internal-ascon-armv7m.S \
    internal-ascon-avr.S \
    $(COMMON_FILES)
ASCON_MASKED_FILES = \
    ascon128-masked.c \
    ascon128-masked.h \
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
    internal-keccakp-200.c \
    internal-keccakp-200.h \
    internal-keccakp-200-armv7m.S \
    internal-keccakp-200-avr.S \
    $(COMMON_FILES)
ELEPHANT_DUMBO_FILES = \
    elephant-dumbo.c \
    elephant-dumbo.h \
    internal-spongent.c \
    internal-spongent.h \
    internal-spongent-avr.S \
    $(COMMON_FILES)
ELEPHANT_JUMBO_FILES = \
    elephant-jumbo.c \
    elephant-jumbo.h \
    internal-spongent.c \
    internal-spongent.h \
    internal-spongent-avr.S \
    $(COMMON_FILES)
GIFT_COFB_FILES = \
    gift-cofb.c \
    gift-cofb.h \
    internal-gift128.c \
    internal-gift128.h \
    internal-gift128-config.h \
    internal-gift128b-full-armv7m.S \
    internal-gift128b-small-armv7m.S \
    internal-gift128b-tiny-armv7m.S \
    internal-gift128b-full-avr.S \
    internal-gift128b-small-avr.S \
    internal-gift128b-tiny-avr.S \
    $(COMMON_FILES)
GIFT_COFB_MASKED_FILES = \
    gift-cofb-masked.c \
    gift-cofb-masked.h \
    internal-gift128-config.h \
    internal-gift128-m.c \
    internal-gift128-m.h \
    $(COMMON_MASKING_FILES)
GRAIN128_FILES = \
    grain128.c \
    grain128.h \
    internal-grain128.c \
    internal-grain128.h \
    internal-grain128-armv7m.S \
    internal-grain128-avr.S \
    $(COMMON_FILES)
ISAP_FILES = \
    isap.c \
    isap.h \
    internal-ascon.c \
    internal-ascon.h \
    internal-ascon-armv7m.S \
    internal-ascon-avr.S \
    internal-isap.h \
    internal-keccakp-400.c \
    internal-keccakp-400.h \
    internal-keccakp-400-armv7m.S \
    internal-keccakp-400-avr.S \
    $(COMMON_FILES)
PHOTON_BEETLE_FILES = \
    photon-beetle.c \
    photon-beetle.h \
    photon-beetle-hash.c \
    internal-photon256.c \
    internal-photon256.h \
    internal-photon256-avr.S \
    $(COMMON_FILES)
ROMULUS_FILES = \
    romulus.c \
    romulus.h \
    internal-skinny-plus.c \
    internal-skinny-plus.h \
    internal-skinny-small-armv7m.S \
    internal-skinny-tiny-armv7m.S \
    internal-skinny-tiny-avr.S \
    internal-skinny-plus-config.h \
    $(COMMON_FILES)
SPARKLE_FILES = \
    sparkle.c \
    sparkle.h \
    internal-sparkle.c \
    internal-sparkle.h \
    internal-sparkle-armv7m.S \
    internal-sparkle-avr.S \
    $(COMMON_FILES)
TINYJAMBU_FILES = \
    tinyjambu.c \
    tinyjambu.h \
    internal-tinyjambu.c \
    internal-tinyjambu.h \
    internal-tinyjambu-armv7m.S \
    internal-tinyjambu-avr.S \
    $(COMMON_FILES)
TINYJAMBU_MASKED_FILES = \
    tinyjambu-masked.c \
    tinyjambu-masked.h \
    internal-tinyjambu-m.c \
    internal-tinyjambu-m.h \
    $(COMMON_MASKING_FILES)
XOODYAK_FILES = \
    xoodyak.c \
    xoodyak.h \
    internal-xoodoo.c \
    internal-xoodoo.h \
    internal-xoodoo-armv7m.S \
    internal-xoodoo-avr.S \
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
    ascon \
    ascon_masked \
    elephant_delirium \
    elephant_dumbo \
    elephant_jumbo \
    gift_cofb \
    gift_cofb_masked \
    grain128 \
    isap \
    photon_beetle \
    romulus \
    sparkle \
    tinyjambu \
    tinyjambu_masked \
    xoodyak \
    xoodyak_masked

.PHONY: all $(ALL_ALGORITHMS)

all: $(ALL_ALGORITHMS)

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

isap:
	cp $(foreach file,$(ISAP_FILES),$(SRCDIR)/$(file)) ISAP

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
