
include ../../options.mak

.PHONY: all clean check individual

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)

LIBRARY = libcryptolw.a

OBJS = \
	aead-metadata.o \
	aead-random.o \
        ascon128.o \
        ascon128-masked.o \
        ascon-hash.o \
        ascon-xof.o \
        elephant-delirium.o \
        elephant-dumbo.o \
        elephant-jumbo.o \
        gift-cofb.o \
        gift-cofb-masked.o \
	grain128.o \
        isap.o \
        photon-beetle-aead.o \
        photon-beetle-hash.o \
        romulus-aead.o \
        romulus-hash.o \
        sparkle-aead.o \
        sparkle-hash.o \
        tinyjambu.o \
        tinyjambu-masked.o \
        xoodyak.o \
        xoodyak-masked.o \
	internal-ascon.o \
	internal-ascon-m.o \
	internal-blake2s.o \
	internal-chachapoly.o \
	internal-gift128.o \
	internal-gift128-m.o \
	internal-grain128.o \
	internal-keccakp-200.o \
	internal-keccakp-400.o \
	internal-photon256.o \
	internal-skinny-plus.o \
        internal-sparkle.o \
        internal-spongent.o \
        internal-tinyjambu.o \
        internal-tinyjambu-m.o \
        internal-xoodoo.o \
        internal-xoodoo-m.o \
	internal-util.o

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	rm -f $(LIBRARY)
	$(AR) rc $(LIBRARY) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBRARY)

check: all

individual:
	(cd ../individual ; $(MAKE) all)

aead-metadata.o: aead-metadata.h aead-random.h internal-masking.h \
	internal-util.h ascon128.h ascon128-masked.h ascon-hash.h ascon-xof.h \
	elephant-delirium.h elephant-dumbo.h elephant-jumbo.h \
	gift-cofb.h gift-cofb-masked.h grain128.h isap.h \
	photon-beetle-aead.h photon-beetle-hash.h \
	romulus-aead.h romulus-hash.h \
	sparkle-aead.h sparkle-hash.h \
	tinyjambu.h tinyjambu-masked.h xoodyak.h xoodyak-masked.h
aead-random.o: aead-random.h
ascon128.o: ascon128.h internal-ascon.h internal-util.h
ascon128-masked.o: ascon128-masked.h internal-ascon.h internal-ascon-m.h aead-random.h internal-masking.h internal-util.h
ascon-hash.o: ascon-hash.h ascon-xof.h
ascon-xof.o: ascon-xof.h internal-ascon.h internal-util.h
elephant-delirium.o: elephant-delirium.h internal-keccakp-200.h internal-util.h
elephant-dumbo.o: elephant-dumbo.h internal-spongent.h internal-util.h
elephant-jumbo.o: elephant-jumbo.h internal-spongent.h internal-util.h
gift-cofb.o: gift-cofb.h internal-gift128.h internal-gift128-config.h internal-util.h
gift-cofb-masked.o: gift-cofb.h internal-gift128-m.h internal-gift128-config.h internal-util.h aead-random.h internal-masking.h
grain128.o: grain128.h internal-grain128.h internal-util.h
isap.o: isap.h internal-isap.h internal-ascon.h internal-keccakp-400.h internal-util.h
photon-beetle-aead.o: photon-beetle-aead.h internal-photon256.h internal-util.h
photon-beetle-hash.o: photon-beetle-hash.h internal-photon256.h internal-util.h
romulus-aead.o: romulus-aead.h internal-skinny-plus.h internal-util.h
romulus-hash.o: romulus-hash.h internal-skinny-plus.h internal-skinny-plus-config.h
sparkle-aead.o: sparkle-aead.h internal-sparkle.h internal-util.h
sparkle-hash.o: sparkle-hash.h internal-sparkle.h internal-util.h
tinyjambu.o: tinyjambu.h internal-tinyjambu.h internal-util.h
tinyjambu-masked.o: tinyjambu-masked.h internal-tinyjambu-m.h aead-random.h internal-masking.h internal-util.h
xoodyak.o: xoodyak.h internal-xoodoo.h internal-util.h
xoodyak-masked.o: xoodyak.h internal-xoodoo.h internal-xoodoo-m.h aead-random.h internal-masking.h internal-util.h
internal-ascon.o: internal-ascon.h internal-util.h
internal-ascon-m.o: internal-ascon-m.h internal-ascon.h aead-random.h internal-masking.h internal-util.h
internal-blake2s.o: internal-blake2s.h internal-util.h aead-metadata.h
internal-chachapoly.o: internal-chachapoly.h internal-util.h aead-metadata.h
internal-gift128.o: internal-gift128.h internal-gift128-config.h internal-util.h
internal-gift128-m.o: internal-gift128-m.h internal-gift128-config.h aead-random.h internal-masking.h internal-util.h
internal-grain128.o: internal-grain128.h internal-util.h
internal-keccakp-200.o: internal-keccakp-200.h internal-util.h
internal-keccakp-400.o: internal-keccakp-400.h internal-util.h
internal-photon256.o: internal-photon256.h internal-photon256-mix.h internal-util.h
internal-skinny-plus.o: internal-skinny-plus.h internal-skinny-plus-config.h internal-util.h
internal-sparkle.o: internal-sparkle.h internal-util.h
internal-spongent.o: internal-spongent.h internal-util.h
internal-tinyjambu.o: internal-tinyjambu.h internal-util.h
internal-tinyjambu-m.o: internal-tinyjambu-m.h aead-random.h internal-masking.h internal-util.h
internal-xoodoo.o: internal-xoodoo.h internal-util.h
internal-xoodoo-m.o: internal-xoodoo-m.h aead-random.h internal-masking.h internal-util.h
internal-util.o: internal-util.h
