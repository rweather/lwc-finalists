
include ../../options.mak

.PHONY: all clean check individual

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)

LIBRARY = libcryptolw.a

OBJS = \
	aead-common.o \
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
        photon-beetle.o \
        romulus.o \
        sparkle.o \
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
	internal-skinny128.o \
        internal-sparkle.o \
        internal-spongent.o \
        internal-tinyjambu.o \
        internal-tinyjambu-m.o \
        internal-xoodoo.o \
        internal-xoodoo-m.o

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	rm -f $(LIBRARY)
	$(AR) rc $(LIBRARY) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBRARY)

check: all

individual:
	(cd ../individual ; $(MAKE) all)

aead-common.o: aead-common.h
aead-random.o: aead-random.h
ascon128.o: ascon128.h aead-common.h internal-ascon.h internal-util.h
ascon128-masked.o: ascon128-masked.h aead-common.h internal-ascon.h internal-ascon-m.h aead-random.h internal-masking.h internal-util.h
ascon-hash.o: ascon128.h aead-common.h internal-ascon.h internal-util.h
ascon-xof.o: ascon128.h aead-common.h internal-ascon.h internal-util.h
elephant-delirium.o: elephant-delirium.h aead-common.h internal-keccakp-200.h internal-util.h
elephant-dumbo.o: elephant-dumbo.h aead-common.h internal-spongent.h internal-util.h
elephant-jumbo.o: elephant-jumbo.h aead-common.h internal-spongent.h internal-util.h
gift-cofb.o: gift-cofb.h aead-common.h internal-gift128.h internal-gift128-config.h internal-util.h
gift-cofb-masked.o: gift-cofb.h aead-common.h internal-gift128-m.h internal-gift128-config.h internal-util.h aead-random.h internal-masking.h
grain128.o: grain128.h internal-grain128.h aead-common.h internal-util.h
isap.o: isap.h aead-common.h internal-isap.h internal-ascon.h internal-keccakp-400.h internal-util.h
photon-beetle.o: photon-beetle.h internal-photon256.h internal-util.h
romulus.o: romulus.h internal-skinny128.h aead-common.h internal-util.h
sparkle.o: sparkle.h internal-sparkle.h aead-common.h internal-util.h
tinyjambu.o: tinyjambu.h internal-tinyjambu.h aead-common.h internal-util.h
tinyjambu-masked.o: tinyjambu-masked.h internal-tinyjambu-m.h aead-common.h aead-random.h internal-masking.h internal-util.h
xoodyak.o: xoodyak.h internal-xoodoo.h aead-common.h internal-util.h
xoodyak-masked.o: xoodyak.h internal-xoodoo.h internal-xoodoo-m.h aead-random.h internal-masking.h aead-common.h internal-util.h
internal-ascon.o: internal-ascon.h internal-util.h
internal-ascon-m.o: internal-ascon-m.h internal-ascon.h aead-random.h internal-masking.h internal-util.h
internal-blake2s.o: internal-blake2s.h internal-util.h
internal-chachapoly.o: internal-chachapoly.h internal-util.h
internal-gift128.o: internal-gift128.h internal-gift128-config.h internal-util.h
internal-gift128-m.o: internal-gift128-m.h internal-gift128-config.h aead-random.h internal-masking.h internal-util.h
internal-grain128.o: internal-grain128.h internal-util.h
internal-keccakp-200.o: internal-keccakp-200.h internal-util.h
internal-keccakp-400.o: internal-keccakp-400.h internal-util.h
internal-photon256.o: internal-photon256.h internal-util.h
internal-skinny128.o: internal-skinny128.h internal-skinnyutil.h internal-util.h
internal-sparkle.o: internal-sparkle.h internal-util.h
internal-spongent.o: internal-spongent.h internal-util.h
internal-tinyjambu.o: internal-tinyjambu.h
internal-tinyjambu-m.o: internal-tinyjambu-m.h aead-random.h internal-masking.h internal-util.h
internal-xoodoo.o: internal-xoodoo.h internal-util.h
internal-xoodoo-m.o: internal-xoodoo-m.h aead-random.h internal-masking.h internal-util.h
