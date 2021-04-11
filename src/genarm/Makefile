
include ../../options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_armv7m \
	bin/gift128_armv7m \
	bin/grain128_armv7m \
	bin/keccakp_200_armv7m \
	bin/keccakp_400_armv7m \
	bin/tinyjambu_armv7m \
	bin/photon256_armv7m \
	bin/skinny128_armv7m \
	bin/sparkle_armv7m \
	bin/spongent_armv7m \
	bin/xoodoo_armv7m

all: $(TARGETS)

bin/ascon_armv7m: ascon_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/gift128_armv7m: gift128_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/grain128_armv7m: grain128_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/keccakp_200_armv7m: keccakp_200_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/keccakp_400_armv7m: keccakp_400_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/photon256_armv7m: photon256_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/skinny128_armv7m: skinny128_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/sparkle_armv7m: sparkle_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/spongent_armv7m: spongent_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/tinyjambu_armv7m: tinyjambu_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/xoodoo_armv7m: xoodoo_armv7m.c copyright.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

check:

generate: all
	bin/ascon_armv7m >../combined/internal-ascon-armv7m.S
	bin/gift128_armv7m full bitsliced cofb-only >../combined/internal-gift128b-full-armv7m.S
	bin/gift128_armv7m small bitsliced cofb-only >../combined/internal-gift128b-small-armv7m.S
	bin/gift128_armv7m tiny bitsliced cofb-only >../combined/internal-gift128b-tiny-armv7m.S
	bin/grain128_armv7m >../combined/internal-grain128-armv7m.S
	bin/keccakp_200_armv7m >../combined/internal-keccakp-200-armv7m.S
	bin/keccakp_400_armv7m >../combined/internal-keccakp-400-armv7m.S
	bin/photon256_armv7m >../combined/internal-photon256-armv7m.S
	bin/tinyjambu_armv7m >../combined/internal-tinyjambu-armv7m.S
	bin/skinny128_armv7m full plus >../combined/internal-skinny-full-armv7m.S
	bin/skinny128_armv7m small plus >../combined/internal-skinny-small-armv7m.S
	bin/skinny128_armv7m tiny plus >../combined/internal-skinny-tiny-armv7m.S
	bin/sparkle_armv7m >../combined/internal-sparkle-armv7m.S
	bin/spongent_armv7m >../combined/internal-spongent-armv7m.S
	bin/xoodoo_armv7m >../combined/internal-xoodoo-armv7m.S
