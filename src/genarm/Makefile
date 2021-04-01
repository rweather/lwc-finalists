
include ../../options.mak

.PHONY: all clean check generate

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter
LDFLAGS += $(COMMON_LDFLAGS)

TARGETS = \
	bin/ascon_arm_cortex_m3 \
	bin/gift128_arm_cortex_m3 \
	bin/tinyjambu_arm_cortex_m3 \
	bin/sparkle_arm_cortex_m3 \
	bin/xoodoo_arm_cortex_m3

all: $(TARGETS)

bin/ascon_arm_cortex_m3: ascon_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/gift128_arm_cortex_m3: gift128_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/tinyjambu_arm_cortex_m3: tinyjambu_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/sparkle_arm_cortex_m3: sparkle_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bin/xoodoo_arm_cortex_m3: xoodoo_arm_cortex_m3.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

check:

generate: all
	bin/ascon_arm_cortex_m3 >../combined/internal-ascon-arm-cm3.S
	bin/gift128_arm_cortex_m3 full bitsliced cofb-only >../combined/internal-gift128b-full-arm-cm3.S
	bin/gift128_arm_cortex_m3 small bitsliced cofb-only >../combined/internal-gift128b-small-arm-cm3.S
	bin/gift128_arm_cortex_m3 tiny bitsliced cofb-only >../combined/internal-gift128b-tiny-arm-cm3.S
	bin/tinyjambu_arm_cortex_m3 >../combined/internal-tinyjambu-arm-cm3.S
	bin/sparkle_arm_cortex_m3 >../combined/internal-sparkle-arm-cm3.S
	bin/xoodoo_arm_cortex_m3 >../combined/internal-xoodoo-arm-cm3.S
