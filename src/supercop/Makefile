
include ../../options.mak

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS)

TAG = rhys
BUILD_TAG = $(TAG)

AEAD_DIRS = $(wildcard out/*/Implementations/crypto_aead/*/$(BUILD_TAG))
HASH_DIRS = $(wildcard out/*/Implementations/crypto_hash/*/$(BUILD_TAG))
BOTH_DIRS = $(wildcard out/*/Implementations/crypto_aead_hash/*/$(BUILD_TAG))

.PHONY: all clean generate check

all: generate

clean:
	rm -rf out kat-aead kat-hash

generate:
	./supercop-gen.sh $(TAG)

check: generate
	@for dir in $(AEAD_DIRS) $(BOTH_DIRS) ; do \
        	CC=$(CC) CFLAGS="$(CFLAGS)" ./build-aead.sh $$dir ; \
        done
	@for dir in $(HASH_DIRS) $(BOTH_DIRS) ; do \
        	CC=$(CC) CFLAGS="$(CFLAGS)" ./build-hash.sh $$dir ; \
        done
	@rm -f kat-aead kat-hash
