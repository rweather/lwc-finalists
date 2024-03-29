
include ../../options.mak

.PHONY: all clean check generate

CXXFLAGS += -g $(COMMON_CFLAGS) $(STDC_CXXFLAGS)

TARGET = genavr

OBJS = \
	algorithm_aes.o \
	algorithm_ascon.o \
	algorithm_ghash.o \
	algorithm_gift128.o \
	algorithm_gift128_fixsliced.o \
	algorithm_grain128.o \
	algorithm_keccak.o \
	algorithm_photon256.o \
	algorithm_sha256.o \
	algorithm_skinny128.o \
	algorithm_sparkle.o \
	algorithm_spongent.o \
	algorithm_tinyjambu.o \
	algorithm_xoodoo.o \
	code.o \
	code_out.o \
	interpret.o \
        main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)

check: all
	./$(TARGET) --test

code.o: code.h
code_out.o: code.h
algorithm_aes.o: code.h gen.h
algorithm_ascon.o: code.h gen.h
algorithm_ghash.o: code.h gen.h
algorithm_gift128.o: code.h gen.h
algorithm_gift128_fixsliced.o: code.h gen.h
algorithm_grain128.o: code.h gen.h
algorithm_keccak.o: code.h gen.h
algorithm_photon256.o: code.h gen.h
algorithm_sha256.o: code.h gen.h
algorithm_skinny128.o: code.h gen.h
algorithm_sparkle.o: code.h gen.h
algorithm_spongent.o: code.h gen.h
algorithm_tinyjambu.o: code.h gen.h
algorithm_xoodoo.o: code.h gen.h
interpret.o: code.h

generate: $(TARGET)
	./$(TARGET) AES >../combined/internal-aes-avr.S
	./$(TARGET) ASCON >../combined/internal-ascon-avr.S
	./$(TARGET) GHASH >../combined/internal-ghash-avr.S
	./$(TARGET) GIFT-COFB-128b-fs-4 >../combined/internal-gift128b-tiny-avr.S
	./$(TARGET) GIFT-COFB-128b-fs-20 >../combined/internal-gift128b-small-avr.S
	./$(TARGET) GIFT-COFB-128b-fs-80 >../combined/internal-gift128b-full-avr.S
	./$(TARGET) Grain-128 >../combined/internal-grain128-avr.S
	./$(TARGET) Keccakp-200 >../combined/internal-keccakp-200-avr.S
	./$(TARGET) Keccakp-400 >../combined/internal-keccakp-400-avr.S
	./$(TARGET) PHOTON-256 >../combined/internal-photon256-avr.S
	./$(TARGET) SHA256 >../combined/internal-sha256-avr.S
	./$(TARGET) SKINNY-128-384-Plus >../combined/internal-skinny-tiny-avr.S
	./$(TARGET) SPARKLE >../combined/internal-sparkle-avr.S
	./$(TARGET) Spongent-pi >../combined/internal-spongent-avr.S
	./$(TARGET) TinyJAMBU >../combined/internal-tinyjambu-avr.S
	./$(TARGET) Xoodoo >../combined/internal-xoodoo-avr.S
