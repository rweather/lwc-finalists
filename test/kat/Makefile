
include ../../options.mak

LIBSRC_DIR = ../../src/combined

.PHONY: all clean check perf

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I$(LIBSRC_DIR)
LDFLAGS += $(COMMON_LDFLAGS) -L$(LIBSRC_DIR) -lcryptolw

TARGET1 = kat
TARGET2 = kat-gen

OBJS1 = \
    kat.o \
    algorithms.o \
    timing.o

OBJS2 = \
    kat-gen.o \
    algorithms.o

DEPS = $(LIBSRC_DIR)/libcryptolw.a

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

$(TARGET2): $(OBJS2) $(DEPS)
	$(CC) -o $(TARGET2) $(OBJS2) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

RUN_KAT = $(SHELL) ./kat-run.sh ./$(TARGET1) ./$(TARGET2)

check: $(TARGET1) $(TARGET2)
	@$(RUN_KAT) ASCON-128 ASCON-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-128a ASCON-128a.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-80pq ASCON-80pq.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-128-Masked ASCON-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-128a-Masked ASCON-128a.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-80pq-Masked ASCON-80pq.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-128-SIV ASCON-128-SIV.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-128a-SIV ASCON-128a-SIV.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-80pq-SIV ASCON-80pq-SIV.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-HASH ASCON-HASH.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ASCON-XOF ASCON-XOF.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Delirium Delirium.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Dumbo Dumbo.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Esch256 Esch256.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Esch384 Esch384.txt $(KAT_OPTIONS)
	@$(RUN_KAT) GIFT-COFB GIFT-COFB.txt $(KAT_OPTIONS)
	@$(RUN_KAT) GIFT-COFB-Masked GIFT-COFB.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Grain-128AEAD Grain-128AEAD.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ISAP-A-128 ISAP-A-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ISAP-A-128A ISAP-A-128A.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ISAP-K-128 ISAP-K-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ISAP-K-128A ISAP-K-128A.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ISAP-A-128-pk ISAP-A-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ISAP-A-128A-pk ISAP-A-128A.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ISAP-K-128-pk ISAP-K-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) ISAP-K-128A-pk ISAP-K-128A.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Jumbo Jumbo.txt $(KAT_OPTIONS)
	@$(RUN_KAT) PHOTON-Beetle-AEAD-ENC-128 PHOTON-Beetle-AEAD-ENC-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) PHOTON-Beetle-AEAD-ENC-32 PHOTON-Beetle-AEAD-ENC-32.txt $(KAT_OPTIONS)
	@$(RUN_KAT) PHOTON-Beetle-HASH PHOTON-Beetle-HASH.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Romulus-H Romulus-H.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Romulus-N Romulus-N.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Romulus-M Romulus-M.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Schwaemm256-128 Schwaemm256-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Schwaemm192-192 Schwaemm192-192.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Schwaemm128-128 Schwaemm128-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Schwaemm256-256 Schwaemm256-256.txt $(KAT_OPTIONS)
	@$(RUN_KAT) TinyJAMBU-128 TinyJAMBU-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) TinyJAMBU-192 TinyJAMBU-192.txt $(KAT_OPTIONS)
	@$(RUN_KAT) TinyJAMBU-256 TinyJAMBU-256.txt $(KAT_OPTIONS)
	@$(RUN_KAT) TinyJAMBU-128-Masked TinyJAMBU-128.txt $(KAT_OPTIONS)
	@$(RUN_KAT) TinyJAMBU-192-Masked TinyJAMBU-192.txt $(KAT_OPTIONS)
	@$(RUN_KAT) TinyJAMBU-256-Masked TinyJAMBU-256.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Xoodyak Xoodyak.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Xoodyak-Masked Xoodyak.txt $(KAT_OPTIONS)
	@$(RUN_KAT) Xoodyak-Hash Xoodyak-Hash.txt $(KAT_OPTIONS)

perf:
	@$(MAKE) check KAT_OPTIONS=--performance

kat.o: algorithms.h timing.h $(wildcard $(LIBSRC_DIR)/*.h)
kat-gen.o: algorithms.h $(wildcard $(LIBSRC_DIR)/*.h)
algorithms.o: algorithms.h $(wildcard $(LIBSRC_DIR)/*.h)
timing.o: timing.h $(wildcard $(LIBSRC_DIR)/*.h)
