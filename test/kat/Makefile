
include ../../options.mak

LIBSRC_DIR = ../../src/combined

.PHONY: all clean check

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I$(LIBSRC_DIR)
LDFLAGS += $(COMMON_LDFLAGS) -L$(LIBSRC_DIR) -lcryptolw

TARGET1 = kat
TARGET2 = kat-gen

OBJS1 = \
    kat.o \
    algorithms.o

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
	@$(RUN_KAT) ASCON-128 ASCON-128.txt
	@$(RUN_KAT) ASCON-128a ASCON-128a.txt
	@$(RUN_KAT) ASCON-80pq ASCON-80pq.txt
	@$(RUN_KAT) ASCON-128-Masked ASCON-128.txt
	@$(RUN_KAT) ASCON-128a-Masked ASCON-128a.txt
	@$(RUN_KAT) ASCON-80pq-Masked ASCON-80pq.txt
	@$(RUN_KAT) ASCON-HASH ASCON-HASH.txt
	@$(RUN_KAT) ASCON-XOF ASCON-XOF.txt
	@$(RUN_KAT) Delirium Delirium.txt
	@$(RUN_KAT) Dumbo Dumbo.txt
	@$(RUN_KAT) Esch256 Esch256.txt
	@$(RUN_KAT) Esch384 Esch384.txt
	@$(RUN_KAT) GIFT-COFB GIFT-COFB.txt
	@$(RUN_KAT) GIFT-COFB-Masked GIFT-COFB.txt
	@$(RUN_KAT) Grain-128AEAD Grain-128AEAD.txt
	@$(RUN_KAT) ISAP-A-128 ISAP-A-128.txt
	@$(RUN_KAT) ISAP-A-128A ISAP-A-128A.txt
	@$(RUN_KAT) ISAP-K-128 ISAP-K-128.txt
	@$(RUN_KAT) ISAP-K-128A ISAP-K-128A.txt
	@$(RUN_KAT) Jumbo Jumbo.txt
	@$(RUN_KAT) PHOTON-Beetle-AEAD-ENC-128 PHOTON-Beetle-AEAD-ENC-128.txt
	@$(RUN_KAT) PHOTON-Beetle-AEAD-ENC-32 PHOTON-Beetle-AEAD-ENC-32.txt
	@$(RUN_KAT) PHOTON-Beetle-HASH PHOTON-Beetle-HASH.txt
	@$(RUN_KAT) Romulus-N1 Romulus-N1.txt
	@$(RUN_KAT) Romulus-N2 Romulus-N2.txt
	@$(RUN_KAT) Romulus-N3 Romulus-N3.txt
	@$(RUN_KAT) Romulus-M1 Romulus-M1.txt
	@$(RUN_KAT) Romulus-M2 Romulus-M2.txt
	@$(RUN_KAT) Romulus-M3 Romulus-M3.txt
	@$(RUN_KAT) Schwaemm256-128 Schwaemm256-128.txt
	@$(RUN_KAT) Schwaemm192-192 Schwaemm192-192.txt
	@$(RUN_KAT) Schwaemm128-128 Schwaemm128-128.txt
	@$(RUN_KAT) Schwaemm256-256 Schwaemm256-256.txt
	@$(RUN_KAT) TinyJAMBU-128 TinyJAMBU-128.txt
	@$(RUN_KAT) TinyJAMBU-192 TinyJAMBU-192.txt
	@$(RUN_KAT) TinyJAMBU-256 TinyJAMBU-256.txt
	@$(RUN_KAT) TinyJAMBU-128-Masked TinyJAMBU-128.txt
	@$(RUN_KAT) TinyJAMBU-192-Masked TinyJAMBU-192.txt
	@$(RUN_KAT) TinyJAMBU-256-Masked TinyJAMBU-256.txt
	@$(RUN_KAT) Xoodyak Xoodyak.txt
	@$(RUN_KAT) Xoodyak-Masked Xoodyak.txt
	@$(RUN_KAT) Xoodyak-Hash Xoodyak-Hash.txt

kat.o: algorithms.h $(wildcard $(LIBSRC_DIR)/*.h)
kat-gen.o: algorithms.h $(wildcard $(LIBSRC_DIR)/*.h)
algorithms.o: algorithms.h $(wildcard $(LIBSRC_DIR)/*.h)
