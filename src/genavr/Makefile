
include ../../options.mak

.PHONY: all clean check

CXXFLAGS += -g $(COMMON_CFLAGS) $(STDC_CXXFLAGS)

TARGET = genavr

OBJS = \
	algorithm_cham.o \
	algorithm_sparkle.o \
	algorithm_speck64.o \
	algorithm_tinyjambu.o \
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
algorithm_cham.o: code.h gen.h
algorithm_sparkle.o: code.h gen.h
algorithm_speck64.o: code.h gen.h
algorithm_tinyjambu.o: code.h gen.h
interpret.o: code.h