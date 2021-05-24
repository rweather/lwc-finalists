
# Machine-selection flags, e.g. -mcpu=cortex-m3 -mthumb
MACHINE_FLAGS =

# Common optimization and warning CFLAGS for compiling all source files.
COMMON_CFLAGS = $(MACHINE_FLAGS) -O3 -Wall -Wextra

# Common linker flags.
COMMON_LDFLAGS =

# Select the C or C++ standard to compile the core library with.
STDC_CFLAGS = -std=c99
STDC_CXXFLAGS = -std=c++11

# Compiling pre-processed assembly code.
CC_ASM = $(CC) -x assembler-with-cpp $(MACHINE_FLAGS)
