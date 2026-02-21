# =============================================================================
# NativeTest/Makefile
#
# Builds SupplicantDxe crypto unit tests natively on macOS arm64 using:
#   - Apple clang (system)
#   - OpenSSL 3.x from Homebrew (crypto backend replacing BaseCryptLib)
#   - GoogleTest from Homebrew
#
# Usage:
#   make         — build all test binaries
#   make run     — build and run all tests
#   make clean   — remove build artefacts
# =============================================================================

OPENSSL_PREFIX  := /opt/homebrew/opt/openssl@3
GTEST_PREFIX    := /opt/homebrew

CC   := clang
CXX  := clang++

# Source roots
SRC_DIR  := ..
TEST_DIR := ../GoogleTest
NAT_DIR  := .

# Compiler flags shared by C and C++ compilations
COMMON_FLAGS := \
  -I$(NAT_DIR)/include \
  -I$(OPENSSL_PREFIX)/include \
  -Wall \
  -Wno-unused-function \
  -Wno-deprecated-declarations

CFLAGS   := $(COMMON_FLAGS) -std=c11
CXXFLAGS := $(COMMON_FLAGS) -std=c++17 -I$(GTEST_PREFIX)/include

LDFLAGS  := \
  -L$(OPENSSL_PREFIX)/lib \
  -L$(GTEST_PREFIX)/lib \
  -lssl -lcrypto \
  -lgtest -lgtest_main \
  -lpthread

# =============================================================================
# Object files
# =============================================================================

OBJS_CRYPTO := \
  WpaCrypto.o \
  BaseCryptShim.o

TARGET_CRYPTO := SupplicantCryptoTest

# =============================================================================
# Default target
# =============================================================================

.PHONY: all run clean

all: $(TARGET_CRYPTO)

# =============================================================================
# Link
# =============================================================================

$(TARGET_CRYPTO): $(OBJS_CRYPTO) SupplicantDxeGoogleTest.o
	$(CXX) $^ $(LDFLAGS) -o $@

# =============================================================================
# Compile: production source (C)
# =============================================================================

WpaCrypto.o: $(SRC_DIR)/WpaCrypto.c
	$(CC) $(CFLAGS) -c $< -o $@

BaseCryptShim.o: $(NAT_DIR)/BaseCryptShim.c
	$(CC) $(CFLAGS) -c $< -o $@

# =============================================================================
# Compile: test source (C++)
# =============================================================================

SupplicantDxeGoogleTest.o: $(TEST_DIR)/SupplicantDxeGoogleTest.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# =============================================================================
# Run
# =============================================================================

run: all
	./$(TARGET_CRYPTO) --gtest_color=yes

# =============================================================================
# Clean
# =============================================================================

clean:
	rm -f *.o $(TARGET_CRYPTO)
