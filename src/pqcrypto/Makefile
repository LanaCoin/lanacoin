# Builds libpqcrypto.a (ML-DSA-44) for the LanaCoin makefiles.
# CC, AR, RANLIB and CFLAGS can be overridden, e.g. for cross compiling.

CC ?= cc
AR ?= ar
RANLIB ?= ranlib
CFLAGS ?= -O2
PQCFLAGS = -std=c99 -Wall -Wextra -I. -Imldsa44 $(CFLAGS)

OBJS = \
    fips202.o \
    randombytes.o \
    mldsa44/ntt.o \
    mldsa44/packing.o \
    mldsa44/poly.o \
    mldsa44/polyvec.o \
    mldsa44/reduce.o \
    mldsa44/rounding.o \
    mldsa44/sign.o \
    mldsa44/symmetric-shake.o

all: libpqcrypto.a

libpqcrypto.a: $(OBJS)
	rm -f $@
	$(AR) rc $@ $(OBJS)
	$(RANLIB) $@

%.o: %.c
	$(CC) $(PQCFLAGS) -c -o $@ $<

$(OBJS): *.h mldsa44/*.h

clean:
	rm -f libpqcrypto.a $(OBJS)

.PHONY: all clean
