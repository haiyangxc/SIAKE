####  Makefile for compilation on Unix-like operative systems  ####

OPT=-O3     # Optimization option by default

CC=gcc
ifeq "$(CC)" "gcc"
	COMPILER=gcc
else ifeq "$(CC)" "clang"
	COMPILER=clang
endif

ARCHITECTURE=_AMD64_
USE_OPT_LEVEL=_GENERIC_
ifeq "$(ARCH)" "x64"
	ARCHITECTURE=_AMD64_
	USE_OPT_LEVEL=_GENERIC_
else ifeq "$(ARCH)" "x86"
	ARCHITECTURE=_X86_
	USE_OPT_LEVEL=_GENERIC_
else ifeq "$(ARCH)" "s390x"
	ARCHITECTURE=_S390X_
	USE_OPT_LEVEL=_GENERIC_
else ifeq "$(ARCH)" "ARM"
	ARCHITECTURE=_ARM_
	USE_OPT_LEVEL=_GENERIC_
	ARM_TARGET=YES
else ifeq "$(ARCH)" "ARM64"
	ARCHITECTURE=_ARM64_
	USE_OPT_LEVEL=_GENERIC_
	ARM_TARGET=YES
endif

ifeq "$(OPT_LEVEL)" "GENERIC"
	USE_OPT_LEVEL=_GENERIC_
endif

ifeq "$(ARM_TARGET)" "YES"
	ARM_SETTING=-lrt
endif

ifeq "$(ARCHITECTURE)" "_AMD64_"
	ifeq "$(USE_OPT_LEVEL)" "_FAST_"
		MULX=-D _MULX_
		ifeq "$(USE_MULX)" "FALSE"
			MULX=
		else
			ADX=-D _ADX_
			ifeq "$(USE_ADX)" "FALSE"
				ADX=
			endif
		endif
	endif
endif

AR=ar rcs
RANLIB=ranlib

ADDITIONAL_SETTINGS=-march=native
ifeq "$(CC)" "clang"
ifeq "$(ARM_TARGET)" "YES"
	ADDITIONAL_SETTINGS=
endif
endif
ifeq "$(ARCHITECTURE)" "_S390X_"
	ADDITIONAL_SETTINGS=-march=z10
endif

CFLAGS=$(OPT) -std=gnu11 $(ADDITIONAL_SETTINGS) -D $(ARCHITECTURE) -D __NIX__ -D $(USE_OPT_LEVEL) $(MULX) $(ADX)
LDFLAGS=-lm
ifeq "$(USE_OPT_LEVEL)" "_GENERIC_"
	EXTRA_OBJECTS_751=objs751/fp_generic.o
else ifeq "$(USE_OPT_LEVEL)" "_FAST_"
ifeq "$(ARCHITECTURE)" "_AMD64_"
	EXTRA_OBJECTS_751=objs751/fp_x64.o objs751/fp_x64_asm.o
endif
endif
OBJECTS_751=objs751/P751.o $(EXTRA_OBJECTS_751) objs/random.o objs/fips202.o

all: lib751 tests

objs751/%.o: P751/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@

ifeq "$(USE_OPT_LEVEL)" "_GENERIC_"     
    objs751/fp_generic.o: P751/generic/fp_generic.c
	    $(CC) -c $(CFLAGS) P751/generic/fp_generic.c -o objs751/fp_generic.o
else ifeq "$(USE_OPT_LEVEL)" "_FAST_"
ifeq "$(ARCHITECTURE)" "_AMD64_"        
	objs751/fp_x64.o: P751/AMD64/fp_x64.c
		$(CC) -c $(CFLAGS) P751/AMD64/fp_x64.c -o objs751/fp_x64.o

	objs751/fp_x64_asm.o: P751/AMD64/fp_x64_asm.S
		$(CC) -c $(CFLAGS) P751/AMD64/fp_x64_asm.S -o objs751/fp_x64_asm.o
endif
endif

objs/random.o: random/random.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) random/random.c -o objs/random.o

objs/fips202.o: sha3/fips202.c
	$(CC) -c $(CFLAGS) sha3/fips202.c -o objs/fips202.o

lib751: $(OBJECTS_751)
	rm -rf lib751 sike
	mkdir lib751 sike
	$(AR) lib751/libsike.a $^
	$(RANLIB) lib751/libsike.a

tests: lib751
	$(CC) $(CFLAGS) -L./lib751 tests/test_SIKEp751.c tests/test_extras.c -lsike $(LDFLAGS) -o sike/test_AKE $(ARM_SETTING)

# AES
AES_OBJS=objs/aes.o objs/aes_c.o

objs/%.o: tests/aes/%.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $< -o $@



check: tests

.PHONY: clean

clean:
	rm -rf *.req objs751* objs lib751* sike 

