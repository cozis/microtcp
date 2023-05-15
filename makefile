ifeq ($(OS),Windows_NT)
	OSNAME = windows
    ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
    	ARCH = AMD64
    else ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
    	ARCH = AMD64
	else ifeq ($(PROCESSOR_ARCHITECTURE),x86)
        ARCH = IA32
	endif
else
	UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        OSNAME = linux
    else ifeq ($(UNAME_S),Darwin)
        OSNAME = osx
    endif

    UNAME_P := $(shell uname -p)
    ifeq ($(UNAME_P),x86_64)
        ARCH = AMD64
    endif
    ifneq ($(filter %86,$(UNAME_P)),)
        ARCH = IA32
    endif
    ifneq ($(filter arm%,$(UNAME_P)),)
        ARCH = ARM
    endif
endif

ifeq ($(OSNAME),windows)
	CC  = gcc.exe
	CXX = g++.exe
	CFLAGS_PLATFORM =
	LFLAGS_PLATFORM = -lws2_32
	CMAKE_GENERATOR = "MinGW Makefiles"
else ifeq ($(OSNAME),linux)
	CC  = gcc
	CXX = g++
	CFLAGS_PLATFORM = -pthread 
	LFLAGS_PLATFORM =
	CMAKE_GENERATOR = "Unix Makefiles"
else
endif

# One of: drmemory, valgrind
MEMDBG=valgrind

LIBDIR = 3p/lib/
INCDIR = 3p/include/

CFLAGS = $(CFLAGS_PLATFORM) -I$(INCDIR) -Iinclude/ -Wall -Wextra -DARP_DEBUG -DMICROTCP_DEBUG -DIP_DEBUG -DICMP_DEBUG -DTCP_DEBUG -DMICROTCP_BACKGROUND_THREAD -DMICROTCP_USING_TAP
LFLAGS = -ltuntap $(LFLAGS_PLATFORM) -L$(LIBDIR)

ifeq ($(MEMDBG),drmemory)
	CFLAGS += -gdwarf-2
else
	CFLAGS += -g
endif

INCDIR=3p/include
LIBDIR=3p/lib

.PHONY: all clean

all: loop2

3p/lib/libtuntap.a: 3p/libtuntap/build/lib/libtuntap.a
	cp 3p/libtuntap/build/lib/libtuntap.a $(LIBDIR)

3p/include/tuntap.h: 3p/libtuntap/tuntap.h
	cp 3p/libtuntap/tuntap.h $(INCDIR)

3p/include/tuntap-export.h: 3p/libtuntap/build/tuntap-export.h
	cp 3p/libtuntap/build/tuntap-export.h $(INCDIR)

3p/libtuntap/build/lib/libtuntap.a 3p/libtuntap/tuntap.h 3p/libtuntap/build/tuntap-export.h:
	cd 3p/libtuntap/      \
		&& mkdir -p build \
		&& cd build       \
		&& cmake .. -G $(CMAKE_GENERATOR)       \
		            -DBUILD_TESTING=OFF         \
		            -DCMAKE_C_COMPILER=$(CC)    \
		            -DCMAKE_CXX_COMPILER=$(CXX) \
		            -DCMAKE_BUILD_TYPE=Debug    \
		&& make

3p/include/tinycthread.h: 3p/tinycthread/source/tinycthread.h
	cp 3p/tinycthread/source/tinycthread.h 3p/include

3p/src/tinycthread.c: 3p/tinycthread/source/tinycthread.c
	cp 3p/tinycthread/source/tinycthread.c 3p/src

loop2: $(LIBDIR)/libtuntap.a 3p/include/tuntap.h 3p/include/tuntap-export.h 3p/src/tinycthread.c 3p/include/tinycthread.h
	gcc src/endian.c src/arp.c src/ip.c src/icmp.c src/tcp.c src/microtcp.c test/loop2.c 3p/src/tinycthread.c -o loop2 $(CFLAGS) $(LFLAGS)

clean:
	rm -f loop2 loop2.exe
	rm -fr 3p/libtuntap/build
	rm -f 3p/lib/* 3p/include/*