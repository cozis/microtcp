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

LIBDIR = 3p/lib
INCDIR = 3p/include

CFLAGS = $(CFLAGS_PLATFORM) -I$(INCDIR) -Ibuild/ -Wall -Wextra
LFLAGS = -ltuntap $(LFLAGS_PLATFORM) -L$(LIBDIR)

ifeq ($(MEMDBG),drmemory)
	CFLAGS += -gdwarf-2
else
	CFLAGS += -g
endif

.PHONY: all clean

all: build/microtcp.h build/microtcp.c build/echo_tcp build/echo_http

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

build/echo_tcp: examples/echo_tcp.c $(LIBDIR)/libtuntap.a 3p/include/tuntap.h 3p/include/tuntap-export.h build/microtcp.c build/microtcp.h
	mkdir -p $(@D)
	gcc build/microtcp.c examples/echo_tcp.c -o $@ $(CFLAGS) $(LFLAGS) -DDEBUG=1 -DARP_DEBUG -DMICROTCP_DEBUG -DIP_DEBUG -DICMP_DEBUG -DTCP_DEBUG -DMICROTCP_BACKGROUND_THREAD -DMICROTCP_USING_TAP -DMICROTCP_USING_MUX

build/microtcp.h: src/microtcp.h
	mkdir -p $(@D)
	[ ! -e $@ ] || rm $@
	echo "#define MICROTCP_AMALGAMATION" >> $@
	cat src/microtcp.h >> $@

build/microtcp.c: 3p/include/tinycthread.h 3p/src/tinycthread.c $(wildcard src/*.c src/*.h)
	mkdir -p $(@D)
	[ ! -e $@ ] || rm $@
	printf "#include \"microtcp.h\"\n" > $@
	printf "#ifdef MICROTCP_BACKGROUND_THREAD" >> $@
	printf "\n#line 1 \"3p/include/tinycthread.h\"\n" >> $@
	cat 3p/include/tinycthread.h >> $@
	printf "\n#line 1 \"3p/src/tinycthread.c\"\n" >> $@
	cat 3p/src/tinycthread.c >> $@
	printf "\n#endif /* MICROTCP_BACKGROUND_THREAD */" >> $@
	printf "\n#line 1 \"src/defs.h\"\n" >> $@
	cat src/defs.h >> $@
	printf "\n#line 1 \"src/endian.h\"\n" >> $@
	cat src/endian.h >> $@
	printf "\n#line 1 \"src/arp.h\"\n" >> $@
	cat src/arp.h    >> $@
	printf "\n#line 1 \"src/icmp.h\"\n" >> $@
	cat src/icmp.h   >> $@
	printf "\n#line 1 \"src/ip.h\"\n" >> $@
	cat src/ip.h     >> $@
	printf "\n#line 1 \"src/tcp.h\"\n" >> $@
	cat src/tcp.h    >> $@
	printf "\n#line 1 \"src/endian.c\"\n" >> $@
	cat src/endian.c >> $@
	printf "\n#line 1 \"src/arp.c\"\n" >> $@
	cat src/arp.c    >> $@
	printf "\n#line 1 \"src/icmp.c\"\n" >> $@
	cat src/icmp.c   >> $@
	printf "\n#line 1 \"src/ip.c\"\n" >> $@
	cat src/ip.c     >> $@
	printf "\n#line 1 \"src/tcp.c\"\n" >> $@
	cat src/tcp.c    >> $@
	printf "\n#line 1 \"src/microtcp.c\"\n" >> $@
	cat src/microtcp.c >> $@

build/echo_http: examples/microhttp/main.c $(LIBDIR)/libtuntap.a 3p/include/tuntap.h 3p/include/tuntap-export.h build/microtcp.h build/microtcp.c
	gcc examples/microhttp/main.c examples/microhttp/xhttp.c build/microtcp.c -o $@ $(CFLAGS) $(LFLAGS) -DDEBUG=1 -DARP_DEBUG -DMICROTCP_DEBUG -DIP_DEBUG -DICMP_DEBUG -DTCP_DEBUG -DMICROTCP_USING_MUX

clean:
	rm -fr build
	rm -fr 3p/libtuntap/build
	rm -f 3p/lib/* 3p/include/*