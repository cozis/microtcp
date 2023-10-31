
ifeq ($(OS),Windows_NT)
	OSTAG = WIN
	EXT = .exe
	CMAKE_GENERATOR = "MinGW Makefiles"
else
	UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
    	OSTAG = LIN
        EXT =
		CMAKE_GENERATOR = "Unix Makefiles"
    else ifeq ($(UNAME_S),Darwin)
    	$(error OSX isn't supported)
        OSNAME = osx
    endif
endif

AR  = ar$(EXT)
CC  = gcc$(EXT)
CXX = g++$(EXT)

SRCDIR = src
OBJDIR = obj
OUTDIR = out

CFILES = $(wildcard $(SRCDIR)/*.c)
HFILES = $(wildcard $(SRCDIR)/*.h)
OFILES = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(CFILES))

CFLAGS_WIN = 
CFLAGS_LIN = -pthread
CFLAGS = -Wall -Wextra -g $(CFLAGS_$(OSTAG)) -DMICROTCP_DEBUG -DTCP_DEBUG

LIBFILE = $(OUTDIR)/libmicrotcp.a

TAP_AFILES = $(OUTDIR)/libtuntap.a
TAP_HFILES = $(OUTDIR)/tuntap.h $(OUTDIR)/tuntap-export.h

EXAMPLE_0 = $(OUTDIR)/http$(EXT)
EXAMPLE_1 = $(OUTDIR)/echo$(EXT)

EXAMPLE_CFILES_0 = $(wildcard examples/http/*.c)
EXAMPLE_HFILES_0 = $(wildcard examples/http/*.h)

EXAMPLE_CFILES_1 = examples/echo.c
EXAMPLE_HFILES_1 = 

EXAMPLE_LFLAGS_WIN = -lws2_32
EXAMPLE_LFLAGS_LIN = 
EXAMPLE_LFLAGS = -lmicrotcp -ltuntap $(EXAMPLE_LFLAGS_$(OSTAG))

.PHONY: all exm lib clean

all: lib exm

exm: $(EXAMPLE_0) $(EXAMPLE_1)

lib: $(LIBFILE) $(TAP_HFILES) $(TAP_AFILES)
	cp $(SRCDIR)/microtcp.h $(OUTDIR)/microtcp.h

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HFILES) $(TAP_HFILES)
	$(CC) -c -o $@ $< $(CFLAGS) -I$(OUTDIR)

$(LIBFILE): $(OFILES)
	$(AR) rcs $@ $^

$(TAP_AFILES) $(TAP_HFILES):
	cd 3p/libtuntap/ && \
	mkdir -p build   && \
	cd build         && \
	cmake .. -G $(CMAKE_GENERATOR) -DBUILD_TESTING=OFF -DCMAKE_C_COMPILER=$(CC) -DCMAKE_CXX_COMPILER=$(CXX) -DCMAKE_BUILD_TYPE=Debug && \
	make
	cp 3p/libtuntap/build/lib/libtuntap.a $(OUTDIR)/libtuntap.a
	cp 3p/libtuntap/tuntap.h $(OUTDIR)/tuntap.h
	cp 3p/libtuntap/build/tuntap-export.h $(OUTDIR)/tuntap-export.h

$(EXAMPLE_0): lib $(EXAMPLE_CFILES_0) $(EXAMPLE_HFILES_0)
	$(CC) -o $@ $(EXAMPLE_CFILES_0) $(CFLAGS) $(EXAMPLE_LFLAGS) -I$(OUTDIR) -L$(OUTDIR)

$(EXAMPLE_1): lib $(EXAMPLE_CFILES_1) $(EXAMPLE_HFILES_1)
	$(CC) -o $@ $(EXAMPLE_CFILES_1) $(CFLAGS) $(EXAMPLE_LFLAGS) -I$(OUTDIR) -L$(OUTDIR)

clean:
	rm -fr $(OBJDIR) $(OUTDIR)
	mkdir obj out
