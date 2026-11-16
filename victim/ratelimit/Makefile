CLANG ?= clang
CC ?= cc
PKG_CONFIG ?= pkg-config

BPF_CPPFLAGS := -I/usr/include/$(shell gcc -dumpmachine)
BPF_CFLAGS := -O2 -g -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 -Wall -Wextra
USER_CFLAGS := -O2 -g -Wall -Wextra
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf)

.PHONY: all clean

all: ratelimit.bpf.o ratelimit

ratelimit.bpf.o: ratelimit.bpf.c ratelimit.h
	$(CLANG) $(BPF_CPPFLAGS) $(BPF_CFLAGS) -c $< -o $@

ratelimit: ratelimit.c ratelimit.h
	$(CC) $(USER_CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

clean:
	rm -f ratelimit.bpf.o ratelimit
