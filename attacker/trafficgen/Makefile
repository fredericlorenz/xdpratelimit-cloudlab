CC ?= gcc
CFLAGS ?= -O3 -Wall -Wextra -std=gnu11

OBJS = main.o rss.o profiles.o net_tx.o

all: trafficgen

trafficgen: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c trafficgen.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) trafficgen

.PHONY: all clean
