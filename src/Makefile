PROJECT = orcavpn
SOURCES = main.c vpnserver.c vpnclient.c eventloop.c sigevent.c \
	network.c tunnel.c logger.c helper.c configparser.c hashmap.c
HEADERS = $(filter-out main.h, $(SOURCES:.c=.h))
OBJECTS = $(SOURCES:.c=.o)

LIBDEPEND = encrypt/libencrypt.a
LOCALLIBS = -lencrypt -Lencrypt
LDLIBS = $(LOCALLIBS) #-lrt glibc<2.17
INC_DIRS = -I encrypt
STATIC = -static
CFLAGS = -Wall -Wextra -ansi -pedantic -O2 -g
CC = gcc
CTAGS = ctags

$(PROJECT): $(OBJECTS) $(LIBDEPEND)
	$(CC) $(CFLAGS) $(STATIC) -o $@ $(OBJECTS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INC_DIRS) -c -o $@ $<

encrypt/libencrypt.a:
	cd encrypt && $(MAKE)

deps.mk: $(SOURCES) Makefile
	$(CC) -MM $(SOURCES) $(INC_DIRS) > $@

tags: $(SOURCES) $(HEADERS)
	$(CTAGS) $(SOURCES) $(HEADERS) encrypt/*

clean:
	rm -f $(PROJECT) *.o *.a *.bin deps.mk tags
	cd encrypt && $(MAKE) clean

ifneq (clean, $(MAKECMDGOALS))
ifneq (tags, $(MAKECMDGOALS))
-include deps.mk
endif
endif
