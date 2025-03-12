PROJECT = orcavpn
SOURCES = main.c vpnserver.c vpnclient.c eventloop.c sigevent.c \
	network.c logger.c helper.c configparser.c hashmap.c
HEADERS = $(filter-out main.h, $(SOURCES:.c=.h))
OBJECTS = $(SOURCES:.c=.o)

LIBDEPEND = encrypt/libencrypt.a
LOCALLIBS = -lencrypt -Lencrypt -lrt
CFLAGS = -Wall -Wextra -ansi -pedantic -O2 -g
CC = gcc
CTAGS = ctags

$(PROJECT): $(OBJECTS) $(LIBDEPEND)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LOCALLIBS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

encrypt/libencrypt.a:
	cd encrypt && $(MAKE)

deps.mk: $(SOURCES) Makefile
	$(CC) -MM $(SOURCES) > $@

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
