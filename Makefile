PROJECT = orcavpn
SERVER = vpnserver
CLIENT = vpnclient
SOURCES = $(wildcard *.c)
HEADERS = $(filter-out $(SERVER).h $(CLIENT).h, $(SOURCES:.c=.h))
SPECIAL = Makefile README.md LICENSE scripts
LIBFILES = encrypt/*.[ch] encrypt/Makefile

SOURCES_SERVER = $(filter-out $(CLIENT).c, $(SOURCES))
SOURCES_CLIENT = $(filter-out $(SERVER).c, $(SOURCES))
OBJECTS_SERVER = $(SOURCES_SERVER:.c=.o)
OBJECTS_CLIENT = $(SOURCES_CLIENT:.c=.o)

LIBDEPEND = encrypt/libencrypt.a
LOCALLIBS = -lencrypt -Lencrypt
CFLAGS = -Wall -Wextra -ansi -pedantic -Ofast -g
CC = gcc
CTAGS = ctags

HOST = artamonovgi@192.168.1.10
REMOTE_PATH = /home/artamonovgi/my/OrcaVPN

all: $(SERVER) $(CLIENT)

$(SERVER): $(OBJECTS_SERVER) $(LIBDEPEND)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS_SERVER) $(LOCALLIBS)

$(CLIENT): $(OBJECTS_CLIENT) $(LIBDEPEND)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS_CLIENT) $(LOCALLIBS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

encrypt/libencrypt.a:
	cd encrypt && $(MAKE)

deps.mk: $(SOURCES) Makefile
	$(CC) -MM $(SOURCES) > $@

tags: $(SOURCES) $(HEADERS)
	$(CTAGS) $(SOURCES) $(HEADERS)

tar: $(PROJECT).tar

$(PROJECT).tar: $(SOURCES) $(HEADERS) $(SPECIAL) $(LIBFILES)
	tar -cf $@ $(SOURCES) $(HEADERS) $(SPECIAL) $(LIBFILES)

push:
	rsync -rvza -e 'ssh -p 503' * $(HOST):$(REMOTE_PATH)

clean:
	rm -f $(SERVER) $(CLIENT) *.o *.a *.bin deps.mk tags
	cd encrypt && $(MAKE) clean

ifneq (clean, $(MAKECMDGOALS))
ifneq (tags, $(MAKECMDGOALS))
ifneq (tar, $(MAKECMDGOALS))
ifneq (push, $(MAKECMDGOALS))
-include deps.mk
endif
endif
endif
endif
