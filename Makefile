PROJECT = orcavpn
SERVER = vpnserver
CLIENT = vpnclient
SOURCES = $(wildcard *.c)
HEADERS = $(filter-out $(SERVER).h $(CLIENT).h, $(SOURCES:.c=.h))
SPECIAL = Makefile vpnserver-setup.sh

SOURCES_SERVER = $(filter-out $(CLIENT).c, $(SOURCES))
SOURCES_CLIENT = $(filter-out $(SERVER).c, $(SOURCES))
OBJECTS_SERVER = $(SOURCES_SERVER:.c=.o)
OBJECTS_CLIENT = $(SOURCES_CLIENT:.c=.o)

CFLAGS = -Wall -Wextra -ansi -pedantic -g
CC = gcc
CTAGS = ctags

HOST = artamonovgi@192.168.1.10
REMOTE_PATH = /home/artamonovgi/my/OrcaVPN

all: $(SERVER) $(CLIENT)

$(SERVER): $(OBJECTS_SERVER)
	$(CC) $(CFLAGS) -o $@ $^

$(CLIENT): $(OBJECTS_CLIENT)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

deps.mk: $(SOURCES) Makefile
	$(CC) -MM $(SOURCES) > $@

tags: $(SOURCES) $(HEADERS)
	$(CTAGS) $(SOURCES) $(HEADERS)

tar: $(PROJECT).tar

$(PROJECT).tar: $(SOURCES) $(HEADERS) $(SPECIAL)
	tar -cf $@ $(SOURCES) $(HEADERS) $(SPECIAL)

push:
	rsync -rvza -e 'ssh -p 503' * $(HOST):$(REMOTE_PATH)

clean:
	rm -f $(SERVER) $(CLIENT) *.o *.a *.bin deps.mk tags

ifneq (clean, $(MAKECMDGOALS))
ifneq (tags, $(MAKECMDGOALS))
ifneq (tar, $(MAKECMDGOALS))
-include deps.mk
endif
endif
endif
