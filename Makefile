PROJECT = orcavpn
SERVER = vpnserver
CLIENT = vpnclient
SOURCES = $(wildcard *.c)
HEADERS = $(filter-out $(SERVER).h $(CLIENT).h, $(SOURCES:.c=.h))
OBJECTS = $(SOURCES:.c=.o)
OBJECTS_SERVER = $(filter-out $(CLIENT).o, $(OBJECTS))
OBJECTS_CLIENT = $(filter-out $(SERVER).o, $(OBJECTS))
ARCHIEVE_FILES = $(SOURCES) $(HEADERS) Makefile README.md LICENSE \
	scripts encrypt/*.[ch] encrypt/Makefile

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

$(PROJECT).tar: $(ARCHIEVE_FILES)
	tar -cf $@ $(ARCHIEVE_FILES)

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
