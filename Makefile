PROJECT = orcavpn
SOURCES = $(wildcard *.c)
HEADERS = $(filter-out main.h, $(SOURCES:.c=.h))
OBJECTS = $(SOURCES:.c=.o)
ARCHIEVE_FILES = $(SOURCES) $(HEADERS) Makefile README.md LICENSE \
	scripts config encrypt/*.[ch] encrypt/Makefile

LIBDEPEND = encrypt/libencrypt.a
LOCALLIBS = -lencrypt -Lencrypt
CFLAGS = -Wall -Wextra -ansi -pedantic -Ofast -g
CC = gcc
CTAGS = ctags

HOST = artamonovgi@192.168.1.10
REMOTE_PATH = /home/artamonovgi/my/OrcaVPN

default: $(PROJECT)

$(PROJECT): $(OBJECTS) $(LIBDEPEND)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LOCALLIBS)

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
	rm -f $(PROJECT) *.o *.a *.bin deps.mk tags
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
