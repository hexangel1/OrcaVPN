LIBNAME = encrypt
LIBFILE = lib$(LIBNAME).a

SOURCES = encryption.c chacha20.c poly1305.c aes.c sha1.c
HEADERS = $(SOURCES:.c=.h)
OBJECTS = $(SOURCES:.c=.o)

ARFLAGS = crs
AR = ar
CFLAGS = -Wall -Wextra -ansi -pedantic -O2 -funroll-loops -g
CC = gcc
CTAGS = ctags

$(LIBFILE): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

deps.mk: $(SOURCES) Makefile
	$(CC) -MM $(SOURCES) > $@

tags: $(SOURCES) $(HEADERS)
	$(CTAGS) $(SOURCES) $(HEADERS)

clean:
	rm -f *.o *.a *.bin deps.mk tags

ifneq (clean, $(MAKECMDGOALS))
ifneq (tags, $(MAKECMDGOALS))
-include deps.mk
endif
endif
