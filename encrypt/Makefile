LIBNAME = encrypt
LIBFILE = lib$(LIBNAME).a

SOURCES = $(wildcard *.c)
HEADERS = $(SOURCES:.c=.h)
OBJECTS = $(SOURCES:.c=.o)

ARFLAGS = crs
AR = ar
CFLAGS = -Wall -Wextra -ansi -pedantic -Ofast -g
CC = gcc
CTAGS = ctags

default: $(LIBFILE)

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
