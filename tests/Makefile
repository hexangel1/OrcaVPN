BUILD_TESTS = test_aes test_sha1
SOURCES_DIR = ../src/
PROJECT = $(SOURCES_DIR)orcavpn
LOCALLIBS = -lencrypt -L $(SOURCES_DIR)encrypt/
INC_DIRS = -I $(SOURCES_DIR) -I $(SOURCES_DIR)encrypt/
REQUIRED_MODULES = helper.c
OBJECTS = $(addprefix $(SOURCES_DIR), $(REQUIRED_MODULES:.c=.o))
CFLAGS = -Wall -Wextra -g
CC = gcc

default: $(BUILD_TESTS)

$(PROJECT):
	cd $(SOURCES_DIR) && $(MAKE)

rebuild:
	cd $(SOURCES_DIR) && $(MAKE) clean && $(MAKE)
	$(MAKE)

test_%: test_%.c test_common.h $(PROJECT)
	$(CC) $(CFLAGS) $(INC_DIRS) -o $@ $< $(OBJECTS) $(LOCALLIBS)

clean:
	rm -f $(BUILD_TESTS) *.o *.a *.bin
