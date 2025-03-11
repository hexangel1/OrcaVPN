PROJECT = orcavpn
ARCHIEVE_FILES = Makefile README.md LICENSE scripts config \
	src/*.[ch] src/*/*.[ch] src/Makefile src/*/Makefile

default: $(PROJECT)

$(PROJECT) tags clean:
	cd src && $(MAKE) $@

tar: $(PROJECT).tar

$(PROJECT).tar: $(ARCHIEVE_FILES)
	tar -cf $@ $(ARCHIEVE_FILES)
