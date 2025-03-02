PROJECT = orcavpn
ARCHIEVE_FILES = Makefile README.md LICENSE scripts config \
	src/*.[ch] src/*/*.[ch] src/Makefile src/*/Makefile

default: $(PROJECT)

$(PROJECT):
	cd src && $(MAKE) $@

tags:
	cd src && $(MAKE) $@

clean:
	cd src && $(MAKE) $@

tar: $(PROJECT).tar

$(PROJECT).tar: $(ARCHIEVE_FILES)
	tar -cf $@ $(ARCHIEVE_FILES)
