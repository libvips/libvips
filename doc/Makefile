#

prefix = /home/john/vips

install all:
	cd src; $(MAKE) -f Makefile install
	echo "Making html man pages"
	./Makehtmlman $(prefix)/share/man/man1
	./Makehtmlman $(prefix)/share/man/man3

.PHONEY: clean
clean: 
	cd src; $(MAKE) -f Makefile clean
