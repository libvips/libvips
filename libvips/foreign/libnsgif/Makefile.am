noinst_LTLIBRARIES = libnsgif.la

MY_SOURCES = \
	nsgif.h \
	gif.c \
	lzw.c \
	lzw.h

if ENABLE_NSGIF
libnsgif_la_SOURCES = $(MY_SOURCES)
endif

EXTRA_DIST = \
	README-ns.md \
	README.md \
	patches \
	update.sh

if !ENABLE_NSGIF
EXTRA_DIST += \
	$(MY_SOURCES) 
endif
