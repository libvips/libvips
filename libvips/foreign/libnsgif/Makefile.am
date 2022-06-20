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
	meson.build \
	patches \
	README.md \
	README-ns.md \
	update.sh

if !ENABLE_NSGIF
EXTRA_DIST += \
	$(MY_SOURCES) 
endif
