noinst_LTLIBRARIES = libnsgif.la

MY_SOURCES = \
	libnsgif.h \
	libnsgif.c \
	lzw.c \
	lzw.h

if ENABLE_NSGIF
libnsgif_la_SOURCES = $(MY_SOURCES)
endif

EXTRA_DIST = \
	README-ns \
	README.md \
	patches \
	update.sh \
	utils 

if !ENABLE_NSGIF
EXTRA_DIST += \
	$(MY_SOURCES) 
endif
