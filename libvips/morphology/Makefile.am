noinst_LTLIBRARIES = libmorphology.la

libmorphology_la_SOURCES = \
	morphology.c \
	pmorphology.h \
	countlines.c \
	rank.c \
	hitmiss.c \
	morph.c \
	labelregions.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
