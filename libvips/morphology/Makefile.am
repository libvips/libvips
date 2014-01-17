noinst_LTLIBRARIES = libmorphology.la

libmorphology_la_SOURCES = \
	morphology.c \
	countlines.c \
	rank.c \
	hitmiss.c \
	morph.c \
	im_label_regions.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
