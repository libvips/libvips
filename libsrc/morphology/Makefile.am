SUBDIRS = man3

noinst_LTLIBRARIES = libmorphology.la

libmorphology_la_SOURCES = \
	im_cntlines.c \
	im_dilate.c\
	im_erode.c\
	morph_dispatch.c \
	im_profile.c

INCLUDES = -I${top_srcdir}/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
