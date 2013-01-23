noinst_LTLIBRARIES = libmorphology.la

libmorphology_la_SOURCES = \
	im_cntlines.c \
	morphology.c\
	im_rank.c \
	im_rank_image.c \
	im_zerox.c \
	morph_dispatch.c \
	im_label_regions.c \
	im_profile.c

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
