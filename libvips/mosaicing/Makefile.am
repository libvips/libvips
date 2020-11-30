noinst_LTLIBRARIES = libmosaicing.la

libmosaicing_la_SOURCES = \
	mosaicing.c \
	merge.c \
	mosaic.c \
	match.c \
	mosaic1.c  \
	chkpair.c \
	matrixinvert.c \
	global_balance.c \
	lrmerge.c \
	tbmerge.c \
	lrmosaic.c \
	tbmosaic.c \
	remosaic.c \
	im_avgdxdy.c \
	im_clinear.c \
	im_improve.c \
	im_initialize.c \
	im_lrcalcon.c \
	im_tbcalcon.c \
	global_balance.h \
	pmosaicing.h

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
