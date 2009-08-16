noinst_LTLIBRARIES = libmosaicing.la

libmosaicing_la_SOURCES = \
	im_align_bands.c \
	match.c \
	mosaic1.c  \
	mosaicing_dispatch.c \
	global_balance.c \
	im_avgdxdy.c \
	im_chkpair.c \
	im_clinear.c \
	im_improve.c \
	im_initialize.c \
	im_lrcalcon.c \
	im_lrmerge.c \
	im_lrmosaic.c \
	im_maxpos_subpel.c \
	im_tbcalcon.c \
	im_tbmerge.c \
	im_remosaic.c \
	im_tbmosaic.c \
	merge.h \
	global_balance.h \
	mosaic.h

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
