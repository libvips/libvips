noinst_LTLIBRARIES = libmask.la

libmask_la_SOURCES = \
	rotmask.c \
	im_gaussmasks.c \
	im_logmasks.c \
	rw_mask.c \
	im_matcat.c \
	im_matinv.c \
	im_matmul.c \
	im_mattrn.c \
	matalloc.c \
	mask_dispatch.c

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
