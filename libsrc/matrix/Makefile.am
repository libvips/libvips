SUBDIRS = man3

noinst_LTLIBRARIES = libmatrix.la

libmatrix_la_SOURCES = \
	im_matcat.c \
	im_matinv.c \
	im_matmul.c \
	im_mattrn.c \
	matalloc.c \
	matrix_dispatch.c

INCLUDES = -I${top_srcdir}/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
