noinst_LTLIBRARIES = libconvolution.la

libconvolution_la_SOURCES = \
	convolution.c \
	pconvolution.h \
	correlation.c \
	correlation.h \
	conv.c \
	convf.c \
	convi.c \
	convsep.c \
	compass.c \
	fastcor.c \
	spcor.c \
	sharpen.c \
	gaussblur.c \
	im_aconv.c \
	im_aconvsep.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
