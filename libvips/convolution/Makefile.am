noinst_LTLIBRARIES = libconvolution.la

libconvolution_la_SOURCES = \
	convolution.c \
	pconvolution.h \
	correlation.c \
	correlation.h \
	conv.c \
	convsep.c \
	compass.c \
	morph.c \
	fastcor.c \
	spcor.c \
	sharpen.c \
	im_aconv.c \
	im_aconvsep.c \
	im_conv.c \
	im_conv_f.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
