noinst_LTLIBRARIES = libconvolution.la

libconvolution_la_SOURCES = \
	convolution.c \
	pconvolution.h \
	conv.c \
	compass.c \
	morph.c \
	convol_dispatch.c \
	im_addgnoise.c \
	im_compass.c \
	im_aconv.c \
	im_aconvsep.c \
	im_conv.c \
	im_conv_f.c \
	im_contrast_surface.c \
	im_fastcor.c \
	im_gradcor.c \
	im_sharpen.c \
	im_spcor.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
