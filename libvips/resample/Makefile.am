noinst_LTLIBRARIES = libresample.la

libresample_la_SOURCES = \
	im_affine.c \
	bicubic.cpp \
	interpolate.c \
	yafrsmooth.cpp \
	nohalo1.cpp \
	snohalo1.cpp \
	nohalo2.cpp \
	templates.h \
	transform.c \
	resample_dispatch.c

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
