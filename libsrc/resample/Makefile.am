noinst_LTLIBRARIES = libresample.la

libresample_la_SOURCES = \
	im_affine.c \
	bicubic.cpp \
	similarity.c \
	interpolate.c \
	yafrsmooth.cpp \
	nohalo1.cpp \
	templates.h \
	transform.c \
	resample_dispatch.c

INCLUDES = -I${top_srcdir}/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
