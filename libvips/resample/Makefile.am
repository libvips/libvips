libresample_la_SOURCES = \
	thumbnail.c \
	mapim.c \
	affine.c \
	quadratic.c \
	resample.c \
	similarity.c \
	resize.c \
	alpha_resize.c \
	presample.h \
	shrink.c \
	shrinkh.c \
	shrinkv.c \
	reduce.c \
	alpha_reduce.c \
	reduceh.cpp \
	alpha_reduceh.cpp \
	reducev.cpp \
	alpha_reducev.cpp \
	interpolate.c \
	transform.c \
	bicubic.cpp \
	lbb.cpp \
	nohalo.cpp \
	vsqbs.cpp \
	templates.h 

EXTRA_DIST = \
	dummy2.cc 

noinst_LTLIBRARIES = libresample.la

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
