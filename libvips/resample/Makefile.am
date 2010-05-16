# only build the C++ stuff if it's enabled
if ENABLE_CXX
C_SOURCES = \
	bicubic.cpp \
	nohalo.cpp \
	lbb.cpp \
	snohalo.cpp \
	templates.h 
C_DIST =
else
C_SOURCES = 
C_DIST = \
	bicubic.cpp \
	nohalo.cpp \
	lbb.cpp \
	snohalo.cpp \
	templates.h 
endif

noinst_LTLIBRARIES = libresample.la

libresample_la_SOURCES = \
	im_affine.c \
	interpolate.c \
	im_shrink.c \
	im_stretch3.c \
	im_rightshift_size.c \
	transform.c \
	resample_dispatch.c \
	$(C_SOURCES)

EXTRA_DIST = \
	$(C_DIST)

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
