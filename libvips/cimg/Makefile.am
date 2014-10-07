noinst_LTLIBRARIES = libcimg.la

OPTIONAL_SRC = 
OPTIONAL_DIST =

if ENABLE_GMIC
OPTIONAL_SRC += vips_gmic.cpp gmic.cpp 
else
OPTIONAL_DIST += vips_gmic.cpp gmic.cpp
endif

libcimg_la_SOURCES = \
	CImg.h \
	gmic_def.h \
	gmic.h \
	cimg.c \
	$(OPTIONAL_SRC)

# various cimg settings as well
# display=0 means don't build the cimg display stuff
# don't turn on the parallel stuff, we rely on vips for that
# don't use cimg_use_rng, we want the system generator
# don't turn on jpg/png/tiff/exr read write, we use vips for that
# don't use -Dcimg_use_fftw3, CImg wants fftw_init_threads() etc. which 
#   are not widely available
if OS_WIN32
AM_CPPFLAGS = \
	-Dcimg_OS=2 \
	-Dgmic_build \
	-Dcimg_strict_warnings \
	-Dcimg_display=0 \
	-DLOCALEDIR=\""$(LOCALEDIR)"\"
else
AM_CPPFLAGS = \
	-Dcimg_OS=1 \
	-Dgmic_build \
	-Dcimg_strict_warnings \
	-Dcimg_display=0 \
	-DLOCALEDIR=\""$(LOCALEDIR)"\"
endif

# used by the final libvips link rather than us
EXTRA_DIST = \
	dummy2.cc \
	$(OPTIONAL_DIST)

AM_CPPFLAGS += -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
