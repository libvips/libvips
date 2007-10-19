noinst_LTLIBRARIES = libcimg.la

libcimg_la_SOURCES = \
	CImg.h \
	cimg_dispatch.c \
	cimg.cpp

# various cimg settings as well
AM_CPPFLAGS = \
	-Dcimg_strict \
	-Dcimg_OS=1 \
	-Dcimg_display_type=0 \
	-DLOCALEDIR=\""$(LOCALEDIR)"\"

INCLUDES = -I${top_srcdir}/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
