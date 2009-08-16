noinst_LTLIBRARIES = libcimg.la

libcimg_la_SOURCES = \
	CImg.h \
	cimg_dispatch.c \
	cimg.cpp

# various cimg settings as well
# we need to change these a bit for win32
if OS_WIN32
AM_CPPFLAGS = \
	-Dcimg_strict \
	-Dcimg_OS=0 \
	-Dcimg_display_type=0 \
	-DLOCALEDIR=\""$(LOCALEDIR)"\"
else
AM_CPPFLAGS = \
	-Dcimg_strict \
	-Dcimg_OS=1 \
	-Dcimg_display_type=0 \
	-DLOCALEDIR=\""$(LOCALEDIR)"\"
endif

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
