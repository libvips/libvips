noinst_LTLIBRARIES = libforeign.la

libforeign_la_SOURCES = \
	vips2jpeg.c \
	jpeg2vips.c \
	jpeg.h \
	jpegload.c \
	jpegsave.c \
	vipssave.c \
	vipsload.c \
	foreign.c 

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
