SUBDIRS = share

bin_PROGRAMS = \
	vips2dj

vips2dj_DEPENDENCIES = vips2dj.h

vips2dj_SOURCES = \
	vips2ah.c \
	vips2dj.c

INCLUDES = -I${top_srcdir}/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libsrc/libvips.la @VIPS_LIBS@

EXTRA_DIST = ${vips2dj_DEPENDENCIES}

