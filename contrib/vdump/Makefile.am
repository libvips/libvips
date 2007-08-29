bin_PROGRAMS = vdump

vdump_SOURCES = vdump.c

man_MANS = \
	vdump.1

pkgdata_DATA = \
	vdump.pro

INCLUDES = -I${top_srcdir}/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libsrc/libvips.la @VIPS_LIBS@

EXTRA_DIST = $(pkgdata_DATA) $(man_MANS)
