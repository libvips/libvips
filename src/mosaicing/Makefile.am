
bin_PROGRAMS = \
	find_mosaic \
	mergeup

find_mosaic_SOURCES = find_mosaic.c
mergeup_SOURCES =  mergeup.c

INCLUDES = -I${top_srcdir}/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@ 
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libsrc/libvips.la @VIPS_LIBS@

