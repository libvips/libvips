
bin_PROGRAMS = \
	find_mosaic \
	mergeup

find_mosaic_SOURCES = find_mosaic.c
mergeup_SOURCES =  mergeup.c

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@ 
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libvips/libvips.la @VIPS_LIBS@
if ENABLE_CXX
LDADD += @VIPS_CXX_LIBS@
endif

