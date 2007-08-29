SUBDIRS = man1

bin_PROGRAMS = \
	cooc \
	cooc_features \
	glds \
	glds_features \
	simcontr \
	sines \
	spatres \
	squares

cooc_SOURCES = cooc.c
cooc_features_SOURCES =  cooc_features.c
glds_SOURCES = glds.c
glds_features_SOURCES = glds_features.c
simcontr_SOURCES = simcontr.c
sines_SOURCES = sines.c
spatres_SOURCES = spatres.c
squares_SOURCES = squares.c

INCLUDES = -I${top_srcdir}/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@ 
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libsrc/libvips.la @VIPS_LIBS@

