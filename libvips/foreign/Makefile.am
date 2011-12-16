noinst_LTLIBRARIES = libforeign.la

libforeign_la_SOURCES = \
	csv.h \
	csv.c \
	csvload.c \
	csvsave.c \
	rawload.c \
	rawsave.c \
	vipsload.c \
	vipssave.c \
	analyzeload.c \
	analyze2vips.c \
	analyze2vips.h \
	foreign.c 

EXTRA_DIST = 

if HAVE_OPENEXR
libforeign_la_SOURCES += \
	openexr2vips.h \
	openexr2vips.c \
	openexrload.c 
else
EXTRA_DIST += \
	openexr2vips.h \
	openexr2vips.c \
	openexrload.c 
endif

if HAVE_CFITSIO
libforeign_la_SOURCES += \
	fits.h \
	fits.c \
	fitsload.c \
	fitssave.c 
else
EXTRA_DIST += \
	fits.h \
	fits.c \
	fitsload.c \
	fitssave.c 
endif

if HAVE_TIFF
libforeign_la_SOURCES += \
	tiff.h \
	vips2tiff.c \
	tiff2vips.c \
	tiffload.c \
	tiffsave.c 
else
EXTRA_DIST += \
	tiff.h \
	vips2tiff.c \
	tiff2vips.c \
	tiffload.c \
	tiffsave.c 
endif

if HAVE_OPENSLIDE
libforeign_la_SOURCES += \
	openslide2vips.h \
	openslide2vips.c \
	openslideload.c 
else
EXTRA_DIST += \
	openslide2vips.h \
	openslide2vips.c \
	openslideload.c 
endif

if HAVE_JPEG
libforeign_la_SOURCES += \
	vips2jpeg.c \
	jpeg2vips.c \
	jpeg.h \
	jpegload.c \
	jpegsave.c 
else
EXTRA_DIST += \
	vips2jpeg.c \
	jpeg2vips.c \
	jpeg.h \
	jpegload.c \
	jpegsave.c 
endif

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@

