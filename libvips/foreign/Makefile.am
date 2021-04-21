if ENABLE_NSGIF
SUBDIRS = libnsgif 
endif

noinst_LTLIBRARIES = libforeign.la

libforeign_la_SOURCES = \
	analyze2vips.c \
	analyzeload.c \
	cairo.c \
	csvload.c \
	csvsave.c \
	dbh.h \
	dzsave.c \
	exif.c \
	fits.c \
	fitsload.c \
	fitssave.c \
	foreign.c \
	heifload.c \
	heifsave.c \
	jp2kload.c \
	jp2ksave.c \
	jpeg2vips.c \
	jpeg.h \
	jpegload.c \
	jpegsave.c \
	magickload.c \
	magicksave.c \
	matlab.c \
	matload.c \
	matrixload.c \
	matrixsave.c \
	niftiload.c \
	niftisave.c \
	nsgifload.c \
	openexr2vips.c \
	openexrload.c \
	openslideload.c \
	pdfiumload.c \
	pdfload.c \
	pforeign.h \
	pngload.c \
	pngsave.c \
	ppmload.c \
	ppmsave.c \
	quantise.c \
	radiance.c \
	radload.c \
	radsave.c \
	rawload.c \
	rawsave.c \
	spngload.c \
	svgload.c \
	tiff2vips.c \
	tiff.c \
	tiff.h \
	tiffload.c \
	tiffsave.c \
	vips2jpeg.c \
	vips2tiff.c \
	vips2webp.c \
	vipsload.c \
	vipspng.c \
	vipssave.c \
	webp2vips.c \
	webpload.c \
	webpsave.c

# We still need to include the GObject part of a loader/saver
# if it is not built as a dynamically loadable module.

if !MAGICK_MODULE
libforeign_la_SOURCES += \
	magick.c \
	magick.h \
	magick2vips.c \
	magick6load.c \
	magick7load.c \
	vips2magick.c
endif # !MAGICK_MODULE

if !HEIF_MODULE
libforeign_la_SOURCES += heif2vips.c vips2heif.c
endif # !HEIF_MODULE

if !POPPLER_MODULE
libforeign_la_SOURCES += poppler2vips.c
endif # !POPPLER_MODULE

if !OPENSLIDE_MODULE
libforeign_la_SOURCES += openslide2vips.c
endif # !OPENSLIDE_MODULE

EXTRA_DIST = libnsgif

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@

