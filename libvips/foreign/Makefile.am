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
	magick2vips.c \
	magick7load.c \
	magick.c \
	magick.h \
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
	openslide2vips.c \
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

EXTRA_DIST = libnsgif

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@

