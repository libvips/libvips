noinst_LTLIBRARIES = libiofuncs.la

libiofuncs_la_SOURCES = \
	type.c \
	enumtypes.c \
	object.c \
	base64.h \
	base64.c \
	error.c \
	image.c \
	vips.c \
	generate.c \
	mapfile.c \
	cache.c \
	sink.h \
	sink.c \
	sinkmemory.c \
	sinkdisc.c \
	sinkscreen.c \
	memory.c \
	header.c \
	operation.c \
	region.c \
	rect.c \
	semaphore.c \
	threadpool.c \
	util.c \
	init.c \
	buf.c \
	window.c \
	vector.c \
	system.c \
	buffer.c 

EXTRA_DIST = enumtemplate

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 

# the headers we scan for enums etc.
# keep in sync with ../include/vips/Makefile.am
# we need absolute filenames here since this list appears in the header dir as
# well
vips_scan_headers = \
	${top_srcdir}/libvips/include/vips/memory.h \
	${top_srcdir}/libvips/include/vips/foreign.h \
	${top_srcdir}/libvips/include/vips/conversion.h \
	${top_srcdir}/libvips/include/vips/arithmetic.h \
	${top_srcdir}/libvips/include/vips/util.h \
	${top_srcdir}/libvips/include/vips/image.h \
	${top_srcdir}/libvips/include/vips/colour.h \
	${top_srcdir}/libvips/include/vips/operation.h \
	${top_srcdir}/libvips/include/vips/convolution.h \
	${top_srcdir}/libvips/include/vips/morphology.h \
	${top_srcdir}/libvips/include/vips/object.h

enumtypes.c: $(vips_scan_headers) Makefile
	glib-mkenums --template enumtemplate \
		$(vips_scan_headers) > xgen-getc && \
	( cmp -s xgen-getc enumtypes.c || cp xgen-getc enumtypes.c ) && \
	rm -f xgen-getc
