noinst_LTLIBRARIES = libiofuncs.la

libiofuncs_la_SOURCES = \
	enumtypes.c \
	object.c \
	base64.h \
	base64.c \
	dispatch_types.c \
	error.c \
	image.c \
	vips.c \
	generate.c \
	mapfile.c \
	sink.h \
	sink.c \
	sinkmemory.c \
	sinkdisc.c \
	sinkscreen.c \
	memory.c \
	package.c \
	header.c \
	region.c \
	rect.c \
	semaphore.c \
	threadpool.c \
	util.c \
	init.c \
	buf.c \
	window.c \
	vector.c \
	buffer.c 

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 

# the headers we scan for enums etc.
# keep in sync with ../include/vips/Makefile.am
# we need absolute filenames here since this list appears in the src dir as
# well
vips_scan_headers = \
	${top_srcdir}/libvips/include/vips/memory.h \
	${top_srcdir}/libvips/include/vips/util.h \
	${top_srcdir}/libvips/include/vips/buf.h \
	${top_srcdir}/libvips/include/vips/image.h \
	${top_srcdir}/libvips/include/vips/object.h

enumtypes.c: $(vips_scan_headers) Makefile
	glib-mkenums --template enumtemplate \
		$(vips_scan_headers) > xgen-getc && \
	( cmp -s xgen-getc enumtypes.c || cp xgen-getc enumtypes.c ) && \
	rm -f xgen-getc
