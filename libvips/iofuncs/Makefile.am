noinst_LTLIBRARIES = libiofuncs.la

libiofuncs_la_SOURCES = \
	enumtypes.c \
	object.c \
	meta.c \
	base64.h \
	base64.c \
	debug.c \
	dispatch_types.c \
	error.c \
	image.c \
	vips.c \
	im_demand_hint.c \
	im_generate.c \
	im_histlin.c \
	im_mapfile.c \
	im_prepare.c \
	im_setupout.c \
	im_guess_prefix.c \
	sinkmemory.c \
	sinkscreen.c \
	sinkdisc.c \
	sink.c \
	im_wrapmany.c \
	im_writeline.c \
	memory.c \
	check.c \
	package.c \
	header.c \
	region.c \
	rect.c \
	semaphore.c \
	threadpool.c \
	util.c \
	im_init_world.c \
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
