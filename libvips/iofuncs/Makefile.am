noinst_LTLIBRARIES = libiofuncs.la

libiofuncs_la_SOURCES = \
	ginputsource.c \
	sourceginput.c \
	connection.c \
	source.c \
	sourcecustom.c \
	target.c \
	targetcustom.c \
	sbuf.c \
	dbuf.c \
	reorder.c \
	vipsmarshal.h \
	vipsmarshal.c \
	type.c \
	gate.c \
	enumtypes.c \
	object.c \
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

vipsmarshal.h: vipsmarshal.list
	glib-genmarshal --prefix=vips --header vipsmarshal.list > vipsmarshal.h
vipsmarshal.c: vipsmarshal.list
	echo "#include \"vipsmarshal.h\"" > vipsmarshal.c 
	glib-genmarshal --prefix=vips --body vipsmarshal.list >> vipsmarshal.c

EXTRA_DIST = \
	enumtemplate \
	vipsmarshal.h \
	vipsmarshal.c \
	vipsmarshal.list

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 

# the headers we scan for enums etc.
# keep in sync with ../include/vips/Makefile.am
# we need absolute filenames here since this list appears in the header dir as
# well
vips_scan_headers = \
	${top_srcdir}/libvips/include/vips/resample.h \
	${top_srcdir}/libvips/include/vips/memory.h \
	${top_srcdir}/libvips/include/vips/create.h \
	${top_srcdir}/libvips/include/vips/foreign.h \
	${top_srcdir}/libvips/include/vips/conversion.h \
	${top_srcdir}/libvips/include/vips/arithmetic.h \
	${top_srcdir}/libvips/include/vips/util.h \
	${top_srcdir}/libvips/include/vips/image.h \
	${top_srcdir}/libvips/include/vips/colour.h \
	${top_srcdir}/libvips/include/vips/operation.h \
	${top_srcdir}/libvips/include/vips/convolution.h \
	${top_srcdir}/libvips/include/vips/morphology.h \
	${top_srcdir}/libvips/include/vips/draw.h \
	${top_srcdir}/libvips/include/vips/basic.h \
	${top_srcdir}/libvips/include/vips/object.h \
	${top_srcdir}/libvips/include/vips/region.h

enumtypes.c: $(vips_scan_headers) Makefile.am
	glib-mkenums --template ${top_srcdir}/libvips/iofuncs/enumtemplate $(vips_scan_headers) > enumtypes.c
