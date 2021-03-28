pkginclude_HEADERS = \
	connection.h \
	sbuf.h \
	basic.h \
	type.h \
	gate.h \
	almostdeprecated.h \
	deprecated.h \
	arithmetic.h \
	buf.h \
	dbuf.h \
	colour.h \
	conversion.h \
	convolution.h \
	debug.h \
	dispatch.h \
	enumtypes.h \
	error.h \
	operation.h \
	format.h \
	foreign.h \
	draw.h \
	generate.h \
	header.h \
	histogram.h \
	freqfilt.h \
	image.h \
	interpolate.h \
	intl.h \
	mask.h \
	memory.h \
	morphology.h \
	mosaicing.h \
	create.h \
	video.h \
	object.h \
	private.h \
	rect.h \
	region.h \
	resample.h \
	semaphore.h \
	soname.h \
	threadpool.h \
	thread.h \
	transform.h \
	util.h \
	vector.h \
	vips7compat.h \
	vips.h

nodist_pkginclude_HEADERS = version.h

EXTRA_DIST = version.h.in internal.h enumtemplate

# the headers we scan for enums etc.
# keep in sync with ${top_srcdir}/libvips/iofuncs/Makefile.am
# we need absolute filenames here since this list appears in the src dir as
# well
vips_scan_headers = \
	${top_srcdir}/libvips/include/vips/resample.h \
	${top_srcdir}/libvips/include/vips/memory.h \
	${top_srcdir}/libvips/include/vips/create.h \
	${top_srcdir}/libvips/include/vips/foreign.h \
	${top_srcdir}/libvips/include/vips/arithmetic.h \
	${top_srcdir}/libvips/include/vips/conversion.h \
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

enumtypes.h: $(vips_scan_headers) Makefile.am
	glib-mkenums --template ${top_srcdir}/libvips/include/vips/enumtemplate $(vips_scan_headers) > enumtypes.h
