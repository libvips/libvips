pkginclude_HEADERS = \
	basic.h \
	type.h \
	gate.h \
	almostdeprecated.h \
	deprecated.h \
	arithmetic.h \
	buf.h \
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
	cimg_funcs.h \
	object.h \
	private.h \
	rect.h \
	region.h \
	relational.h \
	resample.h \
	semaphore.h \
	threadpool.h \
	thread.h \
	transform.h \
	util.h \
	version.h \
	vector.h \
	vips7compat.h \
	vips.h 

vipsc++.h:
	vips --cpph all > vipsc++.h

EXTRA_DIST = version.h.in internal.h enumtemplate

# the headers we scan for enums etc.
# keep in sync with ${top_srcdir}/libvips/iofuncs/Makefile.am
# we need absolute filenames here since this list appears in the src dir as
# well
vips_scan_headers = \
	${top_srcdir}/libvips/include/vips/memory.h \
	${top_srcdir}/libvips/include/vips/foreign.h \
	${top_srcdir}/libvips/include/vips/arithmetic.h \
	${top_srcdir}/libvips/include/vips/conversion.h \
	${top_srcdir}/libvips/include/vips/util.h \
	${top_srcdir}/libvips/include/vips/image.h \
	${top_srcdir}/libvips/include/vips/colour.h \
	${top_srcdir}/libvips/include/vips/operation.h \
	${top_srcdir}/libvips/include/vips/convolution.h \
	${top_srcdir}/libvips/include/vips/morphology.h \
	${top_srcdir}/libvips/include/vips/object.h

enumtypes.h: $(vips_scan_headers) Makefile
	glib-mkenums --template enumtemplate \
		$(vips_scan_headers) > xgen-geth && \
	( cmp -s xgen-geth enumtypes.h || cp xgen-geth enumtypes.h ) && \
	rm -f xgen-geth 
