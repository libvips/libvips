bin_PROGRAMS = \
	vips \
	vipsedit \
	vipsthumbnail \
	vipsheader 

vips_SOURCES = vips.c
vipsedit_SOURCES = vipsedit.c
vipsheader_SOURCES = vipsheader.c
vipsthumbnail_SOURCES = vipsthumbnail.c

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@ 
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libvips/libvips.la @VIPS_LIBS@

bin_SCRIPTS = \
	light_correct \
	shrink_width \
	batch_image_convert \
	batch_rubber_sheet \
	batch_crop \
	vipsprofile \
	vips-8.13

EXTRA_DIST = \
	batch_crop.in \ 
	batch_image_convert.in \
	batch_rubber_sheet.in \
	light_correct.in \
	meson.build \
	shrink_width.in \
	vips-8.13 \
	vipsprofile

install-exec-hook:
	chmod ugo+x ${DESTDIR}${bindir}/light_correct
	chmod ugo+x ${DESTDIR}${bindir}/shrink_width
	chmod ugo+x ${DESTDIR}${bindir}/batch_image_convert
	chmod ugo+x ${DESTDIR}${bindir}/batch_rubber_sheet
	chmod ugo+x ${DESTDIR}${bindir}/batch_crop
	chmod ugo+x ${DESTDIR}${bindir}/vipsprofile

