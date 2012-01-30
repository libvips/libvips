bin_PROGRAMS = \
	find_mosaic \
	mergeup \
	vips \
	edvips \
	vipsthumbnail \
	header 

vips_SOURCES = vips.c
edvips_SOURCES = edvips.c
header_SOURCES = header.c
vipsthumbnail_SOURCES = vipsthumbnail.c
find_mosaic_SOURCES = find_mosaic.c
mergeup_SOURCES =  mergeup.c

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@ 
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libvips/libvips.la @VIPS_LIBS@
if ENABLE_CXX
LDADD += @VIPS_CXX_LIBS@
endif

bin_SCRIPTS = \
	light_correct \
	shrink_width \
	batch_image_convert \
	batch_rubber_sheet \
	batch_crop \
	vips-7.28

EXTRA_DIST = \
	vips-7.28 \
	light_correct.in \
	shrink_width.in \
	batch_image_convert.in \
	batch_rubber_sheet.in \
	batch_crop.in 

install-exec-hook:
	chmod ugo+x ${DESTDIR}${bindir}/light_correct
	chmod ugo+x ${DESTDIR}${bindir}/shrink_width
	chmod ugo+x ${DESTDIR}${bindir}/batch_image_convert
	chmod ugo+x ${DESTDIR}${bindir}/batch_rubber_sheet
	chmod ugo+x ${DESTDIR}${bindir}/batch_crop

