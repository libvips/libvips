bin_SCRIPTS = \
	light_correct \
	shrink_width \
	batch_image_convert \
	batch_rubber_sheet \
	batch_crop \
	vips-7.22

noinst_SCRIPTS = post_install

EXTRA_DIST = \
	vips-7.22 \
	${noinst_SCRIPTS} \
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
