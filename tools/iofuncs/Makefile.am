bin_PROGRAMS = \
	vips \
	binfile \
	debugim \
	edvips \
	header \
	printlines

vips_SOURCES = vips.c
binfile_SOURCES =  binfile.c
debugim_SOURCES = debugim.c
edvips_SOURCES = edvips.c
header_SOURCES = header.c
printlines_SOURCES = printlines.c

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@ 
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libvips/libvips.la @VIPS_LIBS@

if ENABLE_LINKS
install-exec-hook:
	${top_srcdir}/src/scripts/post_install ${DESTDIR}${bindir}
endif

uninstall-hook:
	${RM} ${bindir}/im_*

