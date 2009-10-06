bin_PROGRAMS = \
	vips \
	edvips \
	header 

vips_SOURCES = vips.c
edvips_SOURCES = edvips.c
header_SOURCES = header.c

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@ 
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libvips/libvips.la @VIPS_LIBS@

if ENABLE_LINKS
install-exec-hook:
	${top_srcdir}/src/scripts/post_install ${DESTDIR}${bindir}
endif

uninstall-hook:
	${RM} ${bindir}/im_*

