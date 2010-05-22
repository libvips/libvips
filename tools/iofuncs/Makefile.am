bin_PROGRAMS = \
	vips \
	edvips \
	vipsthumbnail \
	header 

vips_SOURCES = vips.c
edvips_SOURCES = edvips.c
header_SOURCES = header.c
vipsthumbnail_SOURCES = vipsthumbnail.c

INCLUDES = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@ 
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libvips/libvips.la @VIPS_LIBS@
if ENABLE_CXX
LDADD += @VIPS_CXX_LIBS@
endif

if ENABLE_LINKS
install-exec-hook:
	${top_srcdir}/src/scripts/post_install ${DESTDIR}${bindir}
uninstall-hook:
	${RM} ${bindir}/im_*
endif

