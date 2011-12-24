
# turn off libvipsCC if C++ is disabled
if ENABLE_CXX
C_COMPILE_DIR = libvipsCC
C_DIST_DIR =
C_PKGCONFIG = vipsCC-7.${VIPS_MINOR_VERSION}.pc

# turn on Python if we can (requires C++)
if HAVE_PYTHON
P_COMPILE_DIR = swig
P_DIST_DIR =
endif

else
C_COMPILE_DIR =
C_DIST_DIR = libvipsCC 
C_PKGCONFIG =
P_COMPILE_DIR =
P_DIST_DIR = swig
endif

SUBDIRS = \
	libvips \
	tools \
	po \
	man \
	doc \
	$(C_COMPILE_DIR) \
	$(P_COMPILE_DIR) 

EXTRA_DIST = \
	m4 \
	benchmark \
	bootstrap.sh \
	vips-7.${VIPS_MINOR_VERSION}.pc.in \
	vipsCC-7.${VIPS_MINOR_VERSION}.pc.in \
	acinclude.m4 \
	depcomp \
	$(C_DIST_DIR) \
	$(P_DIST_DIR)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vips-7.${VIPS_MINOR_VERSION}.pc $(C_PKGCONFIG)

install-exec-hook:
	-rm -rf ${DESTDIR}$(datadir)/doc/vips
	$(mkinstalldirs) ${DESTDIR}$(datadir)/doc/vips
	-cp -r ${top_srcdir}/doc/html ${top_srcdir}/doc/pdf ${DESTDIR}$(datadir)/doc/vips 

dist-hook:
# make sure we don't get any .svn dirs from EXTRA_DIST
	-find $(distdir) -name .svn -exec rm -rf {} \;

uninstall-hook:
# make sure we have write permission for 'rm'
	-chmod -R u+w ${DESTDIR}$(datadir)/doc/vips
	-rm -rf ${DESTDIR}$(datadir)/doc/vips

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc --enable-introspection
