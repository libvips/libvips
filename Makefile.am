
# turn off libvipsCC if C++ is disabled
if ENABLE_CXX
C_COMPILE_DIR = libvipsCC
C_DIST_DIR =
C_PKGCONFIG = vipsCC.pc

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

if ENABLE_DOCS
D_DIST_DIR = 
D_BUILD_DIR = doc
else
D_DIST_DIR = doc
D_BUILD_DIR = 
endif

SUBDIRS = \
	libvips \
	tools \
	po \
	man \
	doc \
	$(C_COMPILE_DIR) \
	$(P_COMPILE_DIR) \
	$(D_BUILD_DIR) 

EXTRA_DIST = \
	m4 \
	benchmark \
	bootstrap.sh \
	vips.pc.in \
	vipsCC.pc.in \
	libvips.supp \
	acinclude.m4 \
	depcomp \
	$(C_DIST_DIR) \
	$(P_DIST_DIR) \
	$(D_DIST_DIR)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vips.pc $(C_PKGCONFIG)

if ENABLE_DOCS
install-exec-hook:
	-rm -rf ${DESTDIR}$(datadir)/doc/vips
	$(mkinstalldirs) ${DESTDIR}$(datadir)/doc/vips
	-cp -r ${top_srcdir}/doc/html ${top_srcdir}/doc/pdf ${DESTDIR}$(datadir)/doc/vips 
endif

dist-hook:
# make sure we don't get any .svn dirs from EXTRA_DIST
# also "fred" gets left around occasionally
	-find $(distdir) -name .svn -exec rm -rf {} \;
	-find $(distdir) -name fred -exec rm {} \;

uninstall-hook:
# make sure we have write permission for 'rm'
	-chmod -R u+w ${DESTDIR}$(datadir)/doc/vips
	-rm -rf ${DESTDIR}$(datadir)/doc/vips

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc --enable-introspection
