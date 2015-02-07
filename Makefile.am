
# turn on Python if we can 
if HAVE_PYTHON
P_COMPILE_DIR = swig
P_DIST_DIR =
else
P_COMPILE_DIR =
P_DIST_DIR = swig
endif

# turn on vips8 Python if we can 
if ENABLE_PYVIPS8
P8_COMPILE_DIR = python
P8_DIST_DIR =
else
P8_COMPILE_DIR = 
P8_DIST_DIR = python
endif

# turn docs on or off
if ENABLE_DOCS
D_DIST_DIR = 
D_BUILD_DIR = doc
else
D_DIST_DIR = doc
D_BUILD_DIR = 
endif

SUBDIRS = \
	libvips \
	libvipsCC \
	cplusplus \
	tools \
	po \
	man \
	doc \
	test \
	$(P_COMPILE_DIR) \
	$(P8_COMPILE_DIR) \
	$(D_BUILD_DIR) 

EXTRA_DIST = \
	m4 \
	benchmark \
	bootstrap.sh \
	vips.pc.in \
	vipsCC.pc.in \
	vips-cpp.pc.in \
	libvips.supp \
	acinclude.m4 \
	depcomp \
	README.md \
	$(P_DIST_DIR) \
	$(P8_DIST_DIR) \
	$(D_DIST_DIR)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vips.pc vipsCC.pc vips-cpp.pc

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
