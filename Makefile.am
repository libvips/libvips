# only build in the python dir if we can
if HAVE_PYTHON
P_COMPILE_DIR = swig
P_DIST_DIR =
else
P_COMPILE_DIR =
P_DIST_DIR = swig
endif

SUBDIRS = \
	libvips \
	tools \
	libvipsCC \
	man \
	po \
	doc \
	$(P_COMPILE_DIR) 

EXTRA_DIST = \
	m4 \
	benchmark \
	bootstrap.sh \
	vipsCC-7.${IM_MINOR_VERSION}.pc.in \
	vips-7.${IM_MINOR_VERSION}.pc.in \
	vips-7.${IM_MINOR_VERSION}.spec.in \
	acinclude.m4 \
	depcomp \
	$(P_DIST_DIR)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vips-7.${IM_MINOR_VERSION}.pc vipsCC-7.${IM_MINOR_VERSION}.pc

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

DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc
