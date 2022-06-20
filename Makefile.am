SUBDIRS = \
	libvips \
	cplusplus \
	tools \
	po \
	man \
	doc \
	test \
	fuzz

EXTRA_DIST = \
	autogen.sh \
	benchmark \
	depcomp \
	m4 \
	meson.build \
	meson_options.txt \
	po/meson.build \
	README.md \
	suppressions \
	vips-cpp.pc.in \
	vips.pc.in

pkgconfig_DATA = vips.pc vips-cpp.pc

dist-hook:
# make sure we don't get any .svn dirs from EXTRA_DIST
# also "fred" gets left around occasionally
	-find $(distdir) -name .svn -exec rm -rf {} \;
	-find $(distdir) -name fred -exec rm {} \;

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc --enable-introspection
