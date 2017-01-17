
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
	$(P8_COMPILE_DIR) 

EXTRA_DIST = \
	m4 \
	benchmark \
	autogen.sh \
	vips.pc.in \
	vipsCC.pc.in \
	vips-cpp.pc.in \
	libvips.supp \
	depcomp \
	README.md \
	$(P_DIST_DIR) \
	$(P8_DIST_DIR) 

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vips.pc vipsCC.pc vips-cpp.pc

dist-hook:
# make sure we don't get any .svn dirs from EXTRA_DIST
# also "fred" gets left around occasionally
	-find $(distdir) -name .svn -exec rm -rf {} \;
	-find $(distdir) -name fred -exec rm {} \;

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc --enable-introspection
