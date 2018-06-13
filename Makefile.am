
# build deprecated vips7 Python interface
if HAVE_PYTHON
P_COMPILE_DIR = swig
P_DIST_DIR =
else
P_COMPILE_DIR =
P_DIST_DIR = swig
endif

# build deprecated vips8 Python interface
if ENABLE_PYVIPS8
P8_COMPILE_DIR = python
P8_DIST_DIR =
else
P8_COMPILE_DIR = 
P8_DIST_DIR = python
endif

# build deprecated vips7 C++ API
if ENABLE_CPP7
CPP7_COMPILE_DIR = libvipsCC
CPP7_DIST_DIR =
CPP7_PKG = vipsCC.pc
else
CPP7_COMPILE_DIR = 
CPP7_DIST_DIR = libvipsCC
CPP7_PKG = 
endif

SUBDIRS = \
	libvips \
	cplusplus \
	tools \
	po \
	man \
	doc \
	test \
	$(CPP7_COMPILE_DIR) \
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
	$(CPP7_DIST_DIR) \
	$(P_DIST_DIR) \
	$(P8_DIST_DIR) 

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vips.pc $(CPP7_PKG) vips-cpp.pc

dist-hook:
# make sure we don't get any .svn dirs from EXTRA_DIST
# also "fred" gets left around occasionally
	-find $(distdir) -name .svn -exec rm -rf {} \;
	-find $(distdir) -name fred -exec rm {} \;

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS=--enable-gtk-doc --enable-introspection
