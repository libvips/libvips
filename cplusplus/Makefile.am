SUBDIRS = \
	include 

AM_CPPFLAGS = \
	-I$(top_srcdir)/libvips/include \
	-I$(top_srcdir)/cplusplus/include \
	@VIPS_CFLAGS@ 

lib_LTLIBRARIES = libvips-cpp.la

libvips_cpp_la_SOURCES = \
	VImage.cpp \
	VInterpolate.cpp \
	VConnection.cpp \
	VError.cpp 

libvips_cpp_la_LDFLAGS = \
	-no-undefined \
	-version-info @LIBRARY_CURRENT@:@LIBRARY_REVISION@:@LIBRARY_AGE@

libvips_cpp_la_LIBADD = \
	$(top_builddir)/libvips/libvips.la @VIPS_LIBS@

vips-operators.cpp:
	echo "// bodies for vips operations" > vips-operators.cpp; \
	echo -n "// " >> vips-operators.cpp; \
	date >> vips-operators.cpp; \
	echo "// this file is generated automatically, do not edit!" >> vips-operators.cpp; \
	./gen-operators.py -g cpp >> vips-operators.cpp

if HAVE_DOXYGEN
html_DATA = html

html: doxygen.stamp

doxygen.stamp: Doxyfile
	$(DOXYGEN) $^
	touch doxygen.stamp

install-htmlDATA:
	-mkdir -p $(DESTDIR)$(htmldir)
	-cp -r html $(DESTDIR)$(htmldir)

uninstall-htmlDATA:
	rm -rf $(DESTDIR)$(htmldir)/html
endif

EXTRA_DIST = \
	README.md \
	vips-operators.cpp \
	Doxyfile.in \
	gen-operators.py

