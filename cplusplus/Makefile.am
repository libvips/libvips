SUBDIRS = \
	include 

AM_CPPFLAGS = \
	-I$(top_srcdir)/libvips/include \
	-I$(top_srcdir)/cplusplus/include \
	@VIPS_CFLAGS@ 

lib_LTLIBRARIES = libvips-cpp.la

libvips_cpp_la_SOURCES = \
	VImage.cpp \
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
	echo "" >> vips-operators.cpp; \
	./gen-operators.py >> vips-operators.cpp 

EXTRA_DIST = \
	README.txt \
	vips-operators.cpp \
	gen-operators.py
