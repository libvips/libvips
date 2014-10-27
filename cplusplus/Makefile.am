SUBDIRS = \
	include 

AM_CPPFLAGS = \
	-I$(top_srcdir)/libvips/include \
	-I$(top_srcdir)/cplusplus/include \
	@VIPS_CFLAGS@ 

lib_LTLIBRARIES = libvips-cc.la

libvips_cc_la_SOURCES = \
	VImage.cc \
	VError.cc 

libvips_cc_la_LDFLAGS = \
	-no-undefined \
	-version-info @LIBRARY_CURRENT@:@LIBRARY_REVISION@:@LIBRARY_AGE@

libvips_cc_la_LIBADD = \
	$(top_builddir)/libvips/libvips.la @VIPS_LIBS@

vips-operators.cc:
	echo "// bodies for vips operations" > vips-operators.cc; \
	echo -n "// " >> vips-operators.cc; \
	date >> vips-operators.cc; \
	echo "// this file is generated automatically, do not edit!" >> vips-operators.cc; \
	echo "" >> vips-operators.cc; \
	./gen-operators.py >> vips-operators.cc 

EXTRA_DIST = \
	     vips-operators.cc \
	     gen-operators.py
