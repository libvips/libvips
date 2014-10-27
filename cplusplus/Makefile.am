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

# swap the 'awk' line for this:
# awk '{if($$1!="deprecated") print $$1}'` ; \
# to not generate the wrappers for deprecated functions
vips-operators.cc:
	packages=`vips list packages | \
	  awk '{print $$1}'` ; \
	  echo > vips-operators.cc ; \
	  for name in $$packages; do \
	    echo "// bodies for package $$name" >> vips-operators.cc ; \
	    vips cppc $$name >> vips-operators.cc ; \
	    echo >> vips-operators.cc ; \
	  done 

EXTRA_DIST = vips-operators.cc
