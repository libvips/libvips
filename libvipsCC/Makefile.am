SUBDIRS = \
	include 

INCLUDES = \
	-I$(top_srcdir)/libvips/include \
	-I$(top_srcdir)/libvipsCC/include \
	@VIPS_CFLAGS@ 

lib_LTLIBRARIES = libvipsCC.la

libvipsCC_la_SOURCES = \
	VImage.cc \
	VError.cc \
	VDisplay.cc \
	VMask.cc

libvipsCC_la_LDFLAGS = \
	-no-undefined \
	-version-info @LIBRARY_CURRENT@:@LIBRARY_REVISION@:@LIBRARY_AGE@

libvipsCC_la_LIBADD = \
	$(top_builddir)/libvips/libvips.la @VIPS_LIBS@

# swap the 'awk' line for this:
# awk '{if($$1!="deprecated") print $$1}'` ; \
# to not generate the wrappers for deprecated functions
vipsc++.cc:
	packages=`vips list packages | \
	  awk '{print $$1}'` ; \
	  echo > vipsc++.cc ; \
	  for name in $$packages; do \
	    echo "// bodies for package $$name" >> vipsc++.cc ; \
	    vips cppc $$name >> vipsc++.cc ; \
	    echo >> vipsc++.cc ; \
	  done 

EXTRA_DIST = vipsc++.cc
