INCLUDES = -I$(top_srcdir)/include @VIPS_CFLAGS@ 

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
	$(top_builddir)/libsrc/libvips.la @VIPS_LIBS@

vipsc++.cc:
	vips --cppc all > vipsc++.cc

EXTRA_DIST = vipsc++.cc
