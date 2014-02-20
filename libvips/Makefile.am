# only build in the cimg dir if C++ is enabled
if ENABLE_CXX
C_COMPILE_DIR = cimg
C_DIST_DIR =
C_LIB = cimg/libcimg.la
else
C_COMPILE_DIR =
C_DIST_DIR = cimg
C_LIB = 
endif

SUBDIRS = \
	include \
	foreign \
	arithmetic \
	resample \
	colour \
	conversion \
	deprecated \
	convolution \
	$(C_COMPILE_DIR) \
	freqfilt \
	histogram \
	draw \
	iofuncs \
	morphology \
	mosaicing \
	create \
	video \
	.

lib_LTLIBRARIES = libvips.la

# empty means default to C linking
libvips_la_SOURCES = 

# if we have C++ components enabled, make sure we link the top-level with c++
#
# sadly the if/endif isn't enough to stop automake detecting a c++ link even
# when c++ is disabled ... comment out this line if you have linking problems
if ENABLE_CXX
nodist_EXTRA_libvips_la_SOURCES = cimg/dummy2.cc
endif

# DLLs need dependant libs there too ... put @VIPS_LIBS@ at the end
libvips_la_LIBADD = \
	resample/libresample.la \
	arithmetic/libarithmetic.la \
	colour/libcolour.la \
	conversion/libconversion.la \
	convolution/libconvolution.la \
	deprecated/libdeprecated.la \
	$(C_LIB) \
	foreign/libforeign.la \
	freqfilt/libfreqfilt.la \
	histogram/libhistogram.la \
	draw/libdraw.la \
	iofuncs/libiofuncs.la \
	morphology/libmorphology.la \
	mosaicing/libmosaicing.la \
	create/libcreate.la \
	video/libvideo.la \
	@VIPS_LIBS@

if ENABLE_CXX
libvips_la_LIBADD += @VIPS_CXX_LIBS@
endif

libvips_la_LDFLAGS = \
	-no-undefined \
	-version-info @LIBRARY_CURRENT@:@LIBRARY_REVISION@:@LIBRARY_AGE@ 

EXTRA_DIST = \
	$(C_DIST_DIR)

CLEANFILES = 

-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=$(srcdir)
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir)

if HAVE_INTROSPECTION
# we can't get the _SOURCES lists from the subdirs directly, we get passed it
# by configure instead
introspection_sources = @vips_introspection_sources@

# we make the vips8 API
Vips-8.0.gir: libvips.la
Vips_8_0_gir_INCLUDES = GObject-2.0
Vips_8_0_gir_CFLAGS = $(INCLUDES) -I${top_srcdir}/libvips/include
Vips_8_0_gir_LIBS = libvips.la
Vips_8_0_gir_FILES = $(introspection_sources)
INTROSPECTION_GIRS += Vips-8.0.gir

Vips_8_0_gir_SCANNERFLAGS = \
			    --warn-all \
			    --verbose \
			    --identifier-prefix=Vips \
			    --identifier-prefix=vips \
			    --symbol-prefix=vips \
			    --symbol-prefix=im \
			    --symbol-prefix=im_ 

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif
