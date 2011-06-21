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
	arithmetic \
	resample \
	boolean \
	colour \
	conversion \
	deprecated \
	convolution \
	$(C_COMPILE_DIR) \
	format \
	freq_filt \
	histograms_lut \
	inplace \
	iofuncs \
	mask \
	morphology \
	mosaicing \
	other \
	relational \
	video \
	.

lib_LTLIBRARIES = libvips.la

libvips_la_SOURCES = dummy.c 
if ENABLE_CXX
libvips_la_SOURCES += dummy2.cc
endif

# DLLs need dependant libs there too ... put @VIPS_LIBS@ at the end
libvips_la_LIBADD = \
	resample/libresample.la \
	arithmetic/libarithmetic.la \
	boolean/libboolean.la \
	colour/libcolour.la \
	conversion/libconversion.la \
	convolution/libconvolution.la \
	deprecated/libdeprecated.la \
	$(C_LIB) \
	format/libformat.la \
	freq_filt/libfreq_filt.la \
	histograms_lut/libhistograms_lut.la \
	inplace/libinplace.la \
	iofuncs/libiofuncs.la \
	mask/libmask.la \
	morphology/libmorphology.la \
	mosaicing/libmosaicing.la \
	other/libother.la \
	relational/librelational.la \
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
Vips_8_0_gir_SCANNERFLAGS = \
			    --warn-all \
			    --verbose \
			    --namespace=Vips \
			    --identifier-prefix=Vips \
			    --symbol-prefix=vips \
			    --symbol-prefix=im \
			    --symbol-prefix=im_ 
INTROSPECTION_GIRS += Vips-8.0.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif
