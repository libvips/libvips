# only build in the cimg dir if it's enabled
if WITH_CIMG
C_COMPILE_DIR = cimg
C_DIST_DIR =
C_LIB = cimg/libcimg.la
else
C_COMPILE_DIR =
C_DIST_DIR = cimg
C_LIB = 
endif

SUBDIRS = \
	acquire \
	arithmetic \
	resample \
	boolean \
	colour \
	conversion \
	convolution \
	$(C_COMPILE_DIR) \
	format \
	freq_filt \
	histograms_lut \
	inplace \
	iofuncs \
	matrix \
	morphology \
	mosaicing \
	other \
	relational \
	video \
	.

lib_LTLIBRARIES = libvips.la

libvips_la_SOURCES = dummy.c dummy2.cc

# DLLs need dependant libs there too ... put @VIPS_LIBS@ at the end
libvips_la_LIBADD = \
	acquire/libacquire.la \
	resample/libresample.la \
	arithmetic/libarithmetic.la \
	boolean/libboolean.la \
	colour/libcolour.la \
	conversion/libconversion.la \
	convolution/libconvolution.la \
	$(C_LIB) \
	format/libformat.la \
	freq_filt/libfreq_filt.la \
	histograms_lut/libhistograms_lut.la \
	inplace/libinplace.la \
	iofuncs/libiofuncs.la \
	matrix/libmatrix.la \
	morphology/libmorphology.la \
	mosaicing/libmosaicing.la \
	other/libother.la \
	relational/librelational.la \
	video/libvideo.la \
	@VIPS_LIBS@

libvips_la_LDFLAGS = \
	-no-undefined \
	-version-info @LIBRARY_CURRENT@:@LIBRARY_REVISION@:@LIBRARY_AGE@ 

EXTRA_DIST = \
	$(C_DIST_DIR)
