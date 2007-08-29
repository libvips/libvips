
SUBDIRS = \
	acquire \
	arithmetic \
	boolean \
	colour \
	conversion \
	convolution \
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

libvips_la_SOURCES = dummy.c

# DLLs need dependant libs there too ... put @VIPS_LIBS@ at the end
libvips_la_LIBADD = \
	acquire/libacquire.la \
	arithmetic/libarithmetic.la \
	boolean/libboolean.la \
	colour/libcolour.la \
	conversion/libconversion.la \
	convolution/libconvolution.la \
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

# use "-no-undefined" because we need to be able to generate dlls as well

# commented out
#	-no-undefined 
# because I can't get libtool DLL builds working :-( 

libvips_la_LDFLAGS = \
	-no-undefined \
	-version-info @LIBRARY_CURRENT@:@LIBRARY_REVISION@:@LIBRARY_AGE@ 

vips.def:
	./makedef.pl $(prefix) > vips.def

EXTRA_DIST = vips.def makedef.pl
