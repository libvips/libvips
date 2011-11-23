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
	file \
	include \
	arithmetic \
	resample \
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
	morphology \
	mosaicing \
	other \
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
	format/libformat.la \
	file/libfile.la \
	freq_filt/libfreq_filt.la \
	histograms_lut/libhistograms_lut.la \
	inplace/libinplace.la \
	iofuncs/libiofuncs.la \
	morphology/libmorphology.la \
	mosaicing/libmosaicing.la \
	other/libother.la \
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
