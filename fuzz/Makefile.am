TESTS = \
	test_fuzz.sh

FUZZPROGS = \
	jpegsave_file_fuzzer \
	jpegsave_buffer_fuzzer \
	pngsave_buffer_fuzzer \
	webpsave_buffer_fuzzer \
	sharpen_fuzzer \
	thumbnail_fuzzer \
	smartcrop_fuzzer \
	mosaic_fuzzer

AM_DEFAULT_SOURCE_EXT = .cc

FUZZLIBS = libstandaloneengine.a

# Include debug symbols by default as recommended by libfuzzer
AM_CXXFLAGS = -g -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@
LDADD = ${top_builddir}/libvips/libvips.la @VIPS_LIBS@ @LIB_FUZZING_ENGINE@

libstandaloneengine_a_SOURCES = StandaloneFuzzTargetMain.c

check_PROGRAMS = $(FUZZPROGS)
noinst_LIBRARIES = $(FUZZLIBS)

EXTRA_DIST = \
	$(TESTS) \
	common_fuzzer_corpus
