# don't run test_thumbnail.sh by default, it takes ages
TESTS = \
	test_connections.sh \
	test_descriptors.sh \
	test_cli.sh \
	test_formats.sh \
	test_seq.sh \
	test_stall.sh \
	test_threading.sh 

SUBDIRS = \
	test-suite 

noinst_PROGRAMS = \
	test_descriptors \
	test_connections

test_descriptors_SOURCES = \
	test_descriptors.c

test_connections_SOURCES = \
	test_connections.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@
AM_LDFLAGS = @LDFLAGS@ 
LDADD = @VIPS_CFLAGS@ ${top_builddir}/libvips/libvips.la @VIPS_LIBS@

EXTRA_DIST = \
	variables.sh.in \
	test_cli.sh \
	test_descriptors.sh \
	test_connections.sh \
	test_formats.sh \
	test_seq.sh \
	test_thumbnail.sh \
	test_stall.sh \
	test_threading.sh 

clean-local: 
	-rm -rf tmp-*

