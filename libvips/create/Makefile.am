noinst_LTLIBRARIES = libcreate.la

libcreate_la_SOURCES = \
	create.c \
	pcreate.h \
	gaussmat.c \
	logmat.c \
	buildlut.c \
	invertlut.c \
	tonelut.c \
	identity.c \
	point.c \
	point.h \
	ffilter.c \
	ffilter.h \
	ffilter_ideal.c \
	ffilter_ideal_ring.c \
	ffilter_ideal_band.c \
	ffilter_butterworth.c \
	ffilter_butterworth_ring.c \
	ffilter_butterworth_band.c \
	ffilter_gaussian.c \
	ffilter_gaussian_ring.c \
	eye.c \
	grey.c \
	xyz.c \
	black.c \
	text.c \
	gaussnoise.c \
	im_benchmark.c \
	sines.c \
	zone.c \
	other_dispatch.c

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
