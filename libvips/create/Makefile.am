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
	mask.c \
	mask.h \
	mask_ideal.c \
	mask_ideal_ring.c \
	mask_ideal_band.c \
	mask_butterworth.c \
	mask_butterworth_ring.c \
	mask_butterworth_band.c \
	mask_gaussian.c \
	mask_gaussian_ring.c \
	mask_gaussian_band.c \
	mask_fractal.c \
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
