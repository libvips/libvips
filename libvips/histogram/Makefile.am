noinst_LTLIBRARIES = libhistogram.la

libhistogram_la_SOURCES = \
	histogram.c \
	phistogram.h \
	maplut.c \
	hist_buffer.c \
	hist_buffer.h \
	hist_cum.c \
	hist_norm.c \
	hist_equal.c \
	hist_plot.c \
	\
	hist_dispatch.c \
	im_histspec.c \
	im_hsp.c \
	im_mpercent.c \
	im_invertlut.c \
	im_lhisteq.c \
	im_project.c \
	im_stdif.c \
	tone.c

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
