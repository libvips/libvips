noinst_LTLIBRARIES = libhistogram.la

libhistogram_la_SOURCES = \
	histogram.c \
	phistogram.h \
	maplut.c \
	hist_unary.c \
	hist_unary.h \
	hist_cum.c \
	hist_norm.c \
	hist_equal.c \
	hist_plot.c \
	hist_match.c \
	hist_local.c \
	percent.c \
	hist_ismonotonic.c \
	hist_entropy.c \
	stdif.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
