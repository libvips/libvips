noinst_LTLIBRARIES = libfreqfilt.la

libfreqfilt_la_SOURCES = \
	freqfilt.c \
	pfreqfilt.h \
	fwfft.c \
	invfft.c \
	freqmult.c \
	spectrum.c \
	phasecor.c \
	freq_dispatch.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
