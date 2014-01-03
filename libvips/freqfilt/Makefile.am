noinst_LTLIBRARIES = libfreqfilt.la

libfreqfilt_la_SOURCES = \
	freqfilt.c \
	pfreqfilt.h \
	fwfft.c \
	invfft.c \
	im_phasecor_fft.c \
	freq_dispatch.c \
	im_disp_ps.c \
	im_fractsurf.c \
	im_freq_mask.c \
	im_freqflt.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
