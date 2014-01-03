noinst_LTLIBRARIES = libfreq_filt.la

libfreq_filt_la_SOURCES = \
	im_phasecor_fft.c \
	freq_dispatch.c \
	im_disp_ps.c \
	im_fractsurf.c \
	im_freq_mask.c \
	im_freqflt.c \
	im_fwfft.c \
	im_invfft.c \
	im_invfftr.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
