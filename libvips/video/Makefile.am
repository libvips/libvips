noinst_LTLIBRARIES = libvideo.la

libvideo_la_SOURCES = \
	video_dispatch.c \
	im_video_v4l1.c \
	im_video_test.c 

AM_CPPFLAGS = -I${top_srcdir}/libvips/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
