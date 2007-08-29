SUBDIRS = man3

noinst_LTLIBRARIES = libvideo.la

libvideo_la_SOURCES = \
	video_dispatch.c \
	im_video_v4l1.c \
	im_video_test.c 

INCLUDES = -I${top_srcdir}/include @VIPS_CFLAGS@ @VIPS_INCLUDES@ 
