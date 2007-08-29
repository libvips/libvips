TEMPLATE    	= lib
DIR_LIB		= ../../lib
CONFIG 		= release staticlib 
win32:CONFIG 	= windows
TMAKEFLAGS	= -nologo
DEFINES		= HAVE_CONFIG_H
INCLUDEPATH	= ../.. ../../include
HEADERS		= ../../config.h
win32:LIBS	= \
	$$DIR_LIB/libjpeg.lib \
	$$DIR_LIB/libtiff.lib \
	$$DIR_LIB/libpng.lib \
	$$DIR_LIB/libz.lib
DESTDIR		= ../../Release
VERSION		= 7.8.10

SOURCES		= \
	im_bernd.c \
	im_vips2tiff.c \
	im_tiff2vips.c \
	conver_dispatch.c \
	im_bandjoin.c \
	im_black.c \
	im_c2amph.c \
	im_c2rect.c \
	im_c2imag.c \
	im_c2ps.c \
	im_c2real.c \
	im_clip.c \
	im_copy.c \
	im_extract.c \
	im_falsecolour.c \
	im_fliphor.c \
	im_flipver.c \
	im_gbandjoin.c \
	im_insert.c \
	im_lrjoin.c \
	im_magick2vips.c \
	im_mask2vips.c \
	im_ppm2vips.c \
	im_recomb.c \
	im_ri2c.c \
	im_rot180.c \
	im_rot270.c \
	im_rot90.c \
	im_scale.c \
	im_scaleps.c \
	im_slice.c \
	im_subsample.c \
	im_system.c \
	im_print.c \
	im_tbjoin.c \
	im_thresh.c \
	im_vips2mask.c \
	im_vips2ppm.c \
	vips_jpeg.c \
	vips_png.c \
	im_zoom.c
TARGET		= conversion

