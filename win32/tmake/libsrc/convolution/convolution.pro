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
	rotmask.c \
	rw_mask.c \
	convol_dispatch.c \
	im_addgnoise.c \
	im_compass.c \
	im_conv.c \
	im_convf.c \
	im_convsep.c \
	im_convsepf.c \
	im_convsub.c \
	im_embed.c \
	im_fastcor.c \
	im_gaussmasks.c \
	im_gaussnoise.c \
	im_gradient.c \
	im_lindetect.c \
	im_logmasks.c \
	im_maxvalue.c \
	im_mpercent.c \
	im_rank.c \
	im_resize_linear.c \
	im_sharpen.c \
	im_shrink.c \
	im_spcor.c \
	im_stretch3.c \
	im_zerox.c
TARGET		= convolution

