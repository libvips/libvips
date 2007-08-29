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
	cooc_funcs.c \
	glds_funcs.c \
	im_dif_std.c \
	im_eye.c \
	im_grey.c \
	im_meanstd.c \
	im_simcontr.c \
	im_sines.c \
	im_spatres.c \
	im_zone.c \
	other_dispatch.c
TARGET			= other

