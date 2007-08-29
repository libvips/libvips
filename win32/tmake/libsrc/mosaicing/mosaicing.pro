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
	im_affine.c \
	match.c \
	mosaic1.c  \
	mosaicing_dispatch.c \
	similarity.c \
	global_balance.c \
	im_avgdxdy.c \
	im_chkpair.c \
	im_clinear.c \
	im_improve.c \
	im_initialize.c \
	im_lrcalcon.c \
	im_lrmerge.c \
	im_lrmosaic.c \
	im_tbcalcon.c \
	im_tbmerge.c \
	im_remosaic.c \
	im_tbmosaic.c 
TARGET		= mosaicing

