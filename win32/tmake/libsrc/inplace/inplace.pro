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
	im_circle.c \
	im_flood.c \
	im_insertplace.c \
	im_line.c \
	im_paintrect.c \
	im_plotmask.c \
	inplace_dispatch.c \
	line_draw.c \
	plot_point.c \
	smudge_area.c
TARGET		= inplace
